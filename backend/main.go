package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"recompiler/backend/internal/analyzer"
	"recompiler/backend/internal/disassembler"
	"recompiler/backend/internal/transformer"
	"recompiler/backend/internal/uploadcache"
)

const (
	defaultMaxFileSize int64 = 1 << 30
	multipartMemory          = 32 << 20
	maxBatchFunctions        = 32
	cacheMaxEntries          = 16
	cacheTTL                 = 2 * time.Hour
)

var (
	maxFileSize     int64
	maxRequestSize  int64
	analyzedUploads *uploadcache.Cache
	analysisWorkers int
	analysisJobs    int
	analysisSlots   chan struct{}
	rawPDBHelper    string
)

func main() {
	envFile, err := loadDotEnv()
	if err != nil {
		log.Fatalf("load backend environment: %v", err)
	}
	logFile, err := configureLogging()
	logToFile := err == nil
	if err != nil {
		log.Printf("file logging unavailable; continuing with console logging: %v", err)
	} else {
		defer logFile.Close()
	}
	initializeRuntimeConfiguration()
	stopDatadog := startDatadogObservability()
	defer stopDatadog()
	logEvent("info", "backend.configuration.loaded", "Backend configuration loaded.", map[string]any{
		"environment.file_loaded": envFile != "",
		"logging.file_enabled":    logToFile,
	})

	analyzedUploads, err = uploadcache.New(uploadcache.Config{
		MaxBytes: configuredCacheLimit(), MaxEntries: cacheMaxEntries, TTL: cacheTTL,
	})
	if err != nil {
		log.Fatalf("initialize upload cache: %v", err)
	}
	logEvent("info", "analysis.concurrency.configured", "Analysis concurrency configured.", map[string]any{
		"analysis.workers": analysisWorkers,
		"analysis.jobs":    analysisJobs,
	})
	if rawPDBHelper != "" {
		logEvent("info", "pdb_analyzer.configured", "PDB analyzer configured.", map[string]any{
			"analyzer.type":       "rawpdb",
			"analyzer.executable": filepath.Base(rawPDBHelper),
		})
	} else {
		logEvent("info", "pdb_analyzer.configured", "PDB analyzer configured.", map[string]any{
			"analyzer.type": "go",
		})
	}
	recompiler := transformerConfig().Executable
	if recompiler == "" {
		logEvent("warn", "transformer.configured", "Transformer is not configured.", map[string]any{
			"transformer.available": false,
		})
	} else if _, err := os.Stat(recompiler); err != nil {
		logEvent("warn", "transformer.configured", "Configured transformer is unavailable.", map[string]any{
			"transformer.available":  false,
			"transformer.executable": filepath.Base(recompiler),
		})
	} else {
		logEvent("info", "transformer.configured", "Transformer configured.", map[string]any{
			"transformer.available":  true,
			"transformer.executable": filepath.Base(recompiler),
		})
	}
	defer func() {
		if err := analyzedUploads.Close(); err != nil {
			log.Printf("remove upload cache: %v", err)
		}
	}()

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /api/analyze", analyzeHandler)
	mux.HandleFunc("POST /api/disassemble", disassembleHandler)
	mux.HandleFunc("POST /api/transform", transformHandler)

	handler := requestLogger(securityHeaders(mux))
	handler = wrapDatadogHandler(handler)
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Minute,
		WriteTimeout:      60 * time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	logEvent("info", "backend.started", "Backend started.", map[string]any{
		"server.address": addr,
	})
	shutdownSignal, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	go func() {
		<-shutdownSignal.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown backend: %v", err)
		}
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("serve backend: %v", err)
	}
}

func initializeRuntimeConfiguration() {
	maxFileSize = configuredUploadLimit()
	maxRequestSize = 2*maxFileSize + (16 << 20)
	analysisWorkers = configuredAnalysisWorkers()
	analysisJobs = configuredAnalysisJobs()
	analysisSlots = make(chan struct{}, analysisJobs)
	rawPDBHelper = configuredRawPDBExecutable()
}

var dotEnvPathVariables = map[string]bool{
	"RECOMPILER_PATH":              true,
	"RECOMPILER_OPT":               true,
	"RECOMPILER_LLC":               true,
	"RECOMPILER_LLVM_LINK":         true,
	"RECOMPILER_RUNTIME":           true,
	"RECOMPILER_SEMANTICS":         true,
	"RECOMPILER_SEMANTICS_INSTALL": true,
	"RECOMPILER_OBJDUMP":           true,
	"RECOMPILER_RAWPDB":            true,
	"RECOMPILER_LOG_FILE":          true,
}

var dotEnvDeniedVariables = map[string]bool{
	"DD_API_KEY": true,
	"DD_APP_KEY": true,
}

func loadDotEnv() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("RECOMPILER_ENV_FILE")); configured != "" {
		absolute, err := filepath.Abs(configured)
		if err != nil {
			return "", fmt.Errorf("resolve RECOMPILER_ENV_FILE: %w", err)
		}
		if err := loadDotEnvFile(absolute); err != nil {
			return "", err
		}
		return absolute, nil
	}

	candidates := []string{".env", filepath.Join("..", ".env")}
	if executable, err := os.Executable(); err == nil {
		directory := filepath.Dir(executable)
		candidates = append(candidates, filepath.Join(directory, ".env"), filepath.Join(directory, "..", ".env"))
	}
	seen := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		absolute, err := filepath.Abs(candidate)
		if err != nil || seen[absolute] {
			continue
		}
		seen[absolute] = true
		if _, err := os.Stat(absolute); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return "", fmt.Errorf("inspect environment file %s: %w", absolute, err)
		}
		if err := loadDotEnvFile(absolute); err != nil {
			return "", err
		}
		return absolute, nil
	}
	return "", nil
}

func loadDotEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open environment file %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !validEnvironmentKey(key) {
			return fmt.Errorf("parse environment file %s line %d: expected NAME=value", path, lineNumber)
		}
		if dotEnvDeniedVariables[key] {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
			value = value[1 : len(value)-1]
		}
		if dotEnvPathVariables[key] && value != "" && !filepath.IsAbs(value) {
			value = filepath.Clean(filepath.Join(filepath.Dir(path), value))
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set %s from environment file: %w", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read environment file %s: %w", path, err)
	}
	return nil
}

func validEnvironmentKey(key string) bool {
	if key == "" {
		return false
	}
	for index, character := range key {
		if character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func configureLogging() (*os.File, error) {
	logPath := strings.TrimSpace(os.Getenv("RECOMPILER_LOG_FILE"))
	if logPath == "" {
		programData := strings.TrimSpace(os.Getenv("ProgramData"))
		if programData == "" {
			if runtime.GOOS == "windows" {
				programData = `C:\ProgramData`
			} else {
				programData = os.TempDir()
			}
		}
		logPath = filepath.Join(programData, "recompiler", "logs", "backend.log")
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file %s: %w", logPath, err)
	}
	log.SetOutput(io.MultiWriter(os.Stderr, file))
	return file, nil
}

func disassembleHandler(w http.ResponseWriter, r *http.Request) {
	if err := parseMultipartUpload(w, r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()

	binaryData, analysis, status, err := loadAnalyzedRequest(r)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	address := strings.ToLower(strings.TrimSpace(r.FormValue("address")))
	if address == "" {
		writeError(w, http.StatusBadRequest, "select a function to disassemble")
		return
	}

	if analysis.Binary.Machine != "x86-64" && analysis.Binary.Machine != "x86" {
		writeError(w, http.StatusUnprocessableEntity, "control-flow analysis currently supports x86 and x86-64 binaries")
		return
	}
	var selected *analyzer.Function
	for index := range analysis.Functions {
		if strings.ToLower(analysis.Functions[index].Address) == address {
			selected = &analysis.Functions[index]
			break
		}
	}
	if selected == nil {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("address %s is not a function in the uploaded binary and PDB", address))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	span, observedCtx := startObservedSpan(ctx, "binary_analysis.disassemble", "disassemble function", map[string]any{
		"binary.bytes": len(binaryData),
	})
	result, err := disassembler.Analyze(observedCtx, disassemblerConfig(), binaryData, *selected, analysis.Functions)
	finishObservedSpan(span, err)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func transformHandler(w http.ResponseWriter, r *http.Request) {
	if err := parseMultipartUpload(w, r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()

	binaryData, analysis, status, err := loadAnalyzedRequest(r)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	addresses := make([]string, 0, len(r.MultipartForm.Value["address"]))
	seenAddress := make(map[string]bool, len(r.MultipartForm.Value["address"]))
	for _, raw := range r.MultipartForm.Value["address"] {
		address := strings.ToLower(strings.TrimSpace(raw))
		if address == "" || seenAddress[address] {
			continue
		}
		seenAddress[address] = true
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		writeError(w, http.StatusBadRequest, "select at least one function to transform")
		return
	}
	if len(addresses) > maxBatchFunctions {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("a batch can contain at most %d functions", maxBatchFunctions))
		return
	}

	if analysis.Binary.Machine != "x86-64" {
		writeError(w, http.StatusUnprocessableEntity, "the recompiler currently supports patching x86-64 binaries only")
		return
	}
	knownAddresses := make(map[string]bool, len(analysis.Functions))
	for _, function := range analysis.Functions {
		knownAddresses[strings.ToLower(function.Address)] = true
	}
	for _, address := range addresses {
		if !knownAddresses[address] {
			writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("address %s is not a function in the uploaded binary and PDB", address))
			return
		}
	}

	nopCount, err := optionalInt(r.FormValue("nopCount"), 3)
	if err != nil {
		writeError(w, http.StatusBadRequest, "nopCount must be an integer")
		return
	}
	obfReps, err := optionalInt(r.FormValue("obfReps"), 1)
	if err != nil {
		writeError(w, http.StatusBadRequest, "obfReps must be an integer")
		return
	}
	passes := make([]transformer.Pass, 0, len(r.MultipartForm.Value["pass"]))
	for _, pass := range r.MultipartForm.Value["pass"] {
		passes = append(passes, transformer.Pass(pass))
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()
	span, observedCtx := startObservedSpan(ctx, "binary_analysis.transform", "transform functions", map[string]any{
		"binary.bytes":     len(binaryData),
		"function.count":   len(addresses),
		"transform.passes": len(passes),
	})
	output, err := transformer.Transform(observedCtx, transformerConfig(), binaryData, addresses, transformer.Options{
		Passes: passes, NopCount: nopCount, ObfReps: obfReps,
	})
	finishObservedSpan(span, err)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", `attachment; filename="recompiled.bin"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(output)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(output); err != nil {
		log.Printf("write transformed binary: %v", err)
	}
}

func optionalInt(value string, fallback int) (int, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	return strconv.Atoi(value)
}

func transformerConfig() transformer.Config {
	executable := strings.TrimSpace(os.Getenv("RECOMPILER_PATH"))
	if info, err := os.Stat(executable); err == nil && info.IsDir() {
		executable = filepath.Join(executable, "remill_recompiler.exe")
	}
	if executable == "" {
		for _, candidate := range []string{
			filepath.Join("..", "recompiler", "remill_recompiler.exe"),
			filepath.Join("recompiler", "remill_recompiler.exe"),
		} {
			if absolute, err := filepath.Abs(candidate); err == nil {
				if _, statErr := os.Stat(absolute); statErr == nil {
					executable = absolute
					break
				}
			}
		}
	}
	toolDirectory := ""
	if executable != "" {
		toolDirectory = filepath.Join(filepath.Dir(executable), "llvm-tools")
	}
	return transformer.Config{
		Executable:      executable,
		Opt:             configuredFile("RECOMPILER_OPT", filepath.Join(toolDirectory, "opt.exe")),
		LLC:             configuredFile("RECOMPILER_LLC", filepath.Join(toolDirectory, "llc.exe")),
		LLVMLink:        configuredFile("RECOMPILER_LLVM_LINK", filepath.Join(toolDirectory, "llvm-link.exe")),
		Runtime:         configuredFile("RECOMPILER_RUNTIME", filepath.Join(toolDirectory, "transparent_memory.ll")),
		Semantics:       configuredFile("RECOMPILER_SEMANTICS", filepath.Join(toolDirectory, "amd64.bc")),
		SemanticsTarget: os.Getenv("RECOMPILER_SEMANTICS_INSTALL"),
	}
}

func disassemblerConfig() disassembler.Config {
	toolDirectory := ""
	if executable := transformerConfig().Executable; executable != "" {
		toolDirectory = filepath.Join(filepath.Dir(executable), "llvm-tools")
	}
	return disassembler.Config{
		ObjDump: configuredFile("RECOMPILER_OBJDUMP", filepath.Join(toolDirectory, "llvm-objdump.exe")),
	}
}

func configuredFile(environmentName, fallback string) string {
	if configured := os.Getenv(environmentName); configured != "" {
		return configured
	}
	if fallback != "" {
		if absolute, err := filepath.Abs(fallback); err == nil {
			if _, statErr := os.Stat(absolute); statErr == nil {
				return absolute
			}
		}
	}
	return ""
}

func configuredRawPDBExecutable() string {
	if configured := strings.TrimSpace(os.Getenv("RECOMPILER_RAWPDB")); configured != "" {
		return configured
	}
	for _, candidate := range []string{
		filepath.Join("..", "rawpdb-helper", "build", "bin", "Release", "rawpdb_analyzer.exe"),
		filepath.Join("rawpdb-helper", "build", "bin", "Release", "rawpdb_analyzer.exe"),
		filepath.Join("..", "rawpdb-helper", "build", "bin", "RelWithDebInfo", "rawpdb_analyzer.exe"),
		filepath.Join("rawpdb-helper", "build", "bin", "RelWithDebInfo", "rawpdb_analyzer.exe"),
	} {
		if absolute, err := filepath.Abs(candidate); err == nil {
			if _, statErr := os.Stat(absolute); statErr == nil {
				return absolute
			}
		}
	}
	return ""
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if err := parseMultipartUpload(w, r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()

	upload, err := readUploadPair(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	uploadDuration := time.Since(started)

	parseStarted := time.Now()
	result, err := analyzeData(r.Context(), upload.binary, upload.pdb, upload.pdbPath)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	parseDuration := time.Since(parseStarted)
	cacheStarted := time.Now()
	cacheSpan, _ := startObservedSpan(r.Context(), "binary_analysis.cache", "cache analyzed upload", map[string]any{
		"binary.bytes": len(upload.binary),
		"pdb.bytes":    len(upload.pdb),
	})
	cacheID, err := analyzedUploads.Put(upload.binary, upload.pdb, result)
	finishObservedSpan(cacheSpan, err)
	if err != nil {
		writeError(w, http.StatusInsufficientStorage, fmt.Sprintf("cache analyzed upload: %v", err))
		return
	}
	cacheDuration := time.Since(cacheStarted)
	result.CacheID = cacheID
	w.Header().Set("Server-Timing", fmt.Sprintf(
		"upload;dur=%.1f, pdb;dur=%.1f, cache;dur=%.1f",
		float64(uploadDuration.Microseconds())/1000,
		float64(parseDuration.Microseconds())/1000,
		float64(cacheDuration.Microseconds())/1000,
	))
	logEventContext(r.Context(), "info", "analysis.completed", "Binary analysis completed.", map[string]any{
		"binary.bytes":       len(upload.binary),
		"pdb.bytes":          len(upload.pdb),
		"function.count":     len(result.Functions),
		"upload.duration_ms": milliseconds(uploadDuration),
		"pdb.duration_ms":    milliseconds(parseDuration),
		"cache.duration_ms":  milliseconds(cacheDuration),
	})
	writeJSON(w, http.StatusOK, result)
}

func loadAnalyzedRequest(r *http.Request) ([]byte, analyzer.Result, int, error) {
	if cacheID := strings.TrimSpace(r.FormValue("cacheId")); cacheID != "" {
		if analyzedUploads == nil {
			return nil, analyzer.Result{}, http.StatusServiceUnavailable, errors.New("upload cache is unavailable")
		}
		entry, err := analyzedUploads.GetBinary(cacheID)
		if errors.Is(err, uploadcache.ErrNotFound) {
			return nil, analyzer.Result{}, http.StatusGone, errors.New("cached upload expired; analyze the binary and PDB again")
		}
		if err != nil {
			return nil, analyzer.Result{}, http.StatusInternalServerError, fmt.Errorf("load cached upload: %w", err)
		}
		return entry.Binary, entry.Analysis, http.StatusOK, nil
	}

	upload, err := readUploadPair(r)
	if err != nil {
		return nil, analyzer.Result{}, http.StatusBadRequest, err
	}
	analysis, err := analyzeData(r.Context(), upload.binary, upload.pdb, upload.pdbPath)
	if err != nil {
		return nil, analyzer.Result{}, http.StatusUnprocessableEntity, err
	}
	return upload.binary, analysis, http.StatusOK, nil
}

func parseMultipartUpload(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if err := r.ParseMultipartForm(multipartMemory); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return fmt.Errorf(
				"combined upload exceeds %d MiB (binary and PDB may each be up to %d MiB)",
				maxRequestSize>>20, maxFileSize>>20,
			)
		}
		return fmt.Errorf("invalid multipart upload: %w", err)
	}
	return nil
}

func configuredUploadLimit() int64 {
	value := strings.TrimSpace(os.Getenv("RECOMPILER_MAX_UPLOAD_MIB"))
	if value == "" {
		return defaultMaxFileSize
	}
	mebibytes, err := strconv.ParseInt(value, 10, 64)
	if err != nil || mebibytes < 1 || mebibytes > 4096 {
		log.Printf("ignoring invalid RECOMPILER_MAX_UPLOAD_MIB=%q; using %d MiB", value, defaultMaxFileSize>>20)
		return defaultMaxFileSize
	}
	return mebibytes << 20
}

func configuredCacheLimit() int64 {
	fallback := int64(4 << 30)
	if pairLimit := 2 * maxFileSize; pairLimit > fallback {
		fallback = pairLimit
	}
	value := strings.TrimSpace(os.Getenv("RECOMPILER_CACHE_MIB"))
	if value == "" {
		return fallback
	}
	mebibytes, err := strconv.ParseInt(value, 10, 64)
	if err != nil || mebibytes < 64 || mebibytes > 65536 {
		log.Printf("ignoring invalid RECOMPILER_CACHE_MIB=%q; using %d MiB", value, fallback>>20)
		return fallback
	}
	return mebibytes << 20
}

func configuredAnalysisWorkers() int {
	fallback := runtime.GOMAXPROCS(0)
	if fallback > 16 {
		fallback = 16
	}
	return configuredAnalysisInteger("RECOMPILER_ANALYSIS_WORKERS", fallback, 1, 64)
}

func configuredAnalysisJobs() int {
	fallback := runtime.GOMAXPROCS(0) / analysisWorkers
	if fallback < 1 {
		fallback = 1
	}
	if fallback > 4 {
		fallback = 4
	}
	return configuredAnalysisInteger("RECOMPILER_ANALYSIS_JOBS", fallback, 1, 16)
}

func configuredAnalysisInteger(name string, fallback, minimum, maximum int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		log.Printf("ignoring invalid %s=%q; using %d", name, value, fallback)
		return fallback
	}
	return parsed
}

func analyzeData(ctx context.Context, binaryData, pdbData []byte, pdbPath string) (analyzer.Result, error) {
	queuedAt := time.Now()
	queueSpan, queueCtx := startObservedSpan(ctx, "binary_analysis.queue", "wait for analysis slot", nil)
	select {
	case analysisSlots <- struct{}{}:
		defer func() { <-analysisSlots }()
		finishObservedSpan(queueSpan, nil)
	case <-queueCtx.Done():
		finishObservedSpan(queueSpan, queueCtx.Err())
		return analyzer.Result{}, queueCtx.Err()
	}
	queueDuration := time.Since(queuedAt)
	started := time.Now()
	analysisSpan, analysisCtx := startObservedSpan(ctx, "binary_analysis.engine", "analyze PE and PDB", map[string]any{
		"binary.bytes": len(binaryData),
		"pdb.bytes":    len(pdbData),
	})
	result, err := analyzer.AnalyzeWithOptions(binaryData, pdbData, analyzer.Options{
		Workers: analysisWorkers, Context: analysisCtx,
		RawPDBExecutable: rawPDBHelper, PDBPath: pdbPath,
	})
	finishObservedSpan(analysisSpan, err)
	fields := map[string]any{
		"queue.duration_ms":    milliseconds(queueDuration),
		"analysis.duration_ms": milliseconds(time.Since(started)),
		"binary.bytes":         len(binaryData),
		"pdb.bytes":            len(pdbData),
		"analysis.success":     err == nil,
	}
	if err == nil {
		fields["function.count"] = len(result.Functions)
		logEventContext(analysisCtx, "info", "analysis.engine.completed", "Analysis engine completed.", fields)
	} else {
		fields["error.message"] = safeLogMessage(err.Error())
		logEventContext(analysisCtx, "error", "analysis.engine.failed", "Analysis engine failed.", fields)
	}
	return result, err
}

type uploadedPair struct {
	binary  []byte
	pdb     []byte
	pdbPath string
}

func readUploadPair(r *http.Request) (uploadedPair, error) {
	type uploadResult struct {
		field string
		data  []byte
		err   error
	}
	binaryFile, binaryHeader, err := openUpload(r, "binary")
	if err != nil {
		return uploadedPair{}, err
	}
	pdbFile, pdbHeader, err := r.FormFile("pdb")
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) {
			defer binaryFile.Close()
			binaryData, readErr := readOpenedUpload(binaryFile, binaryHeader, "binary")
			return uploadedPair{binary: binaryData}, readErr
		}
		binaryFile.Close()
		return uploadedPair{}, fmt.Errorf("read %q file: %w", "pdb", err)
	}
	pdbPath := ""
	if diskFile, ok := pdbFile.(*os.File); ok {
		pdbPath = diskFile.Name()
	}
	results := make(chan uploadResult, 2)
	go func() {
		defer binaryFile.Close()
		data, err := readOpenedUpload(binaryFile, binaryHeader, "binary")
		results <- uploadResult{field: "binary", data: data, err: err}
	}()
	go func() {
		defer pdbFile.Close()
		data, err := readOpenedUpload(pdbFile, pdbHeader, "pdb")
		results <- uploadResult{field: "pdb", data: data, err: err}
	}()
	var binaryData, pdbData []byte
	var binaryErr, pdbErr error
	for range 2 {
		result := <-results
		if result.field == "binary" {
			binaryData, binaryErr = result.data, result.err
		} else {
			pdbData, pdbErr = result.data, result.err
		}
	}
	if binaryErr != nil {
		return uploadedPair{}, binaryErr
	}
	if pdbErr != nil {
		return uploadedPair{}, pdbErr
	}
	return uploadedPair{binary: binaryData, pdb: pdbData, pdbPath: pdbPath}, nil
}

func openUpload(r *http.Request, field string) (multipart.File, *multipart.FileHeader, error) {
	file, header, err := r.FormFile(field)
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) {
			return nil, nil, fmt.Errorf("missing %q file", field)
		}
		return nil, nil, fmt.Errorf("read %q file: %w", field, err)
	}
	return file, header, nil
}

func readOpenedUpload(file multipart.File, header *multipart.FileHeader, field string) ([]byte, error) {
	if header.Size <= 0 {
		return nil, fmt.Errorf("%q file is empty", field)
	}
	if header.Size > maxFileSize {
		return nil, fmt.Errorf("%q file is larger than the %d MiB limit", field, maxFileSize>>20)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %q file: %w", field, err)
	}
	if int64(len(data)) > maxFileSize {
		return nil, fmt.Errorf("%q file is larger than the %d MiB limit", field, maxFileSize>>20)
	}
	return data, nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(&appResponseWriter{
			ResponseWriter: w,
			acceptsGzip:    strings.Contains(r.Header.Get("Accept-Encoding"), "gzip"),
			context:        r.Context(),
		}, r)
	})
}

type responseMetricsWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (writer *responseMetricsWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *responseMetricsWriter) Write(data []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	written, err := writer.ResponseWriter.Write(data)
	writer.bytes += written
	return written, err
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		writer := &responseMetricsWriter{ResponseWriter: w}
		next.ServeHTTP(writer, r)
		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}
		level := "info"
		if status >= 500 {
			level = "error"
		} else if status >= 400 {
			level = "warn"
		}
		requestBytes := r.ContentLength
		if requestBytes < 0 {
			requestBytes = 0
		}
		logEventContext(r.Context(), level, "http.request.completed", "HTTP request completed.", map[string]any{
			"http.method":         r.Method,
			"http.route":          logRoute(r.URL.Path),
			"http.status_code":    status,
			"request.bytes":       requestBytes,
			"response.bytes":      writer.bytes,
			"request.duration_ms": milliseconds(time.Since(started)),
		})
	})
}

func logRoute(path string) string {
	switch path {
	case "/api/health", "/api/analyze", "/api/disassemble", "/api/transform":
		return path
	default:
		return "unmatched"
	}
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration.Microseconds()) / 1000
}

var logAddressPattern = regexp.MustCompile(`(?i)\b0x[0-9a-f]+\b`)

func safeLogMessage(message string) string {
	message = strings.TrimSpace(message)
	if temporaryDirectory := strings.TrimSpace(os.TempDir()); temporaryDirectory != "" {
		message = strings.ReplaceAll(message, temporaryDirectory, "<temp>")
	}
	message = logAddressPattern.ReplaceAllString(message, "<address>")
	characters := []rune(message)
	if len(characters) > 2048 {
		message = string(characters[:2048]) + "..."
	}
	return message
}

var logEventMu sync.Mutex

func logEvent(level, event, message string, fields map[string]any) {
	logEventContext(context.Background(), level, event, message, fields)
}

func logEventContext(ctx context.Context, level, event, message string, fields map[string]any) {
	record := make(map[string]any, len(fields)+4)
	record["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	record["status"] = level
	record["event"] = event
	record["message"] = message
	for key, value := range fields {
		record[key] = value
	}
	addDatadogCorrelation(ctx, record)
	data, err := json.Marshal(record)
	if err != nil {
		log.Printf("encode structured log event %s: %v", event, err)
		return
	}
	data = append(data, '\n')
	logEventMu.Lock()
	_, err = log.Writer().Write(data)
	logEventMu.Unlock()
	if err != nil {
		log.Printf("write structured log event %s: %v", event, err)
	}
}

type appResponseWriter struct {
	http.ResponseWriter
	acceptsGzip bool
	context     context.Context
}

func writeError(w http.ResponseWriter, status int, message string) {
	message = strings.TrimSpace(message)
	level := "warn"
	if status >= 500 {
		level = "error"
	}
	ctx := context.Background()
	if wrapped, ok := w.(*appResponseWriter); ok {
		ctx = wrapped.context
	}
	logEventContext(ctx, level, "http.request.error", "HTTP request failed.", map[string]any{
		"http.status_code": status,
		"error.message":    safeLogMessage(message),
	})
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	if wrapped, ok := w.(*appResponseWriter); ok && wrapped.acceptsGzip {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		w.WriteHeader(status)
		compressed, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		if err != nil {
			log.Printf("initialize compressed response: %v", err)
			return
		}
		if err := json.NewEncoder(compressed).Encode(value); err != nil {
			log.Printf("write compressed response: %v", err)
		}
		if err := compressed.Close(); err != nil {
			log.Printf("finish compressed response: %v", err)
		}
		return
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write response: %v", err)
	}
}
