package transformer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const maxDiagnosticBytes = 1 << 20

var semanticsMu sync.Mutex

type Pass string

const (
	PassMutate           Pass = "mutate"
	PassOpaquePredicates Pass = "opaque-predicates"
	PassDeadCode         Pass = "dead-code"
	PassNOPSled          Pass = "nop-sled"
	PassDeobfuscate      Pass = "deobfuscate"
)

type Config struct {
	Executable      string
	Opt             string
	LLC             string
	LLVMLink        string
	Runtime         string
	Semantics       string
	SemanticsTarget string
}

type Options struct {
	Passes   []Pass
	NopCount int
	ObfReps  int
}

// Transform runs remill_recompiler once per address, in an isolated temporary
// directory, chaining each patched output into the next address's input so a
// batch of functions all land in one returned PE. The original upload is
// never passed as --patch-exe, so the tool cannot overwrite it.
func Transform(ctx context.Context, config Config, input []byte, addresses []string, options Options) ([]byte, error) {
	if len(input) < 2 || string(input[:2]) != "MZ" {
		return nil, errors.New("input is not a PE image")
	}
	if len(addresses) == 0 {
		return nil, errors.New("select at least one function to transform")
	}
	if strings.TrimSpace(config.Executable) == "" {
		return nil, errors.New("recompiler executable is not configured")
	}
	if _, err := os.Stat(config.Executable); err != nil {
		return nil, fmt.Errorf("recompiler executable is unavailable: %w", err)
	}
	if err := ensureSemantics(config); err != nil {
		return nil, err
	}

	jobDir, err := os.MkdirTemp("", "recompiler-job-*")
	if err != nil {
		return nil, fmt.Errorf("create transformation workspace: %w", err)
	}
	defer os.RemoveAll(jobDir)

	current := input
	for i, address := range addresses {
		inputPath := filepath.Join(jobDir, fmt.Sprintf("input-%d.exe", i))
		outputPath := filepath.Join(jobDir, fmt.Sprintf("output-%d.exe", i))
		objectPath := filepath.Join(jobDir, fmt.Sprintf("function-%d.obj", i))
		if err := os.WriteFile(inputPath, current, 0o600); err != nil {
			return nil, fmt.Errorf("write transformation input: %w", err)
		}
		if err := os.WriteFile(outputPath, current, 0o600); err != nil {
			return nil, fmt.Errorf("create output image: %w", err)
		}

		args, err := buildArgs(config, address, options, inputPath, outputPath, objectPath)
		if err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, config.Executable, args...)
		cmd.Dir = jobDir
		var diagnostic limitedBuffer
		cmd.Stdout = &diagnostic
		cmd.Stderr = &diagnostic
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("recompiler timed out or was cancelled: %w", ctx.Err())
			}
			message := strings.TrimSpace(diagnostic.String())
			if message == "" {
				message = err.Error()
			}
			return nil, fmt.Errorf("recompiler failed on function %d/%d (%s): %s", i+1, len(addresses), address, message)
		}

		output, err := os.ReadFile(outputPath)
		if err != nil {
			return nil, fmt.Errorf("read transformed binary: %w", err)
		}
		current = output
	}

	parsed, err := pe.NewFile(bytes.NewReader(current))
	if err != nil {
		return nil, errors.New("recompiler produced an invalid PE image")
	}
	parsed.Close()
	return current, nil
}

func ensureSemantics(config Config) error {
	semanticsMu.Lock()
	defer semanticsMu.Unlock()
	if runtime.GOOS != "windows" && config.SemanticsTarget == "" {
		return nil
	}
	if config.Semantics == "" {
		return errors.New("Remill amd64 semantics are not configured; add llvm-tools/amd64.bc beside the recompiler")
	}
	target := config.SemanticsTarget
	if target == "" {
		target = `C:\remill\install\share\remill\18\semantics\amd64.bc`
	}
	semanticsFiles := []string{"amd64.bc", "amd64_avx.bc", "amd64_avx512.bc"}
	for _, name := range semanticsFiles {
		source := config.Semantics
		if name != "amd64.bc" {
			source = filepath.Join(filepath.Dir(config.Semantics), name)
			if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return fmt.Errorf("inspect Remill %s semantics: %w", name, err)
			}
		}
		destination := target
		if name != "amd64.bc" {
			destination = filepath.Join(filepath.Dir(target), name)
		}
		if err := ensureSemanticsFile(source, destination); err != nil {
			return err
		}
	}
	return nil
}

func ensureSemanticsFile(source, target string) error {
	sourceData, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read Remill semantics %s: %w", filepath.Base(source), err)
	}
	if len(sourceData) < 4 || !bytes.Equal(sourceData[:4], []byte{'B', 'C', 0xc0, 0xde}) {
		return fmt.Errorf("configured Remill semantics file %s is not LLVM bitcode", filepath.Base(source))
	}
	if targetData, readErr := os.ReadFile(target); readErr == nil {
		if sha256.Sum256(targetData) != sha256.Sum256(sourceData) {
			return fmt.Errorf("a different %s already exists at %s; remove it or set RECOMPILER_SEMANTICS_INSTALL", filepath.Base(target), target)
		}
		return nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("inspect Remill semantics target: %w", readErr)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create Remill semantics directory %s: %w", filepath.Dir(target), err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+"-*")
	if err != nil {
		return fmt.Errorf("stage Remill semantics: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err := temporary.Write(sourceData); err != nil {
		temporary.Close()
		return fmt.Errorf("stage Remill semantics: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("stage Remill semantics: %w", err)
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return fmt.Errorf("install Remill semantics at %s: %w", target, err)
	}
	return nil
}

func buildArgs(config Config, rawAddress string, options Options, inputPath, outputPath string, objectPath string) ([]string, error) {
	address, err := normalizeAddress(rawAddress)
	if err != nil {
		return nil, err
	}
	if len(options.Passes) == 0 {
		return nil, errors.New("select at least one transformation pass")
	}
	if options.NopCount == 0 {
		options.NopCount = 3
	}
	if options.ObfReps == 0 {
		options.ObfReps = 1
	}
	if options.NopCount < 1 || options.NopCount > 64 {
		return nil, errors.New("NOP count must be between 1 and 64")
	}
	if options.ObfReps < 1 || options.ObfReps > 3 {
		return nil, errors.New("mutation repetitions must be between 1 and 3")
	}

	args := []string{
		"--pe", inputPath,
		"--address", address,
		"--out", objectPath,
		"--patch-ready",
		"--patch-exe", outputPath,
	}
	if config.Opt != "" {
		args = append(args, "--opt", config.Opt)
	}
	if config.LLC != "" {
		args = append(args, "--llc", config.LLC)
	}
	if config.LLVMLink != "" {
		args = append(args, "--llvm-link", config.LLVMLink)
	}
	if config.Runtime != "" {
		args = append(args, "--runtime", config.Runtime)
	}

	seen := make(map[Pass]bool)
	containsDeobfuscation := false
	containsObfuscation := false
	for _, pass := range options.Passes {
		if pass == PassDeobfuscate {
			containsDeobfuscation = true
		} else {
			containsObfuscation = true
		}
	}
	if containsDeobfuscation && containsObfuscation {
		return nil, errors.New("obfuscation and deobfuscation passes must be run separately")
	}
	for _, pass := range options.Passes {
		if seen[pass] {
			continue
		}
		seen[pass] = true
		switch pass {
		case PassMutate:
			args = append(args, "--mutate", "--obf-reps", strconv.Itoa(options.ObfReps))
		case PassOpaquePredicates:
			args = append(args, "--opaque-predicates")
		case PassDeadCode:
			args = append(args, "--dead-code")
		case PassNOPSled:
			args = append(args, "--nop-sled", "--nop-count", strconv.Itoa(options.NopCount))
		case PassDeobfuscate:
			args = append(args, "--deobfuscate")
		default:
			return nil, fmt.Errorf("unsupported transformation pass %q", pass)
		}
	}
	return args, nil
}

func normalizeAddress(rawAddress string) (string, error) {
	address := strings.ToLower(strings.TrimSpace(rawAddress))
	if !strings.HasPrefix(address, "0x") {
		return "", errors.New("function address must be hexadecimal")
	}
	if _, err := strconv.ParseUint(strings.TrimPrefix(address, "0x"), 16, 64); err != nil {
		return "", errors.New("function address must be hexadecimal")
	}
	return address, nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := maxDiagnosticBytes - b.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.Buffer.Write(data)
	}
	return original, nil
}
