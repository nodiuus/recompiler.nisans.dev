package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDotEnvFileResolvesRecompilerPath(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, ".env")
	if err := os.WriteFile(path, []byte("# backend settings\nRECOMPILER_PATH=./tools/remill_recompiler.exe\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	previous, existed := os.LookupEnv("RECOMPILER_PATH")
	if err := os.Unsetenv("RECOMPILER_PATH"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv("RECOMPILER_PATH", previous)
		} else {
			_ = os.Unsetenv("RECOMPILER_PATH")
		}
	})

	if err := loadDotEnvFile(path); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(directory, "tools", "remill_recompiler.exe")
	if got := os.Getenv("RECOMPILER_PATH"); got != want {
		t.Fatalf("RECOMPILER_PATH = %q, want %q", got, want)
	}
}

func TestLoadDotEnvFileDoesNotOverrideEnvironment(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, ".env")
	if err := os.WriteFile(path, []byte("RECOMPILER_PATH=from-file.exe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECOMPILER_PATH", "from-process.exe")

	if err := loadDotEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("RECOMPILER_PATH"); got != "from-process.exe" {
		t.Fatalf("RECOMPILER_PATH = %q, want explicit process value", got)
	}
}

func TestLoadDotEnvFileDoesNotLoadDatadogServerKeys(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, ".env")
	if err := os.WriteFile(path, []byte("DD_API_KEY=not-a-real-key\nDD_APP_KEY=not-a-real-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")
	if err := os.Unsetenv("DD_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("DD_APP_KEY"); err != nil {
		t.Fatal(err)
	}

	if err := loadDotEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if _, exists := os.LookupEnv("DD_API_KEY"); exists {
		t.Fatal("DD_API_KEY from .env was loaded into the backend process")
	}
	if _, exists := os.LookupEnv("DD_APP_KEY"); exists {
		t.Fatal("DD_APP_KEY from .env was loaded into the backend process")
	}
}

func TestTransformerConfigAcceptsRecompilerDirectory(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "remill_recompiler.exe")
	if err := os.WriteFile(executable, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECOMPILER_PATH", directory)

	if got := transformerConfig().Executable; got != executable {
		t.Fatalf("executable = %q, want %q", got, executable)
	}
}

func TestRequestLoggerWritesStructuredEvent(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })

	handler := requestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("result"))
	}))
	request := httptest.NewRequest(http.MethodPost, "/api/analyze", strings.NewReader("upload"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("decode structured log: %v\n%s", err, output.String())
	}
	if event["event"] != "http.request.completed" || event["http.route"] != "/api/analyze" {
		t.Fatalf("unexpected event: %+v", event)
	}
	if event["http.status_code"] != float64(http.StatusCreated) || event["request.bytes"] != float64(6) || event["response.bytes"] != float64(6) {
		t.Fatalf("unexpected request metrics: %+v", event)
	}
}

func TestSafeLogMessageRedactsSensitiveValuesAndLimitsLength(t *testing.T) {
	message := filepath.Join(os.TempDir(), "function-0x140001000-"+strings.Repeat("x", 3000))
	got := safeLogMessage(message)
	if strings.Contains(got, os.TempDir()) {
		t.Fatalf("temporary directory was not redacted: %q", got)
	}
	if strings.Contains(got, "0x140001000") {
		t.Fatalf("function address was not redacted: %q", got)
	}
	if len([]rune(got)) > 2051 {
		t.Fatalf("message was not limited: %d characters", len([]rune(got)))
	}
}
