package transformer

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBuildArgsUsesOnlyAllowlistedPasses(t *testing.T) {
	args, err := buildArgs(Config{Opt: `C:\llvm\opt.exe`}, "0x140001000", Options{
		Passes:  []Pass{PassMutate, PassNOPSled},
		ObfReps: 2, NopCount: 5,
	}, "input.exe", "output.exe", "function.obj")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--pe", "input.exe", "--address", "0x140001000", "--out", "function.obj",
		"--patch-ready", "--patch-exe", "output.exe", "--opt", `C:\llvm\opt.exe`,
		"--mutate", "--obf-reps", "2", "--nop-sled", "--nop-count", "5",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\ngot:  %#v\nwant: %#v", args, want)
	}
}

func TestEnsureSemanticsStagesMatchingBitcode(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.bc")
	target := filepath.Join(directory, "install", "amd64.bc")
	data := []byte{'B', 'C', 0xc0, 0xde, 1, 2, 3}
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureSemantics(Config{Semantics: source, SemanticsTarget: target}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, data) {
		t.Fatalf("staged semantics mismatch: %x", got)
	}
}

func TestEnsureSemanticsStagesAVXFamily(t *testing.T) {
	directory := t.TempDir()
	sourceDirectory := filepath.Join(directory, "tools")
	if err := os.MkdirAll(sourceDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte{'B', 'C', 0xc0, 0xde, 9, 8, 7}
	for _, name := range []string{"amd64.bc", "amd64_avx.bc", "amd64_avx512.bc"} {
		if err := os.WriteFile(filepath.Join(sourceDirectory, name), append(data, name...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(directory, "install", "amd64.bc")
	if err := ensureSemantics(Config{Semantics: filepath.Join(sourceDirectory, "amd64.bc"), SemanticsTarget: target}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"amd64.bc", "amd64_avx.bc", "amd64_avx512.bc"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(target), name)); err != nil {
			t.Fatalf("%s was not staged: %v", name, err)
		}
	}
}

func TestBuildArgsRejectsUnknownPass(t *testing.T) {
	_, err := buildArgs(Config{}, "0x1000", Options{Passes: []Pass{"--jit"}}, "in", "out", "obj")
	if err == nil {
		t.Fatal("expected unsupported pass error")
	}
}

func TestBuildArgsSupportsDeobfuscationSeparately(t *testing.T) {
	args, err := buildArgs(Config{}, "0x140001000", Options{
		Passes: []Pass{PassDeobfuscate},
	}, "input.exe", "output.exe", "function.obj")
	if err != nil {
		t.Fatal(err)
	}
	if args[len(args)-1] != "--deobfuscate" {
		t.Fatalf("last argument = %q, want --deobfuscate", args[len(args)-1])
	}
}

func TestBuildArgsRejectsMixedObfuscationAndDeobfuscation(t *testing.T) {
	_, err := buildArgs(Config{}, "0x140001000", Options{
		Passes: []Pass{PassMutate, PassDeobfuscate},
	}, "input.exe", "output.exe", "function.obj")
	if err == nil {
		t.Fatal("expected mixed transformation error")
	}
}

func TestNormalizeAddress(t *testing.T) {
	got, err := normalizeAddress("  0X14000ABCD  ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0x14000abcd" {
		t.Fatalf("address = %q, want normalized hexadecimal address", got)
	}
	if _, err := normalizeAddress("140001000"); err == nil {
		t.Fatal("expected address without 0x prefix to be rejected")
	}
}
