package analyzer

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDecodeRawPDBProtocol(t *testing.T) {
	var data bytes.Buffer
	data.WriteString(rawPDBProtocolMagic)
	guid := [16]byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8}
	data.Write(guid[:])
	_ = binary.Write(&data, binary.LittleEndian, uint32(3))
	_ = binary.Write(&data, binary.LittleEndian, uint32(1))
	_ = binary.Write(&data, binary.LittleEndian, uint32(0x1234))
	_ = binary.Write(&data, binary.LittleEndian, uint32(77))
	data.WriteByte(1)
	writeTestRawPDBString(t, &data, "Solution::run")
	writeTestRawPDBString(t, &data, `C:\build\main.obj`)
	writeTestRawPDBString(t, &data, "?run@Solution@@QEAAHXZ")

	result, err := decodeRawPDB(&data)
	if err != nil {
		t.Fatal(err)
	}
	if result.guid != guid || result.age != 3 || len(result.functions) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	function := result.functions[0]
	if function.rva != 0x1234 || function.size != 77 || function.visibility != "global" ||
		function.name != "Solution::run" || function.module != `C:\build\main.obj` ||
		function.decoratedName != "?run@Solution@@QEAAHXZ" {
		t.Fatalf("unexpected function: %+v", function)
	}
}

func TestFunctionsFromRawPDBRejectsNonExecutableRVAs(t *testing.T) {
	image := peInfo{imageBase: 0x140000000, sections: []peSection{
		{name: ".text", virtualAddress: 0x1000, virtualSize: 0x100, characteristics: imageScnMemExecute},
		{name: ".data", virtualAddress: 0x2000, virtualSize: 0x100},
	}}
	raw := rawPDBResult{functions: []rawPDBFunction{
		{rva: 0x1010, size: 12, visibility: "local", name: "kept", module: `C:\obj\main.obj`},
		{rva: 0x2010, size: 12, visibility: "global", name: "discarded"},
	}}
	functions := functionsFromRawPDB(raw, image)
	if len(functions) != 1 || functions[0].Name != "kept" || functions[0].Module != "main.obj" {
		t.Fatalf("unexpected functions: %+v", functions)
	}
}

func TestRawPDBHelperIntegration(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	helper := filepath.Join(root, "rawpdb-helper", "build", "bin", "Release", "rawpdb_analyzer.exe")
	sampleBinary := filepath.Join(root, "rawpdb-helper", "build", "bin", "RelWithDebInfo", "rawpdb_analyzer.exe")
	samplePDB := filepath.Join(root, "rawpdb-helper", "build", "bin", "RelWithDebInfo", "rawpdb_analyzer.pdb")
	for _, required := range []string{helper, sampleBinary, samplePDB} {
		if _, err := os.Stat(required); err != nil {
			t.Skip("RawPDB helper build artifacts are not available")
		}
	}
	binaryData, err := os.ReadFile(sampleBinary)
	if err != nil {
		t.Fatal(err)
	}
	pdbData, err := os.ReadFile(samplePDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := AnalyzeWithOptions(binaryData, pdbData, Options{
		Context: ctx, RawPDBExecutable: helper, PDBPath: samplePDB,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Functions) == 0 || result.Binary.GUID == "" {
		t.Fatalf("unexpected RawPDB result: %+v", result.Binary)
	}
	legacy, err := AnalyzeWithOptions(binaryData, pdbData, Options{})
	if err != nil {
		t.Fatal(err)
	}
	legacyAddresses := make(map[string]struct{}, len(legacy.Functions))
	for _, function := range legacy.Functions {
		legacyAddresses[function.Address] = struct{}{}
	}
	if len(result.Functions) != len(legacy.Functions) {
		t.Fatalf("RawPDB returned %d functions; Go parser returned %d", len(result.Functions), len(legacy.Functions))
	}
	for _, function := range result.Functions {
		if _, found := legacyAddresses[function.Address]; !found {
			t.Fatalf("RawPDB returned unexpected function address %s", function.Address)
		}
	}
}

func writeTestRawPDBString(t *testing.T, output *bytes.Buffer, value string) {
	t.Helper()
	if err := binary.Write(output, binary.LittleEndian, uint32(len(value))); err != nil {
		t.Fatal(err)
	}
	output.WriteString(value)
}
