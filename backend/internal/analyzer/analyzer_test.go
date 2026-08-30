package analyzer

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseProcedure(t *testing.T) {
	body := make([]byte, 36+len("main")+1)
	binary.LittleEndian.PutUint32(body[12:16], 123)
	binary.LittleEndian.PutUint32(body[28:32], 0x20)
	binary.LittleEndian.PutUint16(body[32:34], 1)
	copy(body[35:], "main\x00")
	image := peInfo{imageBase: 0x140000000, sections: []peSection{{
		name: ".text", virtualAddress: 0x1000, virtualSize: 0x1000,
		characteristics: imageScnMemExecute,
	}}}

	fn, ok := parseProcedure(sGProc32, body, "example.obj", image)
	if !ok {
		t.Fatal("procedure was not parsed")
	}
	if fn.Name != "main" || fn.Address != "0x140001020" || fn.RVA != "0x1020" || fn.Size != 123 {
		t.Fatalf("unexpected function: %+v", fn)
	}
}

func TestPDBStreamViewReadsNoncontiguousAndCrossBlockData(t *testing.T) {
	pdb := &pdbFile{
		data:      make([]byte, 24),
		blockSize: 8,
		streams: []pdbStream{{
			size: 12, blocks: []uint32{2, 0},
		}},
	}
	copy(pdb.data[16:24], []byte("abcdefgh"))
	copy(pdb.data[0:4], []byte("ijkl"))
	view, err := pdb.streamView(0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := view.slice(6, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("ghijk")) {
		t.Fatalf("got %q, want ghijk", got)
	}
}

func TestParseSymbolRecordsStopsAtMalformedRecord(t *testing.T) {
	data := []byte{3, 0, 0x0e, 0x11, 0xff, 20, 0, 0x0e, 0x11}
	count := 0
	parseSymbolRecords(data, func(_ uint16, _ []byte) { count++ })
	if count != 1 {
		t.Fatalf("got %d records, want 1", count)
	}
}

func TestDisplayBaseNameHandlesWindowsPaths(t *testing.T) {
	if got := displayBaseName(`C:\build\symbols\app.pdb`); got != "app.pdb" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatGUIDUsesWindowsGUIDByteOrder(t *testing.T) {
	raw := [16]byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8}
	want := "12345678-9abc-def0-0102-030405060708"
	if got := formatGUID(raw); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestValidateX64PE(t *testing.T) {
	if err := validateX64PE(peInfo{machine: pe.IMAGE_FILE_MACHINE_AMD64, isPE64: true}); err != nil {
		t.Fatalf("valid x86-64 PE was rejected: %v", err)
	}
	if err := validateX64PE(peInfo{machine: pe.IMAGE_FILE_MACHINE_I386}); err == nil ||
		!strings.Contains(err.Error(), "only x86-64 PE executables are supported") {
		t.Fatalf("x86 rejection = %v", err)
	}
	if err := validateX64PE(peInfo{machine: pe.IMAGE_FILE_MACHINE_AMD64}); err == nil ||
		!strings.Contains(err.Error(), "invalid x86-64 PE header") {
		t.Fatalf("invalid PE32+ rejection = %v", err)
	}
}

func TestAnalyzeRejectsInvalidBinaryAsX64PE(t *testing.T) {
	_, err := Analyze([]byte("not a PE"), nil)
	if err == nil || !strings.Contains(err.Error(), "not a valid x86-64 PE executable") {
		t.Fatalf("invalid binary error = %v", err)
	}
}

func TestPDBInfoUsesDBIAgeForStrippedPDB(t *testing.T) {
	info := make([]byte, 28)
	binary.LittleEndian.PutUint32(info[8:12], 3)
	dbi := make([]byte, 64)
	binary.LittleEndian.PutUint32(dbi[8:12], 1)

	pdb := pdbFile{blockSize: 512}
	pdb.data = make([]byte, 1024)
	copy(pdb.data[0:512], info)
	copy(pdb.data[512:1024], dbi)
	pdb.streams = []pdbStream{{}, {size: uint32(len(info)), blocks: []uint32{0}}, {}, {size: uint32(len(dbi)), blocks: []uint32{1}}}

	id, err := pdb.info()
	if err != nil {
		t.Fatal(err)
	}
	if id.age != 1 {
		t.Fatalf("got age %d, want DBI age 1", id.age)
	}
}

func TestDiscoverFunctionsUsesUnwindEntryAndRetainedNames(t *testing.T) {
	data := make([]byte, 0x500)
	putRuntimeFunction := func(index int, begin, end uint32) {
		offset := 0x400 + index*12
		binary.LittleEndian.PutUint32(data[offset:offset+4], begin)
		binary.LittleEndian.PutUint32(data[offset+4:offset+8], end)
	}
	putRuntimeFunction(0, 0x1010, 0x1030)
	putRuntimeFunction(1, 0x1040, 0x1060)
	putRuntimeFunction(2, 0x1080, 0x1090)
	image := peInfo{
		imageBase: 0x140000000, machine: pe.IMAGE_FILE_MACHINE_AMD64,
		entryRVA: 0x1040, exceptionRVA: 0x3000, exceptionSize: 36,
		sections: []peSection{
			{name: ".text", virtualAddress: 0x1000, virtualSize: 0x200, rawOffset: 0x200, rawSize: 0x200, characteristics: imageScnMemExecute},
			{name: ".pdata", virtualAddress: 0x3000, virtualSize: 0x100, rawOffset: 0x400, rawSize: 0x100},
		},
		coffSymbols: []retainedSymbol{{name: "_main", sectionNumber: 1, offset: 0x10}},
	}

	functions, err := discoverFunctions(data, image)
	if err != nil {
		t.Fatal(err)
	}
	if len(functions) != 3 {
		t.Fatalf("got %d functions, want 3: %+v", len(functions), functions)
	}
	if functions[0].Name != "main" || functions[0].Source != "coff" || functions[0].Size != 0x20 {
		t.Fatalf("retained main was not overlaid on unwind data: %+v", functions[0])
	}
	if functions[1].Name != "start" || functions[1].Source != "entry" || functions[1].Size != 0x20 {
		t.Fatalf("entry point was not named: %+v", functions[1])
	}
	if functions[2].Name != "sub_140001080" || functions[2].Source != "unwind" {
		t.Fatalf("stripped function did not receive a fallback name: %+v", functions[2])
	}
}

func TestRecognizableRetainedFunctionNames(t *testing.T) {
	for _, name := range []string{"main", "_wmain", "_mainCRTStartup", "WinMain@16", "DllMain"} {
		if !isRecognizableFunctionName(name) {
			t.Errorf("%q should be recognizable", name)
		}
	}
	if isRecognizableFunctionName("not_a_function") {
		t.Fatal("arbitrary data symbol was recognized as a function")
	}
}
