package analyzer

import (
	"bytes"
	"context"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
)

var little = binary.LittleEndian

const (
	msfMagic           = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
	imageDebugCodeView = 2
	imageScnMemExecute = 0x20000000
	noStream           = 0xffff

	sPub32       = 0x110e
	sLProc32     = 0x110f
	sGProc32     = 0x1110
	sLProc32ID   = 0x1146
	sGProc32ID   = 0x1147
	sLProc32DPC  = 0x1155
	sLProc32DPCI = 0x1156
	publicFunc   = 1 << 1

	procedureRecords symbolRecordFilter = 1
	publicRecords    symbolRecordFilter = 2
)

type symbolRecordFilter uint8

// Function is a function recovered from the matching PDB and resolved against
// a section in the uploaded PE image.
type Function struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	DecoratedName string `json:"decoratedName,omitempty"`
	Address       string `json:"address"`
	RVA           string `json:"rva"`
	Size          uint32 `json:"size"`
	Section       string `json:"section"`
	Module        string `json:"module,omitempty"`
	Visibility    string `json:"visibility"`
	Source        string `json:"source,omitempty"`

	sectionNumber uint16
	offset        uint32
}

type BinaryInfo struct {
	Machine   string `json:"machine"`
	ImageBase string `json:"imageBase"`
	PDBPath   string `json:"pdbPath"`
	GUID      string `json:"guid"`
	Age       uint32 `json:"age"`
	HasPDB    bool   `json:"hasPdb"`
	Symbols   string `json:"symbols"`
}

type Result struct {
	CacheID   string     `json:"cacheId,omitempty"`
	Binary    BinaryInfo `json:"binary"`
	Functions []Function `json:"functions"`
}

type Options struct {
	Workers          int
	Context          context.Context
	RawPDBExecutable string
	PDBPath          string
}

type peInfo struct {
	imageBase     uint64
	machine       uint16
	isPE64        bool
	sections      []peSection
	codeView      codeViewID
	hasCodeView   bool
	entryRVA      uint32
	exportRVA     uint32
	exportSize    uint32
	exceptionRVA  uint32
	exceptionSize uint32
	coffSymbols   []retainedSymbol
}

type retainedSymbol struct {
	name          string
	sectionNumber uint16
	offset        uint32
}

type peSection struct {
	name            string
	virtualAddress  uint32
	virtualSize     uint32
	rawOffset       uint32
	rawSize         uint32
	characteristics uint32
}

type codeViewID struct {
	guid    [16]byte
	age     uint32
	pdbPath string
}

// Analyze verifies that binaryData and pdbData belong together and returns all
// procedure records that can be mapped to executable PE sections.
func Analyze(binaryData, pdbData []byte) (Result, error) {
	return AnalyzeWithOptions(binaryData, pdbData, Options{})
}

func AnalyzeWithOptions(binaryData, pdbData []byte, options Options) (Result, error) {
	image, err := parsePE(binaryData)
	if err != nil {
		return Result{}, fmt.Errorf("uploaded file is not a valid x86-64 PE executable: %w", err)
	}
	if err := validateX64PE(image); err != nil {
		return Result{}, err
	}

	if len(pdbData) == 0 {
		functions, err := discoverFunctions(binaryData, image)
		if err != nil {
			return Result{}, fmt.Errorf("discover PE functions: %w", err)
		}
		if len(functions) == 0 {
			return Result{}, errors.New("the PE contains no discoverable executable functions")
		}
		return buildResult(image, functions, false), nil
	}

	type pdbResult struct {
		pdb *pdbFile
		raw *rawPDBResult
		id  codeViewID
		err error
	}
	parsedPDB := func() pdbResult {
		if options.RawPDBExecutable != "" {
			raw, err := extractRawPDB(options.Context, options.RawPDBExecutable, options.PDBPath, pdbData)
			return pdbResult{raw: &raw, id: codeViewID{guid: raw.guid, age: raw.age}, err: err}
		}
		pdb, err := openPDB(pdbData)
		if err != nil {
			return pdbResult{err: err}
		}
		id, err := pdb.info()
		return pdbResult{pdb: pdb, id: id, err: err}
	}()

	if parsedPDB.err != nil {
		if options.RawPDBExecutable != "" {
			return Result{}, fmt.Errorf("analyze PDB with RawPDB: %w", parsedPDB.err)
		}
		if parsedPDB.pdb == nil {
			return Result{}, fmt.Errorf("parse PDB: %w", parsedPDB.err)
		}
		return Result{}, fmt.Errorf("read PDB identity: %w", parsedPDB.err)
	}
	pdbID := parsedPDB.id
	if !image.hasCodeView {
		return Result{}, errors.New("the PE has no RSDS CodeView identity, so the supplied PDB cannot be verified")
	}
	if image.codeView.guid != pdbID.guid || image.codeView.age != pdbID.age {
		return Result{}, fmt.Errorf(
			"PDB does not match binary (binary %s age %d, PDB %s age %d)",
			formatGUID(image.codeView.guid), image.codeView.age,
			formatGUID(pdbID.guid), pdbID.age,
		)
	}

	var functions []Function
	if parsedPDB.raw != nil {
		functions = functionsFromRawPDB(*parsedPDB.raw, image)
	} else {
		workerCount := options.Workers
		if workerCount <= 0 {
			workerCount = runtime.GOMAXPROCS(0)
			if workerCount > 8 {
				workerCount = 8
			}
		}
		var err error
		functions, err = parsedPDB.pdb.functions(image, workerCount)
		if err != nil {
			return Result{}, fmt.Errorf("read PDB symbols: %w", err)
		}
	}
	if len(functions) == 0 {
		return Result{}, errors.New("the matching PDB contains no mappable function symbols")
	}

	for index := range functions {
		functions[index].Source = "pdb"
	}
	return buildResult(image, functions, true), nil
}

func validateX64PE(image peInfo) error {
	if image.machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return fmt.Errorf("uploaded binary is %s; only x86-64 PE executables are supported", machineName(image.machine))
	}
	if !image.isPE64 {
		return errors.New("uploaded binary has an invalid x86-64 PE header")
	}
	return nil
}

func buildResult(image peInfo, functions []Function, hasPDB bool) Result {
	guid := ""
	if image.hasCodeView {
		guid = formatGUID(image.codeView.guid)
	}
	symbols := "PE metadata"
	if hasPDB {
		symbols = "PDB + PE"
	}
	return Result{
		Binary: BinaryInfo{
			Machine: machineName(image.machine), ImageBase: fmt.Sprintf("0x%x", image.imageBase),
			PDBPath: displayBaseName(image.codeView.pdbPath), GUID: guid, Age: image.codeView.age,
			HasPDB: hasPDB, Symbols: symbols,
		},
		Functions: functions,
	}
}

func parsePE(data []byte) (peInfo, error) {
	file, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return peInfo{}, errors.New("input is not a valid PE executable")
	}
	defer file.Close()

	result := peInfo{machine: file.Machine}
	var debugRVA, debugSize uint32
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		result.imageBase = uint64(header.ImageBase)
		result.entryRVA = header.AddressOfEntryPoint
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_DEBUG {
			debugRVA = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
			debugSize = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].Size
		}
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			result.exportRVA = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
			result.exportSize = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size
		}
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION {
			result.exceptionRVA = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress
			result.exceptionSize = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size
		}
	case *pe.OptionalHeader64:
		result.isPE64 = true
		result.imageBase = header.ImageBase
		result.entryRVA = header.AddressOfEntryPoint
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_DEBUG {
			debugRVA = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
			debugSize = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].Size
		}
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			result.exportRVA = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
			result.exportSize = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size
		}
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION {
			result.exceptionRVA = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress
			result.exceptionSize = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size
		}
	default:
		return peInfo{}, errors.New("PE image has no supported optional header")
	}

	for _, section := range file.Sections {
		result.sections = append(result.sections, peSection{
			name:            strings.TrimRight(section.Name, "\x00"),
			virtualAddress:  section.VirtualAddress,
			virtualSize:     section.VirtualSize,
			rawOffset:       section.Offset,
			rawSize:         section.Size,
			characteristics: section.Characteristics,
		})
	}
	for _, symbol := range file.Symbols {
		if symbol.SectionNumber <= 0 || int(symbol.SectionNumber) > len(result.sections) {
			continue
		}
		section := result.sections[symbol.SectionNumber-1]
		if section.characteristics&imageScnMemExecute == 0 || symbol.Name == "" {
			continue
		}
		if symbol.Type&0x20 == 0 && !isRecognizableFunctionName(symbol.Name) {
			continue
		}
		result.coffSymbols = append(result.coffSymbols, retainedSymbol{
			name: symbol.Name, sectionNumber: uint16(symbol.SectionNumber), offset: symbol.Value,
		})
	}
	if debugRVA == 0 || debugSize < 28 {
		return result, nil
	}

	debugOffset, ok := result.rvaToFileOffset(debugRVA)
	if !ok || uint64(debugOffset)+uint64(debugSize) > uint64(len(data)) {
		return result, nil
	}
	for pos := uint64(debugOffset); pos+28 <= uint64(debugOffset)+uint64(debugSize); pos += 28 {
		record := data[pos : pos+28]
		if little.Uint32(record[12:16]) != imageDebugCodeView {
			continue
		}
		size := little.Uint32(record[16:20])
		raw := little.Uint32(record[24:28])
		if size < 24 || uint64(raw)+uint64(size) > uint64(len(data)) {
			continue
		}
		cv := data[raw : raw+size]
		if string(cv[:4]) != "RSDS" {
			continue
		}
		copy(result.codeView.guid[:], cv[4:20])
		result.codeView.age = little.Uint32(cv[20:24])
		result.codeView.pdbPath = cString(cv[24:])
		result.hasCodeView = true
		return result, nil
	}
	return result, nil
}

func (p peInfo) rvaToFileOffset(rva uint32) (uint32, bool) {
	for _, section := range p.sections {
		span := section.virtualSize
		if section.rawSize > span {
			span = section.rawSize
		}
		if rva >= section.virtualAddress && uint64(rva) < uint64(section.virtualAddress)+uint64(span) {
			delta := rva - section.virtualAddress
			if delta >= section.rawSize {
				return 0, false
			}
			return section.rawOffset + delta, true
		}
	}
	return 0, false
}

func (p peInfo) resolve(sectionNumber uint16, offset uint32) (peSection, uint32, bool) {
	if sectionNumber == 0 || int(sectionNumber) > len(p.sections) {
		return peSection{}, 0, false
	}
	section := p.sections[sectionNumber-1]
	if section.characteristics&imageScnMemExecute == 0 {
		return peSection{}, 0, false
	}
	if uint64(offset) >= uint64(section.virtualSize) && uint64(offset) >= uint64(section.rawSize) {
		return peSection{}, 0, false
	}
	return section, section.virtualAddress + offset, true
}

func (p peInfo) resolveRVA(rva uint32) (peSection, uint16, uint32, bool) {
	for index, section := range p.sections {
		span := section.virtualSize
		if section.rawSize > span {
			span = section.rawSize
		}
		if rva < section.virtualAddress || uint64(rva) >= uint64(section.virtualAddress)+uint64(span) {
			continue
		}
		offset := rva - section.virtualAddress
		if section.characteristics&imageScnMemExecute == 0 {
			return peSection{}, 0, 0, false
		}
		return section, uint16(index + 1), offset, true
	}
	return peSection{}, 0, 0, false
}

type discoveredFunction struct {
	function  Function
	priority  int
	exactSize bool
}

func discoverFunctions(data []byte, image peInfo) ([]Function, error) {
	byLocation := make(map[uint64]discoveredFunction)
	add := func(rva uint32, size uint32, name, source, visibility string, priority int, exactSize bool) {
		section, sectionNumber, offset, ok := image.resolveRVA(rva)
		if !ok {
			return
		}
		key := locationKey(sectionNumber, offset)
		candidate := Function{
			Name: name, Address: fmt.Sprintf("0x%x", image.imageBase+uint64(rva)),
			RVA: fmt.Sprintf("0x%x", rva), Size: size, Section: section.name,
			Visibility: visibility, Source: source,
			sectionNumber: sectionNumber, offset: offset,
		}
		if candidate.Name == "" {
			candidate.Name = fmt.Sprintf("sub_%x", image.imageBase+uint64(rva))
		}
		current, exists := byLocation[key]
		if !exists {
			byLocation[key] = discoveredFunction{function: candidate, priority: priority, exactSize: exactSize}
			return
		}
		if candidate.Size != 0 && (current.function.Size == 0 || exactSize) {
			current.function.Size = candidate.Size
			current.exactSize = exactSize
		}
		if priority >= current.priority {
			current.function.Name = candidate.Name
			current.function.Source = candidate.Source
			current.function.Visibility = candidate.Visibility
			current.priority = priority
		}
		byLocation[key] = current
	}

	// AMD64 .pdata contains sorted RUNTIME_FUNCTION records and provides the
	// most reliable function boundaries available in a stripped executable.
	if image.machine == pe.IMAGE_FILE_MACHINE_AMD64 && image.exceptionRVA != 0 {
		count := image.exceptionSize / 12
		if count > 1_000_000 {
			return nil, errors.New("PE exception directory contains too many records")
		}
		if table, ok := readRVA(data, image, image.exceptionRVA, count*12); ok {
			for index := uint32(0); index < count; index++ {
				record := table[index*12 : index*12+12]
				begin := little.Uint32(record[0:4])
				end := little.Uint32(record[4:8])
				if begin != 0 && end > begin {
					add(begin, end-begin, "", "unwind", "local", 1, true)
				}
			}
		}
	}

	for _, exported := range readExports(data, image) {
		add(exported.rva, 0, exported.name, "export", "public", 3, false)
	}
	if image.entryRVA != 0 {
		add(image.entryRVA, 0, "start", "entry", "global", 2, false)
	}
	for _, symbol := range image.coffSymbols {
		section, rva, ok := image.resolve(symbol.sectionNumber, symbol.offset)
		if !ok || section.characteristics&imageScnMemExecute == 0 {
			continue
		}
		add(rva, 0, displayRetainedFunctionName(symbol.name), "coff", "global", 4, false)
	}

	functions := make([]Function, 0, len(byLocation))
	for _, discovered := range byLocation {
		functions = append(functions, discovered.function)
	}
	sort.Slice(functions, func(i, j int) bool {
		if functions[i].sectionNumber != functions[j].sectionNumber {
			return functions[i].sectionNumber < functions[j].sectionNumber
		}
		return functions[i].offset < functions[j].offset
	})
	for index := range functions {
		if functions[index].Size == 0 {
			section := image.sections[functions[index].sectionNumber-1]
			end := section.virtualSize
			if section.rawSize > end {
				end = section.rawSize
			}
			if index+1 < len(functions) && functions[index+1].sectionNumber == functions[index].sectionNumber {
				end = functions[index+1].offset
			}
			if end > functions[index].offset {
				functions[index].Size = end - functions[index].offset
			}
		}
		functions[index].ID = fmt.Sprintf("fn_%04x_%08x", functions[index].sectionNumber, functions[index].offset)
	}
	return functions, nil
}

type exportedFunction struct {
	rva  uint32
	name string
}

func readExports(data []byte, image peInfo) []exportedFunction {
	if image.exportRVA == 0 || image.exportSize < 40 {
		return nil
	}
	directory, ok := readRVA(data, image, image.exportRVA, 40)
	if !ok {
		return nil
	}
	functionCount := little.Uint32(directory[20:24])
	nameCount := little.Uint32(directory[24:28])
	if functionCount > 1_000_000 || nameCount > 1_000_000 {
		return nil
	}
	functionTableRVA := little.Uint32(directory[28:32])
	nameTableRVA := little.Uint32(directory[32:36])
	ordinalTableRVA := little.Uint32(directory[36:40])
	functionTable, ok := readRVA(data, image, functionTableRVA, functionCount*4)
	if !ok {
		return nil
	}

	functions := make([]exportedFunction, functionCount)
	for index := uint32(0); index < functionCount; index++ {
		rva := little.Uint32(functionTable[index*4 : index*4+4])
		// RVAs inside the export directory are forwarder strings, not code.
		if rva != 0 && !(rva >= image.exportRVA && uint64(rva) < uint64(image.exportRVA)+uint64(image.exportSize)) {
			functions[index] = exportedFunction{rva: rva}
		}
	}
	nameTable, namesOK := readRVA(data, image, nameTableRVA, nameCount*4)
	ordinalTable, ordinalsOK := readRVA(data, image, ordinalTableRVA, nameCount*2)
	if namesOK && ordinalsOK {
		for index := uint32(0); index < nameCount; index++ {
			ordinal := uint32(little.Uint16(ordinalTable[index*2 : index*2+2]))
			if ordinal >= functionCount || functions[ordinal].rva == 0 {
				continue
			}
			nameRVA := little.Uint32(nameTable[index*4 : index*4+4])
			functions[ordinal].name = readCStringRVA(data, image, nameRVA)
		}
	}
	result := functions[:0]
	for _, function := range functions {
		if function.rva != 0 {
			result = append(result, function)
		}
	}
	return result
}

func readRVA(data []byte, image peInfo, rva, size uint32) ([]byte, bool) {
	offset, ok := image.rvaToFileOffset(rva)
	if !ok || uint64(offset)+uint64(size) > uint64(len(data)) {
		return nil, false
	}
	return data[offset : offset+size], true
}

func readCStringRVA(data []byte, image peInfo, rva uint32) string {
	offset, ok := image.rvaToFileOffset(rva)
	if !ok || int(offset) >= len(data) {
		return ""
	}
	remaining := data[offset:]
	if len(remaining) > 4096 {
		remaining = remaining[:4096]
	}
	return cString(remaining)
}

func isRecognizableFunctionName(name string) bool {
	normalized := strings.ToLower(displayRetainedFunctionName(name))
	switch normalized {
	case "main", "wmain", "winmain", "wwinmain", "dllmain", "start",
		"maincrtstartup", "wmaincrtstartup", "winmaincrtstartup", "wwinmaincrtstartup", "dllmaincrtstartup":
		return true
	default:
		return false
	}
}

func displayRetainedFunctionName(name string) string {
	if strings.HasPrefix(name, "_") && !strings.HasPrefix(name, "__") {
		name = name[1:]
	}
	if at := strings.LastIndexByte(name, '@'); at > 0 {
		digitsOnly := true
		for _, char := range name[at+1:] {
			if char < '0' || char > '9' {
				digitsOnly = false
				break
			}
		}
		if digitsOnly {
			name = name[:at]
		}
	}
	lower := strings.ToLower(name)
	switch lower {
	case "maincrtstartup", "wmaincrtstartup", "winmaincrtstartup", "wwinmaincrtstartup", "dllmaincrtstartup":
		return "start"
	}
	return name
}

type pdbFile struct {
	data      []byte
	blockSize uint32
	streams   []pdbStream
}

type pdbStream struct {
	size   uint32
	blocks []uint32
}

type pdbStreamView struct {
	pdb    *pdbFile
	stream *pdbStream
}

func openPDB(data []byte) (*pdbFile, error) {
	if len(data) < 56 || string(data[:32]) != msfMagic {
		return nil, errors.New("input is not an MSF 7.0 native PDB")
	}
	blockSize := little.Uint32(data[32:36])
	numBlocks := little.Uint32(data[40:44])
	directorySize := little.Uint32(data[44:48])
	blockMap := little.Uint32(data[52:56])
	if blockSize < 512 || blockSize > 65536 || blockSize&(blockSize-1) != 0 {
		return nil, errors.New("invalid PDB block size")
	}
	if numBlocks == 0 || uint64(numBlocks)*uint64(blockSize) > uint64(len(data)) {
		return nil, errors.New("PDB block table exceeds file size")
	}
	directoryBlocks := blocksFor(directorySize, blockSize)
	if directoryBlocks > blockSize/4 {
		return nil, errors.New("PDB stream directory block map is too large")
	}
	mapOffset := uint64(blockMap) * uint64(blockSize)
	if mapOffset+uint64(directoryBlocks)*4 > uint64(len(data)) {
		return nil, errors.New("PDB stream directory map is truncated")
	}
	pages := make([]uint32, directoryBlocks)
	for i := range pages {
		pages[i] = little.Uint32(data[mapOffset+uint64(i)*4:])
	}
	directory, err := readBlocks(data, blockSize, numBlocks, pages, directorySize)
	if err != nil {
		return nil, fmt.Errorf("read stream directory: %w", err)
	}
	if len(directory) < 4 {
		return nil, errors.New("PDB stream directory is truncated")
	}
	numStreams := little.Uint32(directory[:4])
	if numStreams > 1_000_000 || uint64(4+numStreams*4) > uint64(len(directory)) {
		return nil, errors.New("invalid PDB stream count")
	}
	streams := make([]pdbStream, numStreams)
	pos := uint64(4)
	for i := range streams {
		streams[i].size = little.Uint32(directory[pos : pos+4])
		pos += 4
	}
	for i := range streams {
		if streams[i].size == 0xffffffff {
			continue
		}
		count := blocksFor(streams[i].size, blockSize)
		if pos+uint64(count)*4 > uint64(len(directory)) {
			return nil, errors.New("PDB stream block list is truncated")
		}
		streams[i].blocks = make([]uint32, count)
		for j := range streams[i].blocks {
			streams[i].blocks[j] = little.Uint32(directory[pos : pos+4])
			pos += 4
		}
	}
	return &pdbFile{data: data, blockSize: blockSize, streams: streams}, nil
}

func (p *pdbFile) streamView(index uint16) (pdbStreamView, error) {
	if int(index) >= len(p.streams) || p.streams[index].size == 0xffffffff {
		return pdbStreamView{}, fmt.Errorf("PDB stream %d is missing", index)
	}
	return pdbStreamView{pdb: p, stream: &p.streams[index]}, nil
}

// slice returns a direct view into the PDB when the requested bytes live in a
// single MSF block. Only records crossing a block boundary need an allocation.
func (view pdbStreamView) slice(offset, length uint64) ([]byte, error) {
	if offset > uint64(view.stream.size) || length > uint64(view.stream.size)-offset {
		return nil, errors.New("PDB stream read is out of range")
	}
	if length == 0 {
		return []byte{}, nil
	}
	blockSize := uint64(view.pdb.blockSize)
	logicalBlock := offset / blockSize
	inBlock := offset % blockSize
	if logicalBlock >= uint64(len(view.stream.blocks)) {
		return nil, errors.New("PDB stream block is missing")
	}
	if inBlock+length <= blockSize {
		physicalBlock := view.stream.blocks[logicalBlock]
		start := uint64(physicalBlock)*blockSize + inBlock
		if start+length > uint64(len(view.pdb.data)) {
			return nil, errors.New("PDB stream block is truncated")
		}
		return view.pdb.data[start : start+length], nil
	}

	out := make([]byte, length)
	written := uint64(0)
	for written < length {
		position := offset + written
		logicalBlock = position / blockSize
		inBlock = position % blockSize
		if logicalBlock >= uint64(len(view.stream.blocks)) {
			return nil, errors.New("PDB stream block is missing")
		}
		physicalBlock := view.stream.blocks[logicalBlock]
		start := uint64(physicalBlock)*blockSize + inBlock
		amount := blockSize - inBlock
		if remaining := length - written; remaining < amount {
			amount = remaining
		}
		if start+amount > uint64(len(view.pdb.data)) {
			return nil, errors.New("PDB stream block is truncated")
		}
		copy(out[written:written+amount], view.pdb.data[start:start+amount])
		written += amount
	}
	return out, nil
}

func readBlocks(data []byte, blockSize, numBlocks uint32, blocks []uint32, size uint32) ([]byte, error) {
	if uint64(len(blocks))*uint64(blockSize) < uint64(size) {
		return nil, errors.New("not enough blocks")
	}
	out := make([]byte, 0, size)
	remaining := uint64(size)
	for _, block := range blocks {
		if block >= numBlocks {
			return nil, errors.New("block number is out of range")
		}
		start := uint64(block) * uint64(blockSize)
		amount := uint64(blockSize)
		if remaining < amount {
			amount = remaining
		}
		if start+amount > uint64(len(data)) {
			return nil, errors.New("block is truncated")
		}
		out = append(out, data[start:start+amount]...)
		remaining -= amount
		if remaining == 0 {
			break
		}
	}
	return out, nil
}

func blocksFor(size, blockSize uint32) uint32 {
	if size == 0 {
		return 0
	}
	return (size-1)/blockSize + 1
}

func (p *pdbFile) info() (codeViewID, error) {
	view, err := p.streamView(1)
	if err != nil {
		return codeViewID{}, err
	}
	if view.stream.size < 28 {
		return codeViewID{}, errors.New("PDB info stream is truncated")
	}
	data, err := view.slice(0, 28)
	if err != nil {
		return codeViewID{}, err
	}
	var id codeViewID
	id.age = little.Uint32(data[8:12])
	copy(id.guid[:], data[12:28])

	// Creating a stripped/public PDB increments the age in the PDB info stream,
	// but the DBI age remains the age stamped into the PE's RSDS record. Native
	// symbol loaders use that DBI value when validating these public PDBs.
	if dbi, dbiErr := p.streamView(3); dbiErr == nil && dbi.stream.size >= 12 {
		if header, headerErr := dbi.slice(8, 4); headerErr == nil {
			id.age = little.Uint32(header)
		}
	}
	return id, nil
}

type dbiModule struct {
	name       string
	stream     uint16
	symbolSize uint32
}

func (p *pdbFile) functions(image peInfo, requestedWorkers int) ([]Function, error) {
	dbi, err := p.streamView(3)
	if err != nil {
		return nil, err
	}
	if dbi.stream.size < 64 {
		return nil, errors.New("DBI stream is truncated")
	}
	header, err := dbi.slice(0, 64)
	if err != nil {
		return nil, err
	}
	symbolStream := little.Uint16(header[20:22])
	moduleBytes := little.Uint32(header[24:28])
	if uint64(64)+uint64(moduleBytes) > uint64(dbi.stream.size) {
		return nil, errors.New("DBI module substream is truncated")
	}
	moduleData, err := dbi.slice(64, uint64(moduleBytes))
	if err != nil {
		return nil, err
	}
	modules, err := parseModules(moduleData)
	if err != nil {
		return nil, err
	}

	mapHint := len(modules) * 8
	if mapHint > 1_000_000 {
		mapHint = 1_000_000
	}
	byLocation := make(map[uint64]Function, mapHint)
	var locationsMu sync.Mutex
	workerCount := requestedWorkers
	if workerCount > len(modules) {
		workerCount = len(modules)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	publicResults := make(chan map[uint64]Function, 1)
	if symbolStream != noStream {
		go func() {
			publicResults <- p.publicFunctions(symbolStream, image)
		}()
	} else {
		publicResults <- nil
	}

	moduleJobs := make(chan dbiModule, workerCount)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for module := range moduleJobs {
				if module.stream == noStream || module.symbolSize <= 4 {
					continue
				}
				stream, streamErr := p.streamView(module.stream)
				if streamErr != nil || stream.stream.size < 4 {
					continue
				}
				limit := uint64(module.symbolSize)
				if limit > uint64(stream.stream.size) {
					limit = uint64(stream.stream.size)
				}
				found := make([]Function, 0, 16)
				parseStreamSymbolRecords(stream, 4, limit, procedureRecords, func(kind uint16, body []byte) {
					if fn, ok := parseProcedure(kind, body, module.name, image); ok {
						found = append(found, fn)
					}
				})
				if len(found) == 0 {
					continue
				}
				locationsMu.Lock()
				for _, fn := range found {
					key := locationKey(fn.sectionNumber, fn.offset)
					if old, exists := byLocation[key]; !exists || old.Size == 0 {
						byLocation[key] = fn
					}
				}
				locationsMu.Unlock()
			}
		}()
	}
	for _, module := range modules {
		moduleJobs <- module
	}
	close(moduleJobs)
	workers.Wait()

	for key, public := range <-publicResults {
		if existing, found := byLocation[key]; found {
			if existing.Name != public.Name {
				existing.DecoratedName = public.Name
				byLocation[key] = existing
			}
			continue
		}
		byLocation[key] = public
	}

	functions := make([]Function, 0, len(byLocation))
	for _, fn := range byLocation {
		functions = append(functions, fn)
	}
	return sortAndIdentifyFunctions(functions), nil
}

func sortAndIdentifyFunctions(functions []Function) []Function {
	sort.Slice(functions, func(i, j int) bool {
		if functions[i].sectionNumber != functions[j].sectionNumber {
			return functions[i].sectionNumber < functions[j].sectionNumber
		}
		return functions[i].offset < functions[j].offset
	})
	for i := range functions {
		functions[i].ID = fmt.Sprintf("fn_%04x_%08x", functions[i].sectionNumber, functions[i].offset)
	}
	return functions
}

func (p *pdbFile) publicFunctions(symbolStream uint16, image peInfo) map[uint64]Function {
	byLocation := make(map[uint64]Function)
	records, err := p.streamView(symbolStream)
	if err != nil {
		return byLocation
	}
	parseStreamSymbolRecords(records, 0, uint64(records.stream.size), publicRecords, func(_ uint16, body []byte) {
		if len(body) < 11 {
			return
		}
		flags := little.Uint32(body[0:4])
		if flags&publicFunc == 0 {
			return
		}
		offset := little.Uint32(body[4:8])
		sectionNumber := little.Uint16(body[8:10])
		name := cString(body[10:])
		section, rva, ok := image.resolve(sectionNumber, offset)
		if !ok || name == "" {
			return
		}
		key := locationKey(sectionNumber, offset)
		if _, exists := byLocation[key]; exists {
			return
		}
		byLocation[key] = Function{
			Name: name, RVA: fmt.Sprintf("0x%x", rva),
			Address: fmt.Sprintf("0x%x", image.imageBase+uint64(rva)),
			Section: section.name, Visibility: "public",
			sectionNumber: sectionNumber, offset: offset,
		}
	})
	return byLocation
}

func parseModules(data []byte) ([]dbiModule, error) {
	var modules []dbiModule
	for pos := 0; pos < len(data); {
		if len(data)-pos < 64 {
			return nil, errors.New("DBI module record is truncated")
		}
		stream := little.Uint16(data[pos+34 : pos+36])
		symbolSize := little.Uint32(data[pos+36 : pos+40])
		nameStart := pos + 64
		nameEnd := bytes.IndexByte(data[nameStart:], 0)
		if nameEnd < 0 {
			return nil, errors.New("DBI module name is unterminated")
		}
		name := string(data[nameStart : nameStart+nameEnd])
		objectStart := nameStart + nameEnd + 1
		objectEnd := bytes.IndexByte(data[objectStart:], 0)
		if objectEnd < 0 {
			return nil, errors.New("DBI object name is unterminated")
		}
		next := align4(objectStart + objectEnd + 1)
		if next > len(data) || next <= pos {
			return nil, errors.New("invalid DBI module record size")
		}
		modules = append(modules, dbiModule{name: displayBaseName(name), stream: stream, symbolSize: symbolSize})
		pos = next
	}
	return modules, nil
}

func parseSymbolRecords(data []byte, visit func(kind uint16, body []byte)) {
	for pos := 0; pos+4 <= len(data); {
		recordLength := int(little.Uint16(data[pos : pos+2]))
		if recordLength < 2 || pos+2+recordLength > len(data) {
			return
		}
		kind := little.Uint16(data[pos+2 : pos+4])
		visit(kind, data[pos+4:pos+2+recordLength])
		pos += 2 + recordLength
	}
}

func parseStreamSymbolRecords(stream pdbStreamView, start, limit uint64, filter symbolRecordFilter, visit func(kind uint16, body []byte)) {
	for position := start; position+4 <= limit; {
		header, err := stream.slice(position, 4)
		if err != nil {
			return
		}
		recordLength := uint64(little.Uint16(header[0:2]))
		if recordLength < 2 || position+2+recordLength > limit {
			return
		}
		kind := little.Uint16(header[2:4])
		if acceptsSymbolRecord(filter, kind) {
			body, err := stream.slice(position+4, recordLength-2)
			if err != nil {
				return
			}
			visit(kind, body)
		}
		position += 2 + recordLength
	}
}

func acceptsSymbolRecord(filter symbolRecordFilter, kind uint16) bool {
	switch filter {
	case procedureRecords:
		switch kind {
		case sGProc32, sGProc32ID, sLProc32, sLProc32ID, sLProc32DPC, sLProc32DPCI:
			return true
		}
	case publicRecords:
		return kind == sPub32
	}
	return false
}

func parseProcedure(kind uint16, body []byte, module string, image peInfo) (Function, bool) {
	visibility := ""
	switch kind {
	case sGProc32, sGProc32ID:
		visibility = "global"
	case sLProc32, sLProc32ID, sLProc32DPC, sLProc32DPCI:
		visibility = "local"
	default:
		return Function{}, false
	}
	if len(body) < 36 {
		return Function{}, false
	}
	size := little.Uint32(body[12:16])
	offset := little.Uint32(body[28:32])
	sectionNumber := little.Uint16(body[32:34])
	name := cString(body[35:])
	section, rva, ok := image.resolve(sectionNumber, offset)
	if !ok || name == "" {
		return Function{}, false
	}
	return Function{
		Name: name, Address: fmt.Sprintf("0x%x", image.imageBase+uint64(rva)),
		RVA: fmt.Sprintf("0x%x", rva), Size: size, Section: section.name,
		Module: module, Visibility: visibility,
		sectionNumber: sectionNumber, offset: offset,
	}, true
}

func locationKey(section uint16, offset uint32) uint64 {
	return uint64(section)<<32 | uint64(offset)
}

func cString(data []byte) string {
	if end := bytes.IndexByte(data, 0); end >= 0 {
		data = data[:end]
	}
	return string(data)
}

func align4(value int) int { return (value + 3) &^ 3 }

func displayBaseName(value string) string {
	value = strings.TrimRight(value, "\\/")
	if at := strings.LastIndexAny(value, "\\/"); at >= 0 {
		return value[at+1:]
	}
	return value
}

func formatGUID(raw [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		little.Uint32(raw[0:4]), little.Uint16(raw[4:6]), little.Uint16(raw[6:8]),
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])
}

func machineName(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86-64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "ARM"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "ARM64"
	default:
		return fmt.Sprintf("0x%04x", machine)
	}
}
