package disassembler

import (
	"bufio"
	"bytes"
	"context"
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"recompiler/backend/internal/analyzer"
)

const maxFunctionBytes uint64 = 64 << 10

var instructionLine = regexp.MustCompile(`^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*([^\s]+)(?:\s+(.*?))?\s*$`)

// Config identifies the LLVM disassembler bundled with the recompiler.
type Config struct {
	ObjDump string
}

type Instruction struct {
	Address  string `json:"address"`
	Offset   uint64 `json:"offset"`
	Bytes    string `json:"bytes"`
	Mnemonic string `json:"mnemonic"`
	Operands string `json:"operands,omitempty"`
	BlockID  string `json:"blockId"`

	address uint64
	size    uint64
}

type BasicBlock struct {
	ID               string `json:"id"`
	StartAddress     string `json:"startAddress"`
	EndAddress       string `json:"endAddress"`
	InstructionStart int    `json:"instructionStart"`
	InstructionEnd   int    `json:"instructionEnd"`
	Reachable        bool   `json:"reachable"`
	Terminal         string `json:"terminal,omitempty"`

	start uint64
}

type Edge struct {
	From          string `json:"from"`
	To            string `json:"to,omitempty"`
	Type          string `json:"type"`
	TargetAddress string `json:"targetAddress,omitempty"`
	External      bool   `json:"external,omitempty"`
}

type Result struct {
	FunctionName string        `json:"functionName"`
	Address      string        `json:"address"`
	EndAddress   string        `json:"endAddress"`
	Boundary     string        `json:"boundary"`
	Truncated    bool          `json:"truncated"`
	Instructions []Instruction `json:"instructions"`
	Blocks       []BasicBlock  `json:"blocks"`
	Edges        []Edge        `json:"edges"`
}

// Analyze disassembles a PDB-validated function and derives an intraprocedural
// basic-block graph from its direct branches.
func Analyze(ctx context.Context, config Config, binaryData []byte, function analyzer.Function, functions []analyzer.Function) (Result, error) {
	if strings.TrimSpace(config.ObjDump) == "" {
		return Result{}, errors.New("LLVM objdump is not configured")
	}
	if _, err := os.Stat(config.ObjDump); err != nil {
		return Result{}, fmt.Errorf("find LLVM objdump: %w", err)
	}

	start, err := parseAddress(function.Address)
	if err != nil {
		return Result{}, fmt.Errorf("invalid function address %q", function.Address)
	}
	stop, boundary, truncated := functionBoundary(start, function, functions)
	if sectionEnd, ok := executableSectionEnd(binaryData, start); ok && stop > sectionEnd {
		stop = sectionEnd
		if boundary == "safety limit" {
			boundary = "PE section end"
		} else {
			boundary += " (capped at PE section end)"
			truncated = true
		}
	}

	temporary, err := os.CreateTemp("", "recompiler-disassembly-*.exe")
	if err != nil {
		return Result{}, fmt.Errorf("create temporary binary: %w", err)
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return Result{}, fmt.Errorf("secure temporary binary: %w", err)
	}
	if _, err := temporary.Write(binaryData); err != nil {
		temporary.Close()
		return Result{}, fmt.Errorf("write temporary binary: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return Result{}, fmt.Errorf("close temporary binary: %w", err)
	}

	command := exec.CommandContext(ctx, config.ObjDump,
		"--disassemble",
		"--x86-asm-syntax=intel",
		fmt.Sprintf("--start-address=0x%x", start),
		fmt.Sprintf("--stop-address=0x%x", stop),
		path,
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		diagnostic := strings.TrimSpace(stderr.String())
		if diagnostic == "" {
			diagnostic = err.Error()
		}
		return Result{}, fmt.Errorf("disassembler failed: %s", diagnostic)
	}

	instructions, err := parseInstructions(output, start, stop)
	if err != nil {
		return Result{}, err
	}
	instructions = trimTrailingAlignment(instructions)
	blocks, edges := buildGraph(instructions)
	return Result{
		FunctionName: function.Name,
		Address:      formatAddress(start),
		EndAddress:   formatAddress(stop),
		Boundary:     boundary,
		Truncated:    truncated,
		Instructions: instructions,
		Blocks:       blocks,
		Edges:        edges,
	}, nil
}

func executableSectionEnd(binaryData []byte, address uint64) (uint64, bool) {
	file, err := pe.NewFile(bytes.NewReader(binaryData))
	if err != nil {
		return 0, false
	}
	defer file.Close()
	var imageBase uint64
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(header.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = header.ImageBase
	default:
		return 0, false
	}
	for _, section := range file.Sections {
		if section.Characteristics&0x20000000 == 0 {
			continue
		}
		start := imageBase + uint64(section.VirtualAddress)
		span := uint64(section.VirtualSize)
		if span == 0 || uint64(section.Size) < span {
			span = uint64(section.Size)
		}
		end := start + span
		if address >= start && address < end {
			return end, true
		}
	}
	return 0, false
}

func trimTrailingAlignment(instructions []Instruction) []Instruction {
	cut := len(instructions)
	for cut > 0 {
		mnemonic := instructions[cut-1].Mnemonic
		if mnemonic != "nop" && mnemonic != "int3" {
			break
		}
		cut--
	}
	if cut == 0 {
		return instructions
	}
	ending := branchKind(instructions[cut-1].Mnemonic)
	if ending == "return" || ending == "jump" || ending == "trap" {
		return instructions[:cut]
	}
	return instructions
}

func functionBoundary(start uint64, function analyzer.Function, functions []analyzer.Function) (uint64, string, bool) {
	var stop uint64
	boundary := "safety limit"
	if function.Size > 0 {
		stop = start + uint64(function.Size)
		if function.Source == "" || function.Source == "pdb" {
			boundary = "PDB size"
		} else if function.Source == "unwind" {
			boundary = "PE unwind size"
		} else {
			boundary = "PE-derived size"
		}
	} else {
		for _, candidate := range functions {
			if candidate.Section != function.Section {
				continue
			}
			address, err := parseAddress(candidate.Address)
			if err == nil && address > start && (stop == 0 || address < stop) {
				stop = address
			}
		}
		if stop != 0 {
			if function.Source == "" || function.Source == "pdb" {
				boundary = "next PDB symbol"
			} else {
				boundary = "next discovered function"
			}
		}
	}
	if stop == 0 || stop <= start {
		stop = start + maxFunctionBytes
	}
	truncated := stop-start > maxFunctionBytes
	if truncated {
		stop = start + maxFunctionBytes
		boundary += " (capped at 64 KiB)"
	}
	return stop, boundary, truncated
}

func parseInstructions(output []byte, start, stop uint64) ([]Instruction, error) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	instructions := make([]Instruction, 0, 128)
	for scanner.Scan() {
		matches := instructionLine.FindStringSubmatch(scanner.Text())
		if matches == nil {
			continue
		}
		address, err := strconv.ParseUint(matches[1], 16, 64)
		if err != nil || address < start || address >= stop {
			continue
		}
		byteFields := strings.Fields(matches[2])
		if len(byteFields) == 0 {
			continue
		}
		instructions = append(instructions, Instruction{
			Address:  formatAddress(address),
			Offset:   address - start,
			Bytes:    strings.Join(byteFields, " "),
			Mnemonic: strings.ToLower(matches[3]),
			Operands: strings.TrimSpace(matches[4]),
			address:  address,
			size:     uint64(len(byteFields)),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read disassembler output: %w", err)
	}
	if len(instructions) == 0 {
		return nil, errors.New("the selected function produced no disassembly")
	}
	sort.Slice(instructions, func(i, j int) bool { return instructions[i].address < instructions[j].address })
	return instructions, nil
}

func buildGraph(instructions []Instruction) ([]BasicBlock, []Edge) {
	addressToInstruction := make(map[uint64]int, len(instructions))
	for index := range instructions {
		addressToInstruction[instructions[index].address] = index
	}
	leaders := map[uint64]bool{instructions[0].address: true}
	for index, instruction := range instructions {
		kind := branchKind(instruction.Mnemonic)
		if target, ok := directTarget(instruction.Operands); ok {
			if _, internal := addressToInstruction[target]; internal && (kind == "taken" || kind == "jump") {
				leaders[target] = true
			}
		}
		if kind == "taken" || kind == "jump" || kind == "return" || kind == "trap" {
			if index+1 < len(instructions) {
				leaders[instructions[index+1].address] = true
			}
		}
	}

	blocks := make([]BasicBlock, 0, len(leaders))
	blockForAddress := make(map[uint64]string, len(instructions))
	blockStart := 0
	for index := 1; index <= len(instructions); index++ {
		if index < len(instructions) && !leaders[instructions[index].address] {
			continue
		}
		last := instructions[index-1]
		id := fmt.Sprintf("block-%d", len(blocks))
		block := BasicBlock{
			ID:               id,
			StartAddress:     instructions[blockStart].Address,
			EndAddress:       formatAddress(last.address + last.size),
			InstructionStart: blockStart,
			InstructionEnd:   index,
			start:            instructions[blockStart].address,
		}
		for instructionIndex := blockStart; instructionIndex < index; instructionIndex++ {
			instructions[instructionIndex].BlockID = id
			blockForAddress[instructions[instructionIndex].address] = id
		}
		blocks = append(blocks, block)
		blockStart = index
	}

	edges := make([]Edge, 0, len(blocks)*2)
	seenEdges := make(map[string]bool)
	for blockIndex := range blocks {
		block := &blocks[blockIndex]
		last := instructions[block.InstructionEnd-1]
		kind := branchKind(last.Mnemonic)
		target, direct := directTarget(last.Operands)
		if kind == "taken" || kind == "jump" {
			if direct {
				if targetBlock, internal := blockForAddress[target]; internal {
					appendEdge(&edges, seenEdges, Edge{From: block.ID, To: targetBlock, Type: kind, TargetAddress: formatAddress(target)})
				} else {
					appendEdge(&edges, seenEdges, Edge{From: block.ID, Type: kind, TargetAddress: formatAddress(target), External: true})
					if kind == "jump" {
						block.Terminal = "jump outside function"
					}
				}
			} else if kind == "jump" {
				block.Terminal = "indirect jump"
			}
		}
		if kind == "return" {
			block.Terminal = "return"
		}
		if kind == "trap" {
			block.Terminal = "trap"
		}
		if kind != "jump" && kind != "return" && kind != "trap" && blockIndex+1 < len(blocks) {
			next := blocks[blockIndex+1]
			appendEdge(&edges, seenEdges, Edge{From: block.ID, To: next.ID, Type: "fallthrough", TargetAddress: next.StartAddress})
		}
	}

	if len(blocks) > 0 {
		blockIndices := edgesBlockIndex(blocks)
		blocks[0].Reachable = true
		changed := true
		for changed {
			changed = false
			for _, edge := range edges {
				fromIndex := blockIndex(blockIndices, edge.From)
				if edge.To == "" || fromIndex < 0 || !blocks[fromIndex].Reachable {
					continue
				}
				targetIndex := blockIndex(blockIndices, edge.To)
				if targetIndex >= 0 && !blocks[targetIndex].Reachable {
					blocks[targetIndex].Reachable = true
					changed = true
				}
			}
		}
	}
	return blocks, edges
}

func edgesBlockIndex(blocks []BasicBlock) map[string]int {
	indices := make(map[string]int, len(blocks))
	for index := range blocks {
		indices[blocks[index].ID] = index
	}
	return indices
}

func blockIndex(indices map[string]int, id string) int {
	if index, ok := indices[id]; ok {
		return index
	}
	return -1
}

func appendEdge(edges *[]Edge, seen map[string]bool, edge Edge) {
	key := edge.From + "\x00" + edge.To + "\x00" + edge.Type + "\x00" + edge.TargetAddress
	if seen[key] {
		return
	}
	seen[key] = true
	*edges = append(*edges, edge)
}

func branchKind(mnemonic string) string {
	mnemonic = strings.ToLower(mnemonic)
	switch {
	case mnemonic == "jmp" || mnemonic == "jmpq" || mnemonic == "ljmp":
		return "jump"
	case (strings.HasPrefix(mnemonic, "j") && mnemonic != "jmp") || strings.HasPrefix(mnemonic, "loop"):
		return "taken"
	case strings.HasPrefix(mnemonic, "ret") || strings.HasPrefix(mnemonic, "iret"):
		return "return"
	case mnemonic == "ud2" || mnemonic == "hlt" || mnemonic == "int3":
		return "trap"
	default:
		return ""
	}
}

func directTarget(operands string) (uint64, bool) {
	first := strings.TrimSpace(strings.SplitN(operands, ",", 2)[0])
	if !strings.HasPrefix(first, "0x") {
		return 0, false
	}
	end := len(first)
	for index := 2; index < len(first); index++ {
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(first[index])) {
			end = index
			break
		}
	}
	address, err := strconv.ParseUint(first[2:end], 16, 64)
	return address, err == nil
}

func parseAddress(value string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x"), 16, 64)
}

func formatAddress(address uint64) string {
	return fmt.Sprintf("0x%x", address)
}
