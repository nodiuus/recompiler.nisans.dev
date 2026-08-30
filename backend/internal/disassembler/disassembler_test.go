package disassembler

import "testing"

func TestParseInstructionsAndBuildGraph(t *testing.T) {
	output := []byte(`
Disassembly of section .text:
140001000: 85 c0                         test eax, eax
140001002: 74 07                         je 0x14000100b <.text+0xb>
140001004: b8 01 00 00 00               mov eax, 0x1
140001009: eb 05                         jmp 0x140001010 <.text+0x10>
14000100b: 31 c0                         xor eax, eax
14000100d: 90                            nop
14000100e: 90                            nop
14000100f: 90                            nop
140001010: c3                            ret
`)
	instructions, err := parseInstructions(output, 0x140001000, 0x140001011)
	if err != nil {
		t.Fatal(err)
	}
	if len(instructions) != 9 {
		t.Fatalf("got %d instructions, want 9", len(instructions))
	}
	if instructions[1].Mnemonic != "je" || instructions[1].Operands != "0x14000100b <.text+0xb>" {
		t.Fatalf("unexpected branch: %+v", instructions[1])
	}

	blocks, edges := buildGraph(instructions)
	if len(blocks) != 4 {
		t.Fatalf("got %d blocks, want 4: %+v", len(blocks), blocks)
	}
	if len(edges) != 4 {
		t.Fatalf("got %d edges, want 4: %+v", len(edges), edges)
	}
	for _, block := range blocks {
		if !block.Reachable {
			t.Fatalf("expected block %s to be reachable", block.ID)
		}
	}
	if blocks[len(blocks)-1].Terminal != "return" {
		t.Fatalf("last block terminal = %q, want return", blocks[len(blocks)-1].Terminal)
	}
}

func TestDirectTargetRejectsIndirectOperand(t *testing.T) {
	if _, ok := directTarget("qword ptr [rip + 0x1234]"); ok {
		t.Fatal("indirect operand was treated as a direct target")
	}
	if target, ok := directTarget("0x140001000 <label>"); !ok || target != 0x140001000 {
		t.Fatalf("direct target = %#x, %v", target, ok)
	}
}

func TestTrimTrailingAlignmentAfterReturn(t *testing.T) {
	instructions := []Instruction{
		{Mnemonic: "mov"},
		{Mnemonic: "ret"},
		{Mnemonic: "int3"},
		{Mnemonic: "nop"},
	}
	if got := trimTrailingAlignment(instructions); len(got) != 2 {
		t.Fatalf("got %d instructions, want 2", len(got))
	}
}
