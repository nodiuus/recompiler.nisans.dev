export interface AnalyzedFunction {
  id: string;
  name: string;
  decoratedName?: string;
  address: string;
  rva: string;
  size: number;
  section: string;
  module?: string;
  visibility: "local" | "global" | "public";
  source?: "pdb" | "unwind" | "export" | "coff" | "entry";
}

export interface AnalysisResult {
  cacheId?: string;
  binary: {
    machine: string;
    imageBase: string;
    pdbPath: string;
    guid: string;
    age: number;
    hasPdb: boolean;
    symbols: string;
  };
  functions: AnalyzedFunction[];
}

export interface DisassembledInstruction {
  address: string;
  offset: number;
  bytes: string;
  mnemonic: string;
  operands?: string;
  blockId: string;
}

export interface BasicBlock {
  id: string;
  startAddress: string;
  endAddress: string;
  instructionStart: number;
  instructionEnd: number;
  reachable: boolean;
  terminal?: string;
}

export interface ControlFlowEdge {
  from: string;
  to?: string;
  type: "fallthrough" | "taken" | "jump";
  targetAddress?: string;
  external?: boolean;
}

export interface DisassemblyResult {
  functionName: string;
  address: string;
  endAddress: string;
  boundary: string;
  truncated: boolean;
  instructions: DisassembledInstruction[];
  blocks: BasicBlock[];
  edges: ControlFlowEdge[];
}

export type TransformationPass =
  | "mutate"
  | "opaque-predicates"
  | "dead-code"
  | "nop-sled"
  | "deobfuscate";
