export interface PESectionInfo {
  name: string;
  rva: number;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  characteristics: string;
}

export interface AnalysisResult {
  binaryId: string;
  filename: string;
  yaraMatched: boolean;
  matchedRules: string[];
  mlRiskScore: number;
  classification: string;
  machineType?: string;
  entryPoint?: number;
  imageBase?: number;
  subsystem?: string;
  sections?: PESectionInfo[];
  packed?: boolean;
}
