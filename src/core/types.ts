/** Status of a piece of data, so every result says where it came from and how fresh it is. */
export type Status = 'LIVE' | 'CACHED' | 'UNAVAILABLE' | 'ERROR';

export interface Provenance {
  source: string;
  url: string;
  status: Status;
  /** ISO timestamp of when the underlying data was fetched. */
  fetchedAt: string;
  note?: string;
}

export interface Sourced<T> {
  data: T | null;
  prov: Provenance;
}

export interface Evidence {
  source: string;
  text: string;
  url?: string;
  value?: number;
}

export interface Signal {
  id: string;
  module: string;
  title: string;
  /** 0-100. */
  score: number;
  entity?: string;
  evidence: Evidence[];
  createdAt: string;
}

export interface ModuleResult<T> {
  module: string;
  input: string;
  generatedAt: string;
  result: T;
  signals: Signal[];
  provenance: Provenance[];
}
