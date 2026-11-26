export type ScanStatus = "RUNNING" | "COMPLETED" | "FAILED";
export type FindingStatus = "FAIL" | "CANNOT_SCAN" | "PASS";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

/** In the order the API sorts them. */
export const FINDING_STATUSES: readonly FindingStatus[] = ["FAIL", "CANNOT_SCAN", "PASS"];
export const SEVERITIES: readonly Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export type StatusCounts = Record<FindingStatus, number>;
export type SeverityCounts = Record<Severity, number>;

export interface ScanSummary {
  id: string;
  status: ScanStatus;
  started_at: string;
  finished_at: string | null;
  account_ids: string[] | null;
  score: number | null;
  counts: StatusCounts;
  error: string | null;
}

export interface AccountScore {
  account_id: string;
  provider: string;
  name: string | null;
  score: number | null;
  counts: StatusCounts;
}

export interface ScanDetail extends ScanSummary {
  fail_counts_by_severity: SeverityCounts;
  accounts: AccountScore[];
}

export interface Finding {
  id: number;
  scan_id: string;
  check_id: string;
  title: string;
  provider: string;
  account_id: string;
  region: string | null;
  resource_id: string | null;
  status: FindingStatus;
  severity: Severity;
  details: string;
}

export interface FindingsPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingsQuery {
  status?: string;
  severity?: string;
  provider?: string;
  account_id?: string;
  page: number;
  page_size: number;
}
