import type { FindingStatus, ScanStatus, Severity } from "../api/types";

export const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  FAIL: "Fail",
  CANNOT_SCAN: "Cannot scan",
  PASS: "Pass",
};

export const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  RUNNING: "Running",
  COMPLETED: "Completed",
  FAILED: "Failed",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

const PROVIDER_LABEL: Record<string, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "Google Cloud",
};

export function providerLabel(provider: string): string {
  return PROVIDER_LABEL[provider.toLowerCase()] ?? provider;
}

/** A null score means nothing was scored (PASS + FAIL is 0). */
export function formatScore(score: number | null): string {
  return score === null ? "N/A" : score.toFixed(1);
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  timeZoneName: "short",
});

/** A UTC timestamp from the API, shown in the viewer's own time zone. */
export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : dateTimeFormat.format(date);
}

export function formatDuration(startIso: string, endIso: string | null, now = Date.now()): string {
  const start = Date.parse(startIso);
  const end = endIso === null ? now : Date.parse(endIso);
  if (Number.isNaN(start) || Number.isNaN(end)) return "";
  const seconds = Math.max(0, (end - start) / 1000);
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ${Math.round(seconds % 60)} s`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
