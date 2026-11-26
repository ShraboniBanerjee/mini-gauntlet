import type { FindingStatus, ScanStatus, Severity } from "../api/types";
import { FINDING_STATUS_LABEL, SCAN_STATUS_LABEL, SEVERITY_LABEL } from "../lib/format";

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className={`badge finding-${status.toLowerCase().replace("_", "-")}`}>
      {FINDING_STATUS_LABEL[status]}
    </span>
  );
}

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span className={`badge scan-${status.toLowerCase()}`}>
      {status === "RUNNING" && <span className="pulse" aria-hidden="true" />}
      {SCAN_STATUS_LABEL[status]}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className="severity">
      <span className={`swatch sev-${severity.toLowerCase()}`} aria-hidden="true" />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}
