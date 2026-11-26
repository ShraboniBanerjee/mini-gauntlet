import { SEVERITIES, type ScanDetail } from "../api/types";
import { SEVERITY_LABEL } from "../lib/format";

const MAX_MARKS = 400;

interface Segment {
  key: string;
  count: number;
  className: string;
  label: string;
}

/**
 * One mark per finding, in the findings table's order: failures from critical to low,
 * then findings that couldn't be scanned, then passes. Past MAX_MARKS findings the
 * marks merge into proportional segments.
 */
export function FindingsStrip({ scan }: { scan: ScanDetail }) {
  const segments: Segment[] = [
    ...SEVERITIES.map((severity) => ({
      key: severity,
      count: scan.fail_counts_by_severity[severity],
      className: `sev-${severity.toLowerCase()}`,
      label: `${scan.fail_counts_by_severity[severity]} failed, ${SEVERITY_LABEL[severity].toLowerCase()} severity`,
    })),
    {
      key: "cannot",
      count: scan.counts.CANNOT_SCAN,
      className: "cannot",
      label: `${scan.counts.CANNOT_SCAN} couldn't be scanned`,
    },
    { key: "pass", count: scan.counts.PASS, className: "pass", label: `${scan.counts.PASS} passed` },
  ].filter((segment) => segment.count > 0);

  const total = segments.reduce((sum, segment) => sum + segment.count, 0);
  if (total === 0) return null;
  const summary = `${total} findings: ${segments.map((segment) => segment.label).join(", ")}`;

  return (
    <figure className="strip-figure">
      <div className="strip" role="img" aria-label={summary}>
        {total <= MAX_MARKS
          ? segments.flatMap((segment) =>
              Array.from({ length: segment.count }, (_, index) => (
                <span key={`${segment.key}-${index}`} className={`mark ${segment.className}`} />
              )),
            )
          : segments.map((segment) => (
              <span
                key={segment.key}
                className={`mark ${segment.className}`}
                style={{ flexGrow: segment.count }}
              />
            ))}
      </div>
      <figcaption>Each mark is one finding, in the same order as the findings table.</figcaption>
    </figure>
  );
}
