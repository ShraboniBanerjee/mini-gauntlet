import { useCallback, useState } from "react";
import { Link } from "react-router-dom";

import { listScans, startScan } from "../api/client";
import type { ScanSummary } from "../api/types";
import { ScanStatusBadge } from "../components/Badges";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/States";
import { formatDateTime, formatDuration, formatScore, messageOf, shortId } from "../lib/format";
import { usePolledResource } from "../lib/usePolledResource";

function anyRunning(scans: ScanSummary[]): boolean {
  return scans.some((scan) => scan.status === "RUNNING");
}

export function ScansPage() {
  const load = useCallback((signal: AbortSignal) => listScans(signal), []);
  const scans = usePolledResource(load, anyRunning);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string>();

  const runScan = async () => {
    setStarting(true);
    setStartError(undefined);
    try {
      await startScan();
      scans.reload();
    } catch (error) {
      setStartError(messageOf(error));
    } finally {
      setStarting(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Scans</h1>
          <p className="lede">
            A scan checks every account in the inventory snapshot against the check catalog.
          </p>
        </div>
        <button
          type="button"
          className="button primary"
          onClick={() => void runScan()}
          disabled={starting}
        >
          {starting ? "Starting scan…" : "Run scan"}
        </button>
      </div>

      {startError && <Notice tone="error" title="The scan didn't start">{startError}</Notice>}

      {scans.data === undefined ? (
        scans.error ? (
          <ErrorState
            title="Can't load scans"
            message={scans.error.message}
            onRetry={scans.reload}
          />
        ) : (
          <LoadingState label="Loading scans" />
        )
      ) : (
        <>
          {scans.error && (
            <Notice tone="error" title="Updates paused">
              {scans.error.message} Retrying automatically.
            </Notice>
          )}
          {scans.data.length === 0 ? (
            <EmptyState title="No scans yet">
              <p>Run a scan to check the inventory snapshot. Results appear here as it runs.</p>
            </EmptyState>
          ) : (
            <ScansTable scans={scans.data} />
          )}
        </>
      )}
    </>
  );
}

function ScansTable({ scans }: { scans: ScanSummary[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">Scan</th>
            <th scope="col">Status</th>
            <th scope="col">Started</th>
            <th scope="col">Duration</th>
            <th scope="col" className="num">
              Score
            </th>
            <th scope="col">Findings</th>
            <th scope="col">Accounts</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td>
                <Link to={`/scans/${encodeURIComponent(scan.id)}`} className="code">
                  {shortId(scan.id)}
                </Link>
              </td>
              <td>
                <ScanStatusBadge status={scan.status} />
              </td>
              <td>
                <time dateTime={scan.started_at}>{formatDateTime(scan.started_at)}</time>
              </td>
              <td>{formatDuration(scan.started_at, scan.finished_at)}</td>
              <td className="num score-cell">{formatScore(scan.score)}</td>
              <td>
                {scan.status === "COMPLETED" ? (
                  <span className="counts">
                    <span className="count-fail">{scan.counts.FAIL} failed</span>
                    <span className="count-cannot">{scan.counts.CANNOT_SCAN} cannot scan</span>
                    <span className="count-pass">{scan.counts.PASS} passed</span>
                  </span>
                ) : scan.status === "FAILED" ? (
                  <span className="muted">No results</span>
                ) : (
                  <span className="muted">Scanning</span>
                )}
              </td>
              <td>
                {scan.account_ids === null
                  ? "All accounts"
                  : `${scan.account_ids.length} ${scan.account_ids.length === 1 ? "account" : "accounts"}`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
