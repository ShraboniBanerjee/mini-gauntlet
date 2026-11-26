import { useCallback, useEffect } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { ApiError, getScan, listFindings } from "../api/client";
import {
  FINDING_STATUSES,
  SEVERITIES,
  type FindingsPage,
  type ScanDetail,
} from "../api/types";
import { ScanStatusBadge } from "../components/Badges";
import { FindingsStrip } from "../components/FindingsStrip";
import { FindingsTable } from "../components/FindingsTable";
import { Pagination } from "../components/Pagination";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/States";
import {
  FINDING_STATUS_LABEL,
  SEVERITY_LABEL,
  formatDateTime,
  formatDuration,
  formatScore,
  providerLabel,
  shortId,
} from "../lib/format";
import { usePolledResource } from "../lib/usePolledResource";

const PAGE_SIZE = 25;
const FILTER_KEYS = ["status", "severity", "provider", "account"] as const;

function isRunning(scan: ScanDetail): boolean {
  return scan.status === "RUNNING";
}

function never(): boolean {
  return false;
}

export function ScanPage() {
  const { scanId = "" } = useParams();
  const load = useCallback((signal: AbortSignal) => getScan(scanId, signal), [scanId]);
  const scan = usePolledResource(load, isRunning);

  if (scan.data === undefined || scan.data.id !== scanId) {
    if (scan.error instanceof ApiError && scan.error.status === 404) {
      return (
        <EmptyState title="This scan doesn't exist">
          <p>
            It may have been deleted with the database. <Link to="/">Go to all scans</Link>
          </p>
        </EmptyState>
      );
    }
    if (scan.error) {
      return <ErrorState title="Can't load this scan" message={scan.error.message} onRetry={scan.reload} />;
    }
    return <LoadingState label="Loading scan" />;
  }

  const data = scan.data;
  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/">Scans</Link>
        <span aria-hidden="true">/</span>
        <span className="code">{shortId(data.id)}</span>
      </nav>

      <div className="page-head">
        <div>
          <h1>
            Scan <span className="code">{shortId(data.id)}</span>
          </h1>
          <dl className="meta">
            <div>
              <dt>Status</dt>
              <dd>
                <ScanStatusBadge status={data.status} />
              </dd>
            </div>
            <div>
              <dt>Started</dt>
              <dd>
                <time dateTime={data.started_at}>{formatDateTime(data.started_at)}</time>
              </dd>
            </div>
            <div>
              <dt>Duration</dt>
              <dd>{formatDuration(data.started_at, data.finished_at)}</dd>
            </div>
          </dl>
        </div>
      </div>

      {scan.error && (
        <Notice tone="error" title="Updates paused">
          {scan.error.message} Retrying automatically.
        </Notice>
      )}
      {data.status === "RUNNING" && (
        <Notice tone="info">This scan is still running. The page updates by itself.</Notice>
      )}
      {data.status === "FAILED" && (
        <Notice tone="error" title="The scan failed">
          {data.error ?? "No reason was recorded."}
        </Notice>
      )}
      {data.status === "COMPLETED" && (
        <>
          <Summary scan={data} />
          <AccountsTable scan={data} />
          <FindingsSection scan={data} />
        </>
      )}
    </>
  );
}

function Summary({ scan }: { scan: ScanDetail }) {
  const scored = scan.counts.PASS + scan.counts.FAIL;
  return (
    <section className="summary" aria-label="Scan summary">
      <div className="summary-top">
        <div className="score">
          <span className="score-value">{formatScore(scan.score)}</span>
          <span className="score-label">Posture score</span>
          <span className="score-note">
            {scored === 0
              ? "No finding passed or failed, so there is nothing to score."
              : `${scan.counts.PASS} of ${scored} passed. Findings that couldn't be scanned don't count.`}
          </span>
        </div>
        <dl className="tallies">
          <div className="tally-group">
            <dt>By status</dt>
            {FINDING_STATUSES.map((status) => (
              <dd key={status} className={`tally finding-${status.toLowerCase().replace("_", "-")}`}>
                <span className="tally-value">{scan.counts[status]}</span>
                <span className="tally-label">{FINDING_STATUS_LABEL[status]}</span>
              </dd>
            ))}
          </div>
          <div className="tally-group">
            <dt>Failures by severity</dt>
            {SEVERITIES.map((severity) => (
              <dd key={severity} className="tally">
                <span className="tally-value">{scan.fail_counts_by_severity[severity]}</span>
                <span className="tally-label">
                  <span className={`swatch sev-${severity.toLowerCase()}`} aria-hidden="true" />
                  {SEVERITY_LABEL[severity]}
                </span>
              </dd>
            ))}
          </div>
        </dl>
      </div>
      <FindingsStrip scan={scan} />
    </section>
  );
}

function AccountsTable({ scan }: { scan: ScanDetail }) {
  return (
    <section className="section">
      <h2>Accounts</h2>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Account</th>
              <th scope="col">Cloud</th>
              <th scope="col" className="num">Score</th>
              <th scope="col" className="num">Fail</th>
              <th scope="col" className="num">Cannot scan</th>
              <th scope="col" className="num">Pass</th>
            </tr>
          </thead>
          <tbody>
            {scan.accounts.map((account) => (
              <tr key={account.account_id}>
                <td className="wrap">
                  <span>{account.name ?? account.account_id}</span>
                  <span className="sub code">{account.account_id}</span>
                </td>
                <td>{providerLabel(account.provider)}</td>
                <td className="num score-cell">{formatScore(account.score)}</td>
                <td className="num">{account.counts.FAIL}</td>
                <td className="num">{account.counts.CANNOT_SCAN}</td>
                <td className="num">{account.counts.PASS}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function FindingsSection({ scan }: { scan: ScanDetail }) {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const severity = params.get("severity") ?? "";
  const provider = params.get("provider") ?? "";
  const account = params.get("account") ?? "";
  const page = Math.max(1, Number.parseInt(params.get("page") ?? "1", 10) || 1);

  const load = useCallback(
    (signal: AbortSignal) =>
      listFindings(
        scan.id,
        { status, severity, provider, account_id: account, page, page_size: PAGE_SIZE },
        signal,
      ),
    [scan.id, status, severity, provider, account, page],
  );
  const findings = usePolledResource<FindingsPage>(load, never);

  const providers = [...new Set(scan.accounts.map((item) => item.provider))];
  const filtering = FILTER_KEYS.some((key) => params.get(key));

  const update = (changes: Record<string, string | number>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value === "" || value === 1) next.delete(key);
      else next.set(key, String(value));
    }
    setParams(next, { replace: true });
  };
  // Any filter change goes back to the first page.
  const setFilter = (key: string, value: string) => update({ [key]: value, page: 1 });

  // A bookmarked or stale page number past the end jumps back to the last real page.
  const lastPage = findings.data ? Math.max(1, Math.ceil(findings.data.total / PAGE_SIZE)) : 1;
  useEffect(() => {
    if (findings.data && page > lastPage) {
      const next = new URLSearchParams(params);
      if (lastPage === 1) next.delete("page");
      else next.set("page", String(lastPage));
      setParams(next, { replace: true });
    }
  }, [findings.data, page, lastPage, params, setParams]);

  return (
    <section className="section">
      <h2>Findings</h2>
      <div className="filters">
        <label>
          Status
          <select value={status} onChange={(event) => setFilter("status", event.target.value)}>
            <option value="">All statuses</option>
            {FINDING_STATUSES.map((value) => (
              <option key={value} value={value}>
                {FINDING_STATUS_LABEL[value]}
              </option>
            ))}
          </select>
        </label>
        <label>
          Severity
          <select value={severity} onChange={(event) => setFilter("severity", event.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {SEVERITY_LABEL[value]}
              </option>
            ))}
          </select>
        </label>
        <label>
          Cloud
          <select value={provider} onChange={(event) => setFilter("provider", event.target.value)}>
            <option value="">All clouds</option>
            {providers.map((value) => (
              <option key={value} value={value}>
                {providerLabel(value)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Account
          <select value={account} onChange={(event) => setFilter("account", event.target.value)}>
            <option value="">All accounts</option>
            {scan.accounts.map((item) => (
              <option key={item.account_id} value={item.account_id}>
                {item.name ?? item.account_id}
              </option>
            ))}
          </select>
        </label>
        {filtering && (
          <button
            type="button"
            className="button quiet"
            onClick={() => setParams(new URLSearchParams(), { replace: true })}
          >
            Clear filters
          </button>
        )}
      </div>

      {findings.data === undefined ? (
        findings.error ? (
          <ErrorState
            title="Can't load findings"
            message={findings.error.message}
            onRetry={findings.reload}
          />
        ) : (
          <LoadingState label="Loading findings" />
        )
      ) : findings.data.total === 0 ? (
        <EmptyState title="No findings match these filters">
          <p>Change or clear the filters to see more.</p>
        </EmptyState>
      ) : (
        <div className={findings.loading ? "is-refreshing" : undefined} aria-busy={findings.loading}>
          {findings.error && (
            <Notice tone="error" title="Can't load this page">
              {findings.error.message}
            </Notice>
          )}
          <FindingsTable findings={findings.data.items} accounts={scan.accounts} />
          <Pagination
            page={page}
            pageSize={PAGE_SIZE}
            total={findings.data.total}
            onPageChange={(next) => update({ page: next })}
          />
        </div>
      )}
    </section>
  );
}
