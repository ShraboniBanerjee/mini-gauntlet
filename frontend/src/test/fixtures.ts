import type { Finding, FindingsPage, ScanDetail, ScanSummary } from "../api/types";

export const runningScan: ScanSummary = {
  id: "11111111-aaaa-bbbb-cccc-000000000001",
  status: "RUNNING",
  started_at: "2026-11-26T10:00:00.000Z",
  finished_at: null,
  account_ids: null,
  score: null,
  counts: { PASS: 0, FAIL: 0, CANNOT_SCAN: 0 },
  error: null,
};

export const completedScan: ScanSummary = {
  ...runningScan,
  id: "22222222-aaaa-bbbb-cccc-000000000002",
  status: "COMPLETED",
  finished_at: "2026-11-26T10:00:03.100Z",
  account_ids: ["123456789012", "example-corp-gcp"],
  score: 60,
  counts: { PASS: 27, FAIL: 18, CANNOT_SCAN: 4 },
};

export const scanDetail: ScanDetail = {
  ...completedScan,
  fail_counts_by_severity: { CRITICAL: 7, HIGH: 8, MEDIUM: 2, LOW: 1 },
  accounts: [
    {
      account_id: "123456789012",
      provider: "aws",
      name: "example-corp-prod",
      score: 58.3,
      counts: { PASS: 14, FAIL: 10, CANNOT_SCAN: 0 },
    },
    {
      account_id: "example-corp-gcp",
      provider: "gcp",
      name: "example-corp-gcp",
      score: null,
      counts: { PASS: 0, FAIL: 0, CANNOT_SCAN: 2 },
    },
  ],
};

export const xssFinding: Finding = {
  id: 1,
  scan_id: completedScan.id,
  check_id: "GCP-VPC-01",
  title: "Firewall rule doesn't expose SSH or RDP to the internet",
  provider: "gcp",
  account_id: "example-corp-gcp",
  region: "global",
  resource_id: "<img src=x onerror=alert('resource')>",
  status: "FAIL",
  severity: "CRITICAL",
  details: "<img src=x onerror=alert('untrusted-input')> exposes RDP (3389)",
};

export const collectionFinding: Finding = {
  ...xssFinding,
  id: 2,
  check_id: "AWS-IAM-01",
  provider: "aws",
  account_id: "123456789012",
  region: null,
  resource_id: null,
  status: "CANNOT_SCAN",
  severity: "HIGH",
  details: "Could not read iam_users: AccessDenied",
};

export function findingsPage(items: Finding[], total = items.length): FindingsPage {
  return { items, total, page: 1, page_size: 25 };
}

/** A fetch mock that answers by method and path, and records every call. */
export function mockApi(routes: Record<string, (init?: RequestInit) => Response | Promise<Response>>) {
  const calls: { method: string; url: string; body?: BodyInit | null }[] = [];
  const fetchMock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method ?? "GET";
    calls.push({ method, url, body: init?.body });
    const path = url.split("?")[0] ?? url;
    const handler = routes[`${method} ${path}`];
    if (!handler) return json({ detail: "Not found" }, 404);
    return handler(init);
  };
  return { fetchMock, calls };
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
