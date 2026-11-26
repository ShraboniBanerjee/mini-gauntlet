import type { FindingsPage, FindingsQuery, ScanDetail, ScanSummary } from "./types";

// Empty by default: the dashboard calls /api on its own origin (nginx or the Vite proxy).
const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

export class ApiError extends Error {
  readonly status: number | null;

  constructor(message: string, status: number | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

/** Pull a readable message out of a FastAPI error body: a string or a list of {msg}. */
async function errorMessage(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    const detail = typeof body === "object" && body !== null ? (body as { detail?: unknown }).detail : undefined;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const messages = detail
        .map((item: unknown) =>
          typeof item === "object" && item !== null && typeof (item as { msg?: unknown }).msg === "string"
            ? (item as { msg: string }).msg
            : null,
        )
        .filter((message): message is string => message !== null);
      if (messages.length > 0) return messages.join("; ");
    }
  } catch {
    // Not JSON, e.g. a proxy's error page; fall through to a generic message.
  }
  if (response.status >= 500) {
    return `The API is unavailable (HTTP ${response.status}). Check that it's running.`;
  }
  return `The request failed (HTTP ${response.status}).`;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
    });
  } catch (error) {
    if (isAbort(error)) throw error;
    throw new ApiError("Can't reach the API. Check that it's running, then try again.", null);
  }
  if (!response.ok) {
    throw new ApiError(await errorMessage(response), response.status);
  }
  return (await response.json()) as T;
}

export function listScans(signal?: AbortSignal): Promise<ScanSummary[]> {
  return request<ScanSummary[]>("/api/scans", { signal });
}

export function getScan(scanId: string, signal?: AbortSignal): Promise<ScanDetail> {
  return request<ScanDetail>(`/api/scans/${encodeURIComponent(scanId)}`, { signal });
}

export function listFindings(
  scanId: string,
  query: FindingsQuery,
  signal?: AbortSignal,
): Promise<FindingsPage> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  return request<FindingsPage>(
    `/api/scans/${encodeURIComponent(scanId)}/findings?${params.toString()}`,
    { signal },
  );
}

export function startScan(accountIds?: string[]): Promise<ScanSummary> {
  return request<ScanSummary>("/api/scans", {
    method: "POST",
    body: accountIds ? JSON.stringify({ account_ids: accountIds }) : undefined,
  });
}
