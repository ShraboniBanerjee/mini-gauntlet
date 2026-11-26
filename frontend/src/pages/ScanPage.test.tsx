import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import type { ScanDetail } from "../api/types";
import {
  collectionFinding,
  findingsPage,
  json,
  mockApi,
  scanDetail,
  xssFinding,
} from "../test/fixtures";
import { ScanPage } from "./ScanPage";

const SCAN_PATH = `/api/scans/${scanDetail.id}`;

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/scans/:scanId" element={<ScanPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ScanPage", () => {
  it("shows the score, counts, per-account scores and findings", async () => {
    const { fetchMock } = mockApi({
      [`GET ${SCAN_PATH}`]: () => json(scanDetail),
      [`GET ${SCAN_PATH}/findings`]: () => json(findingsPage([xssFinding, collectionFinding], 49)),
    });
    vi.stubGlobal("fetch", fetchMock);
    renderAt(`/scans/${scanDetail.id}`);

    const summary = await screen.findByRole("region", { name: "Scan summary" });
    expect(within(summary).getByText("60.0")).toBeInTheDocument();
    expect(within(summary).getByText("27 of 45 passed.", { exact: false })).toBeInTheDocument();
    expect(within(summary).getByRole("img")).toHaveAccessibleName(/49 findings: 7 failed, critical/);

    const accounts = screen.getByRole("heading", { name: "Accounts" }).closest("section")!;
    const gcpRow = within(accounts).getByText("example-corp-gcp", { selector: "span:not(.code)" }).closest("tr")!;
    expect(within(gcpRow).getByText("N/A")).toBeInTheDocument();
    expect(within(accounts).getByText("58.3")).toBeInTheDocument();

    expect(await screen.findByText("Showing 1–25 of 49")).toBeInTheDocument();
    expect(screen.getByText("Whole collection")).toBeInTheDocument();
  });

  it("sends filters to the API and starts again from page 1", async () => {
    const { fetchMock, calls } = mockApi({
      [`GET ${SCAN_PATH}`]: () => json(scanDetail),
      [`GET ${SCAN_PATH}/findings`]: () => json(findingsPage([xssFinding], 30)),
    });
    vi.stubGlobal("fetch", fetchMock);
    renderAt(`/scans/${scanDetail.id}?page=2`);
    expect(await screen.findByText("Showing 26–30 of 30")).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Status"), "FAIL");
    await userEvent.selectOptions(screen.getByLabelText("Cloud"), "gcp");

    const last = new URL(calls.at(-1)!.url, "http://localhost");
    expect(last.searchParams.get("status")).toBe("FAIL");
    expect(last.searchParams.get("provider")).toBe("gcp");
    expect(last.searchParams.get("page")).toBe("1");
    expect(last.searchParams.get("page_size")).toBe("25");
  });

  it("jumps back to the last page when the page number is past the end", async () => {
    const { fetchMock, calls } = mockApi({
      [`GET ${SCAN_PATH}`]: () => json(scanDetail),
      [`GET ${SCAN_PATH}/findings`]: () => {
        const page = new URL(calls.at(-1)!.url, "http://localhost").searchParams.get("page");
        return json(page === "9" ? { ...findingsPage([], 30), page: 9 } : findingsPage([xssFinding], 30));
      },
    });
    vi.stubGlobal("fetch", fetchMock);
    renderAt(`/scans/${scanDetail.id}?page=9`);

    expect(await screen.findByText("Showing 26–30 of 30")).toBeInTheDocument();
    expect(calls.at(-1)!.url).toContain("page=2");
  });

  it("shows why a scan failed", async () => {
    const failed: ScanDetail = {
      ...scanDetail,
      status: "FAILED",
      score: null,
      error: "Inventory file not found: /inventory/inventory.json",
    };
    const { fetchMock } = mockApi({ [`GET ${SCAN_PATH}`]: () => json(failed) });
    vi.stubGlobal("fetch", fetchMock);
    renderAt(`/scans/${scanDetail.id}`);

    expect(await screen.findByText(/Inventory file not found/)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Scan summary" })).toBeNull();
  });

  it("says when a scan doesn't exist", async () => {
    const { fetchMock } = mockApi({});
    vi.stubGlobal("fetch", fetchMock);
    renderAt("/scans/missing");

    expect(await screen.findByText("This scan doesn't exist")).toBeInTheDocument();
  });
});
