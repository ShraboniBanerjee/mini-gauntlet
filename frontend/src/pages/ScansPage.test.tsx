import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { completedScan, json, mockApi, runningScan } from "../test/fixtures";
import { ScansPage } from "./ScansPage";

function renderPage() {
  return render(
    <MemoryRouter>
      <ScansPage />
    </MemoryRouter>,
  );
}

describe("ScansPage", () => {
  it("explains the problem when the API is down", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    renderPage();

    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("Can't load scans")).toBeInTheDocument();
    expect(within(alert).getByText(/Can't reach the API/)).toBeInTheDocument();
    expect(within(alert).getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("explains a gateway error from the proxy", async () => {
    const { fetchMock } = mockApi({ "GET /api/scans": () => new Response("Bad Gateway", { status: 502 }) });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(await screen.findByText(/The API is unavailable \(HTTP 502\)/)).toBeInTheDocument();
  });

  it("invites the first scan when there are none", async () => {
    const { fetchMock } = mockApi({ "GET /api/scans": () => json([]) });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    expect(await screen.findByText("No scans yet")).toBeInTheDocument();
  });

  it("lists scans with status, score and counts", async () => {
    const { fetchMock } = mockApi({ "GET /api/scans": () => json([completedScan]) });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();

    const row = (await screen.findByRole("link", { name: "22222222" })).closest("tr")!;
    expect(within(row).getByText("Completed")).toBeInTheDocument();
    expect(within(row).getByText("60.0")).toBeInTheDocument();
    expect(within(row).getByText("18 failed")).toBeInTheDocument();
    expect(within(row).getByText("3.1 s")).toBeInTheDocument();
    expect(within(row).getByText("2 accounts")).toBeInTheDocument();
  });

  it("starts a scan and shows it running with an N/A score", async () => {
    let scans = [completedScan];
    const { fetchMock, calls } = mockApi({
      "GET /api/scans": () => json(scans),
      "POST /api/scans": () => {
        scans = [runningScan, completedScan];
        return json(runningScan, 202);
      },
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await screen.findByText("Completed");

    await userEvent.click(screen.getByRole("button", { name: "Run scan" }));

    const row = (await screen.findByText("Running")).closest("tr")!;
    expect(within(row).getByText("N/A")).toBeInTheDocument();
    expect(within(row).getByText("All accounts")).toBeInTheDocument();
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(1);
  });

  it("shows why a scan couldn't start", async () => {
    const { fetchMock } = mockApi({
      "GET /api/scans": () => json([]),
      "POST /api/scans": () =>
        json({ detail: [{ loc: ["body", "account_ids"], msg: "Unknown account IDs: x" }] }, 422),
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await screen.findByText("No scans yet");

    await userEvent.click(screen.getByRole("button", { name: "Run scan" }));

    expect(await screen.findByText("Unknown account IDs: x")).toBeInTheDocument();
  });
});
