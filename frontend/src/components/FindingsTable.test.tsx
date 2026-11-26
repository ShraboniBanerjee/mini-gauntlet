import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { collectionFinding, scanDetail, xssFinding } from "../test/fixtures";
import { FindingsTable } from "./FindingsTable";

describe("FindingsTable", () => {
  it("renders untrusted strings as text, never as HTML", () => {
    const { container } = render(
      <FindingsTable findings={[xssFinding]} accounts={scanDetail.accounts} />,
    );

    expect(container.querySelector("img")).toBeNull();
    expect(
      screen.getByText("<img src=x onerror=alert('untrusted-input')> exposes RDP (3389)"),
    ).toBeInTheDocument();
    expect(screen.getByText("<img src=x onerror=alert('resource')>")).toBeInTheDocument();
  });

  it("shows status, severity, check, account name and cloud for each finding", () => {
    render(<FindingsTable findings={[xssFinding, collectionFinding]} accounts={scanDetail.accounts} />);
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);

    const first = within(rows[0]!);
    expect(first.getByText("Fail")).toBeInTheDocument();
    expect(first.getByText("Critical")).toBeInTheDocument();
    expect(first.getByText("GCP-VPC-01")).toBeInTheDocument();
    expect(first.getByText("Google Cloud")).toBeInTheDocument();

    const second = within(rows[1]!);
    expect(second.getByText("Cannot scan")).toBeInTheDocument();
    expect(second.getByText("Whole collection")).toBeInTheDocument();
    expect(second.getByText("example-corp-prod")).toBeInTheDocument();
  });
});
