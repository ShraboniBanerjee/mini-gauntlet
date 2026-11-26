import { describe, expect, it } from "vitest";

import { formatDuration, formatScore, providerLabel } from "./format";

describe("format", () => {
  it("shows N/A for a null score and one decimal otherwise", () => {
    expect(formatScore(null)).toBe("N/A");
    expect(formatScore(60)).toBe("60.0");
    expect(formatScore(58.3)).toBe("58.3");
  });

  it("formats durations", () => {
    expect(formatDuration("2026-11-26T10:00:00Z", "2026-11-26T10:00:03.05Z")).toBe("3.0 s");
    expect(formatDuration("2026-11-26T10:00:00Z", "2026-11-26T10:01:05Z")).toBe("1 min 5 s");
    const now = Date.parse("2026-11-26T10:00:02Z");
    expect(formatDuration("2026-11-26T10:00:00Z", null, now)).toBe("2.0 s");
  });

  it("names known clouds and passes unknown ones through as text", () => {
    expect(providerLabel("gcp")).toBe("Google Cloud");
    expect(providerLabel("oracle")).toBe("oracle");
  });
});
