import { afterEach, describe, expect, it, vi } from "vitest";

import { reportUnexpected } from "../../src/background/report";

const SECRET = "hunter2-Moth-Secret";

const logged = (error: unknown): string => {
  const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  reportUnexpected(error);
  expect(spy).toHaveBeenCalledOnce();
  return JSON.stringify(spy.mock.calls[0]);
};

describe("unexpected errors", () => {
  afterEach(() => vi.restoreAllMocks());

  it("logs the type and code locations, never the message", () => {
    let error: unknown;
    try {
      JSON.parse(`{"password": "${SECRET}"`);
    } catch (caught) {
      error = caught;
    }
    const line = logged(error);
    expect(line).toContain("SyntaxError");
    expect(line).toMatch(/report\.test\.ts:\d+:\d+/);
    expect(line).not.toContain(SECRET);
  });

  it("keeps Firefox-style frames and drops the message line", () => {
    const error = new TypeError(`bad ${SECRET} @ value`);
    error.stack = `handle@moz-extension://x/background.js:10:5\n${SECRET}@evil\nrun@moz-extension://x/background.js:20:1`;
    const line = logged(error);
    expect(line).toContain("handle@moz-extension://x/background.js:10:5");
    expect(line).toContain("run@moz-extension://x/background.js:20:1");
    expect(line).not.toContain(SECRET);
  });

  it("names a thrown value that is not an Error by its type only", () => {
    const line = logged(SECRET);
    expect(line).toContain("unexpected string");
    expect(line).not.toContain(SECRET);
  });
});
