import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./api";

afterEach(() => vi.unstubAllGlobals());
describe("authenticated API client", () => {
  it("forwards only the explicit in-memory credential and disables caching", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ id: "scan" }), { status: 202 }),
      );
    vi.stubGlobal("fetch", fetchMock);
    expect(
      await api("ephemeral", "/v1/repositories/repo/scans", {
        sha: "a".repeat(40),
      }),
    ).toEqual({ id: "scan" });
    const [path, request] = fetchMock.mock.calls[0];
    expect(path).toBe("/api/bridge/v1/repositories/repo/scans");
    expect(request.cache).toBe("no-store");
    expect(request.headers.Authorization).toBe("Bearer ephemeral");
    expect(request.method).toBe("POST");
  });
  it("preserves permission failures for the error state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "invalid credential" }), {
          status: 401,
        }),
      ),
    );
    await expect(api("revoked", "/v1/repositories")).rejects.toEqual(
      new ApiError(401, "invalid credential"),
    );
  });
  it("does not expose structured validation payloads as raw UI errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: [{ input: "sensitive" }] }), {
          status: 422,
        }),
      ),
    );
    await expect(api("token", "/v1/repositories", {})).rejects.toThrow(
      "Check access and input",
    );
  });
});
