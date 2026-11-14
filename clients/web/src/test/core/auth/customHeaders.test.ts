/** OAuth routing headers preserve protocol headers, input objects and deadlines. */
import { describe, expect, it, vi } from "vitest";
import {
  cleanOAuthHeaders,
  withOAuthHeaders,
} from "@inspector/core/auth/customHeaders.js";
import {
  deadlineForRequestInit,
  stampRequestDeadline,
} from "@inspector/core/auth/requestTimeout.js";

describe("OAuth custom headers", () => {
  it.each([
    undefined,
    null,
    [],
    "bad",
    42,
    {},
    { "": "blank", "x-env": 1 },
    {
      Authorization: "secret",
      Cookie: "secret",
      Accept: "bad",
      Host: "bad",
      "Content-Type": "bad",
      "MCP-Session-Id": "bad",
    },
  ])("drops invalid or reserved configuration %j", (value) => {
    expect(cleanOAuthHeaders(value)).toBeUndefined();
  });

  it("normalizes names and rejects invalid HTTP headers", () => {
    expect(
      cleanOAuthHeaders({
        " X-TT-Env ": " boe ",
        "bad name": "bad",
        "x-invalid": "a\r\nb",
      }),
    ).toEqual({ "x-tt-env": "boe" });
  });
  it("rejects controls and non-Latin1 values but accepts tabs and empty values", () => {
    expect(
      cleanOAuthHeaders({
        "x-control": "a\x00b",
        "x-del": "a\x7fb",
        "x-unicode": "☃",
        "x-tab": "a\tb",
        "x-empty": "",
        "x-latin": "é",
      }),
    ).toEqual({ "x-tab": "a\tb", "x-empty": "", "x-latin": "é" });
  });

  it("passes through without settings", async () => {
    const base = vi.fn<typeof fetch>().mockResolvedValue(new Response());
    const init = { method: "GET" };
    await withOAuthHeaders(
      base,
      () => undefined,
      () => undefined,
    )("https://mcp.test/meta", init);
    expect(base).toHaveBeenCalledWith("https://mcp.test/meta", init);
  });

  it.each([
    "https://mcp.test/.well-known/oauth-protected-resource",
    "https://mcp.test/register",
    "https://mcp.test/token",
    "https://mcp.test/revoke",
  ])(
    "inherits same-origin headers at %s without replacing OAuth credentials",
    async (url) => {
      const base = vi.fn<typeof fetch>().mockResolvedValue(new Response());
      const headers = new Headers({
        Authorization: "Basic sdk",
        "Content-Type": "application/x-www-form-urlencoded",
        "x-existing": "caller",
      });
      const signal = new AbortController().signal;
      const body = new URLSearchParams({ grant_type: "refresh_token" });
      const init = { headers, signal, body, method: "POST" };
      stampRequestDeadline(init, 1234);
      await withOAuthHeaders(
        base,
        () => ({
          headers: [
            { key: "x-tt-env", value: "boe" },
            { key: "Authorization", value: "Bearer mcp" },
            { key: "x-existing", value: "config" },
          ],
        }),
        () => "https://mcp.test/mcp",
      )(url, init);
      const sent = base.mock.calls[0][1]!;
      expect(new Headers(sent.headers).get("x-tt-env")).toBe("boe");
      expect(new Headers(sent.headers).get("authorization")).toBe("Basic sdk");
      expect(new Headers(sent.headers).get("x-existing")).toBe("caller");
      expect(new Headers(sent.headers).get("content-type")).toBe(
        "application/x-www-form-urlencoded",
      );
      expect(headers.has("x-tt-env")).toBe(false);
      expect(sent.signal).toBe(signal);
      expect(sent.body).toBe(body);
      expect(deadlineForRequestInit(sent)).toBe(1234);
    },
  );

  it("does not inherit MCP headers across origins or ports; explicit OAuth headers opt in", async () => {
    const base = vi.fn<typeof fetch>().mockResolvedValue(new Response());
    const settings = {
      headers: [{ key: "x-api-key", value: "mcp-secret" }],
      oauthHeaders: [{ key: "x-tt-env", value: "boe_oauth" }],
    };
    const wrapped = withOAuthHeaders(
      base,
      () => settings,
      () => "https://mcp.test/mcp",
    );
    for (const url of ["https://as.test/token", "https://mcp.test:444/token"]) {
      await wrapped(new Request(url, { headers: { "x-request": "original" } }));
      const headers = new Headers(base.mock.lastCall![1]!.headers);
      expect(headers.get("x-tt-env")).toBe("boe_oauth");
      expect(headers.get("x-api-key")).toBeNull();
      expect(headers.get("x-request")).toBe("original");
    }
  });

  it("explicit OAuth headers override inherited routing and work with no server URL", async () => {
    const base = vi.fn<typeof fetch>().mockResolvedValue(new Response());
    const settings = {
      headers: [{ key: "x-tt-env", value: "mcp" }],
      oauthHeaders: [{ key: "X-TT-Env", value: "oauth" }],
    };
    await withOAuthHeaders(
      base,
      () => settings,
      () => "https://mcp.test/mcp",
    )(new URL("https://mcp.test/token"));
    expect(new Headers(base.mock.lastCall![1]!.headers).get("x-tt-env")).toBe(
      "oauth",
    );
    await withOAuthHeaders(
      base,
      () => settings,
      () => undefined,
    )("https://as.test/token");
    expect(new Headers(base.mock.lastCall![1]!.headers).get("x-tt-env")).toBe(
      "oauth",
    );
  });
});
