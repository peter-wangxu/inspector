/** Exercise both OAuthManager and transport-internal SDK OAuth fetch wiring. */
import { describe, expect, it, vi } from "vitest";
import { InspectorClient } from "@inspector/core/mcp/inspectorClient.js";
import { BrowserOAuthStorage } from "@inspector/core/auth/browser/storage.js";
import {
  mcpConfigToServerEntries,
  inspectorSettingsToStoredFields,
} from "@inspector/core/mcp/serverList.js";
import type { CreateTransportOptions } from "@inspector/core/mcp/types.js";
import type { Transport, JSONRPCMessage } from "@modelcontextprotocol/client";

class InertTransport implements Transport {
  onmessage?: (message: JSONRPCMessage) => void;
  async start(): Promise<void> {}
  async send(): Promise<void> {
    throw new Error("not connected");
  }
  async close(): Promise<void> {}
}

describe("Inspector OAuth headers", () => {
  it("round-trips OAuth headers through the server catalog", () => {
    const [entry] = mcpConfigToServerEntries({
      mcpServers: {
        test: {
          type: "streamable-http",
          url: "https://mcp.test/mcp",
          oauth: { headers: { "X-TT-Env": "boe" } },
        },
      },
    });
    expect(entry.settings?.oauthHeaders).toEqual([
      { key: "x-tt-env", value: "boe" },
    ]);
    expect(
      inspectorSettingsToStoredFields(entry.settings!).oauth?.headers,
    ).toEqual({ "x-tt-env": "boe" });
  });

  it.each([false, true])(
    "covers discovery and DCR plus transport OAuth (separate base %s)",
    async (separate) => {
      sessionStorage.clear();
      localStorage.clear();
      const mcp = "https://mcp.test/mcp";
      const issuer = "https://as.test";
      const requests: { url: string; headers: Headers }[] = [];
      const base: typeof fetch = async (input, init) => {
        const url = input instanceof Request ? input.url : String(input);
        const headers = new Headers(init?.headers);
        requests.push({ url, headers });
        const json = url.includes("oauth-protected-resource")
          ? { resource: mcp, authorization_servers: [issuer] }
          : url.includes("oauth-authorization-server")
            ? {
                issuer,
                authorization_endpoint: `${issuer}/authorize`,
                token_endpoint: `${issuer}/token`,
                registration_endpoint: `${issuer}/register`,
                response_types_supported: ["code"],
                code_challenge_methods_supported: ["S256"],
              }
            : url.endsWith("/register")
              ? {
                  client_id: "test-client",
                  redirect_uris: ["http://localhost/callback"],
                }
              : { access_token: "token", token_type: "Bearer" };
        return new Response(JSON.stringify(json), {
          headers: { "content-type": "application/json" },
        });
      };
      const [entry] = mcpConfigToServerEntries({
        mcpServers: {
          test: {
            type: "streamable-http",
            url: mcp,
            headers: { "x-tt-env": "mcp-lane" },
            oauth: { headers: { "x-tt-env": "oauth-lane" } },
          },
        },
      });
      let captured: CreateTransportOptions | undefined;
      const navigate = vi.fn();
      const client = new InspectorClient(entry.config, {
        serverSettings: entry.settings,
        environment: {
          fetch: base,
          ...(separate ? { oauthFetch: base } : {}),
          transport: (_config, options) => {
            captured = options;
            return { transport: new InertTransport() };
          },
          oauth: {
            storage: new BrowserOAuthStorage(),
            navigation: { navigateToAuthorization: navigate },
            redirectUrlProvider: {
              getRedirectUrl: () => "http://localhost/callback",
            },
          },
        },
      });
      try {
        const authorizeUrl = await client.authenticate();
        expect(authorizeUrl?.pathname).toBe("/authorize");
        expect(requests.some(({ url }) => url.endsWith("/register"))).toBe(
          true,
        );
        for (const request of requests)
          expect(request.headers.get("x-tt-env")).toBe("oauth-lane");
        expect(requests.some(({ url }) => url.includes("/authorize"))).toBe(
          false,
        );
        await client.connect().catch(() => undefined);
        expect(captured?.fetchFn).toBeDefined();
        await captured!.fetchFn!(`${issuer}/token`, {
          method: "POST",
          body: new URLSearchParams({ grant_type: "refresh_token" }),
          headers: { "content-type": "application/x-www-form-urlencoded" },
        });
        expect(requests.at(-1)?.headers.get("x-tt-env")).toBe("oauth-lane");
      } finally {
        await client.disconnect();
      }
    },
  );
});
