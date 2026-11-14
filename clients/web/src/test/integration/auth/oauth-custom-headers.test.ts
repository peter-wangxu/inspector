/** A real HTTP peer requires a routing header on OAuth and MCP requests. */
import { createServer } from "node:http";
import type { ServerResponse } from "node:http";
import { describe, expect, it } from "vitest";
import { InspectorClient } from "@inspector/core/mcp/inspectorClient.js";
import { createTransportNode } from "@inspector/core/mcp/node/transport.js";
import { createGuardedFetch } from "@inspector/core/mcp/node/fetchGuard.js";
import { OAuthStorageBase } from "@inspector/core/auth/oauth-storage.js";
import { OAuthMemoryStore } from "@inspector/core/auth/store.js";
import { mcpConfigToServerEntries } from "@inspector/core/mcp/serverList.js";

describe("OAuth and MCP routing headers on the wire", () => {
  it.each(["streamable-http", "sse"] as const)(
    "sends routing headers through discovery, DCR, code exchange, refresh and revocation (%s)",
    async (type) => {
      let base = "";
      let stream: ServerResponse | undefined;
      const requests: {
        path: string;
        env: string | string[] | undefined;
        authorization: string | undefined;
        body: string;
      }[] = [];
      const server = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (chunk: Buffer) => chunks.push(chunk));
        req.on("end", () => {
          const path = req.url ?? "";
          const body = Buffer.concat(chunks).toString();
          requests.push({
            path,
            body,
            env: req.headers["x-tt-env"],
            authorization: req.headers.authorization,
          });
          if (req.headers["x-tt-env"] !== "boe_test") {
            res.writeHead(400).end("missing routing header");
            return;
          }
          const json = (value: object) => {
            res
              .writeHead(200, { "content-type": "application/json" })
              .end(JSON.stringify(value));
          };
          if (path.includes("oauth-protected-resource")) {
            json({ resource: `${base}/mcp`, authorization_servers: [base] });
            return;
          }
          if (path.includes("oauth-authorization-server")) {
            json({
              issuer: base,
              authorization_endpoint: `${base}/authorize`,
              token_endpoint: `${base}/token`,
              registration_endpoint: `${base}/register`,
              revocation_endpoint: `${base}/revoke`,
              response_types_supported: ["code"],
              code_challenge_methods_supported: ["S256"],
              token_endpoint_auth_methods_supported: ["none"],
            });
            return;
          }
          if (path === "/register") {
            json({
              client_id: "test-client",
              redirect_uris: ["http://localhost/callback"],
            });
            return;
          }
          if (path === "/token") {
            json({
              access_token: "access-test",
              refresh_token: "refresh-test",
              token_type: "Bearer",
              expires_in: 3600,
            });
            return;
          }
          if (path === "/revoke") {
            res.writeHead(200).end();
            return;
          }
          if (req.method === "GET" && type === "sse" && path === "/mcp") {
            stream = res;
            res.writeHead(200, { "content-type": "text/event-stream" });
            res.write("event: endpoint\ndata: /messages\n\n");
            return;
          }
          if (req.method === "GET") {
            res.writeHead(405).end();
            return;
          }
          if (req.method === "DELETE") {
            res.writeHead(200).end();
            return;
          }
          const rpc = JSON.parse(body) as {
            id?: string | number;
            method: string;
            params?: { protocolVersion?: string };
          };
          if (rpc.id === undefined) {
            res.writeHead(202).end();
            return;
          }
          const result =
            rpc.method === "initialize"
              ? {
                  protocolVersion: rpc.params?.protocolVersion,
                  serverInfo: { name: "header-test", version: "1" },
                  capabilities: { tools: {} },
                }
              : { tools: [] };
          const message = { jsonrpc: "2.0", id: rpc.id, result };
          if (type === "sse") {
            stream?.write(
              `event: message\ndata: ${JSON.stringify(message)}\n\n`,
            );
            res.writeHead(202).end();
          } else json(message);
        });
      });
      await new Promise<void>((resolve) =>
        server.listen(0, "127.0.0.1", resolve),
      );
      const address = server.address();
      if (!address || typeof address === "string")
        throw new Error("No server address");
      base = `http://127.0.0.1:${address.port}`;
      const [entry] = mcpConfigToServerEntries({
        mcpServers: {
          test: {
            type,
            url: `${base}/mcp`,
            headers: { "x-tt-env": "boe_test" },
            oauth: { headers: { "x-tt-env": "boe_test" } },
          },
        },
      });
      const storage = new OAuthStorageBase(new OAuthMemoryStore(), {
        read: async () => null,
        write: async () => {},
      });
      const client = new InspectorClient(entry.config, {
        serverSettings: entry.settings,
        environment: {
          transport: createTransportNode,
          fetch: globalThis.fetch,
          oauthFetch: createGuardedFetch(),
          oauth: {
            storage,
            navigation: { navigateToAuthorization: () => {} },
            redirectUrlProvider: {
              getRedirectUrl: () => "http://localhost/callback",
            },
          },
        },
      });
      try {
        const url = await client.authenticate();
        expect(url?.pathname).toBe("/authorize");
        await client.completeOAuthFlow(
          "code-test",
          base,
          url!.searchParams.get("state")!,
        );
        // No browser navigation was simulated: code redemption is tested directly.
        expect(requests.find(({ path }) => path === "/token")?.body).toContain(
          "grant_type=authorization_code",
        );
        await client.connect();
        await client.listTools();
        expect(
          requests
            .filter(({ path }) => path === "/mcp" || path === "/messages")
            .every(
              ({ authorization }) => authorization === "Bearer access-test",
            ),
        ).toBe(true);
        await client.handleAuthChallenge({ reason: "unauthorized" });
        expect(
          requests.some(
            ({ path, body }) =>
              path === "/token" && body.includes("grant_type=refresh_token"),
          ),
        ).toBe(true);
        // Revocation consumes the legacy metadata cache, independently of SDK discovery state.
        await storage.saveServerMetadata(`${base}/mcp`, {
          issuer: base,
          authorization_endpoint: `${base}/authorize`,
          token_endpoint: `${base}/token`,
          revocation_endpoint: `${base}/revoke`,
          revocation_endpoint_auth_methods_supported: ["none"],
          response_types_supported: ["code"],
        });
        const revocation = await client.clearOAuthTokens({ revoke: true });
        expect(revocation).toMatchObject({ status: "revoked" });
        expect(requests.some(({ path }) => path === "/revoke")).toBe(true);
        expect(
          requests.some(({ path }) =>
            path.includes("oauth-protected-resource"),
          ),
        ).toBe(true);
        expect(requests.some(({ path }) => path === "/register")).toBe(true);
        expect(requests.every(({ env }) => env === "boe_test")).toBe(true);
      } finally {
        await client.disconnect();
        stream?.end();
        await new Promise<void>((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        );
      }
    },
  );
});
