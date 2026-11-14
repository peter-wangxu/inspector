/**
 * Add per-server routing headers to OAuth fetches, not to browser navigation.
 * MCP headers are inherited only at the configured server's origin. Sending
 * headers to an external authorization server requires explicit oauth.headers.
 * OAuth's own credentials and protocol headers always win.
 */
import {
  requestHeadersOf,
  requestUrlOf,
  deadlineForRequestInit,
  stampRequestDeadline,
} from "./requestTimeout.js";
import type { InspectorServerSettings } from "../mcp/types.js";

type HeaderSettings = Pick<InspectorServerSettings, "headers" | "oauthHeaders">;
const RESERVED =
  /^(authorization|proxy-authorization|cookie|host|content-type|content-length|accept|connection|mcp-.*|x-mcp-remote-auth)$/i;

/** Drop malformed hand-edited config, but retain blank rows in the UI itself. */
export function cleanOAuthHeaders(
  value: unknown,
): Record<string, string> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return undefined;
  const headers = new Map<string, string>();
  for (const [key, item] of Object.entries(value)) {
    const name = key.trim().toLowerCase();
    if (
      typeof item !== "string" ||
      !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) ||
      RESERVED.test(name)
    )
      continue;
    // Fetch permits HTAB, visible ASCII and obs-text, but not CR/LF or Unicode.
    const text = item.trim();
    if (
      [...text].some(
        (char) =>
          char !== "\t" &&
          (char.charCodeAt(0) < 32 ||
            char.charCodeAt(0) === 127 ||
            char.charCodeAt(0) > 255),
      )
    )
      continue;
    headers.set(name, text);
  }
  return headers.size ? Object.fromEntries(headers) : undefined;
}

function rowsToHeaders(rows: { key: string; value: string }[] | undefined) {
  return cleanOAuthHeaders(
    Object.fromEntries((rows ?? []).map(({ key, value }) => [key, value])),
  );
}

export function withOAuthHeaders(
  fetchFn: typeof fetch,
  getSettings: () => HeaderSettings | undefined,
  getServerUrl: () => string | undefined,
): typeof fetch {
  return (input, init) => {
    const settings = getSettings();
    if (!settings) return fetchFn(input, init);
    const serverUrl = getServerUrl();
    const sameOrigin =
      serverUrl !== undefined &&
      new URL(requestUrlOf(input)).origin === new URL(serverUrl).origin;
    const custom = {
      ...(sameOrigin ? rowsToHeaders(settings.headers) : undefined),
      ...rowsToHeaders(settings.oauthHeaders),
    };
    const headers = requestHeadersOf(input, init);
    for (const [key, value] of Object.entries(custom)) {
      if (!headers.has(key)) headers.set(key, value);
    }
    const nextInit = { ...init, headers };
    const deadline = deadlineForRequestInit(init);
    if (deadline !== undefined) stampRequestDeadline(nextInit, deadline);
    return fetchFn(input, nextInit);
  };
}
