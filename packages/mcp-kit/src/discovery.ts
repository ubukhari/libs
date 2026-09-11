/**
 * The documents an agent or a registry fetches before it decides whether to use you.
 *
 * Checked against the primary sources on 10 September 2026, because the summaries are wrong
 * about this in ways that matter. Two paths that get recommended everywhere are not served
 * here on purpose:
 *
 *   - `/.well-known/mcp.json` — no specification defines it. Six live examples were compared
 *     and no two share a schema (`servers[]`, `mcpServers{}`, `{name,description,endpoint}`,
 *     a registry `server.json`, …). A client that guesses wrong attempts a connection and
 *     fails, rather than skipping gracefully, so publishing a seventh shape is worse than
 *     publishing nothing.
 *   - `/.well-known/mcp/server-card.json` — the MCP extension's own discovery document lists
 *     this under "alternatives considered, not recommended". A server card is application
 *     metadata, not site metadata, so it belongs at the MCP endpoint. `serverCardResponse`
 *     serves it at `<mcp-url>/server-card`, which is the reserved location GitHub and
 *     Hugging Face already use in production.
 *
 * Nothing here is invented. `ai-catalog.json` follows the AI Catalog specification, which is
 * what GitHub, Vercel, Hugging Face, Supabase, Apify and Zapier serve today and what
 * Hugging Face's `hf discover` reads. `security.txt` is RFC 9116. The server card follows the
 * MCP `ext-server-card` schema, which is still experimental and may change — the shape is
 * additive and inert, so a client that does not know it ignores it.
 *
 * One failure mode is worth more than the rest: **a 200 with the wrong body is worse than a
 * 404.** A framework catch-all that answers every unknown path with an HTML page will serve
 * HTML at `/.well-known/anything`, and a crawler trusting the status code parses it as JSON.
 * Every helper here returns an explicit content type, and anything not served must genuinely
 * 404.
 */

/** RFC 9116 §2.5.3: `Expires` should be under a year out, and a stale file is worse than none. */
export interface SecurityTxtOptions {
  /** at least one; mailto: or https: */
  contact: string[];
  /** ISO 8601 instant this file stops being trustworthy */
  expires: string;
  policyUrl?: string;
  acknowledgmentsUrl?: string;
  preferredLanguages?: string;
  /** where this file canonically lives; helps a reader spot a copy served from elsewhere */
  canonicalUrl?: string;
}

export function securityTxt(options: SecurityTxtOptions): string {
  const lines: string[] = [];
  for (const contact of options.contact) lines.push(`Contact: ${contact}`);
  lines.push(`Expires: ${options.expires}`);
  if (options.policyUrl) lines.push(`Policy: ${options.policyUrl}`);
  if (options.acknowledgmentsUrl) lines.push(`Acknowledgments: ${options.acknowledgmentsUrl}`);
  if (options.preferredLanguages) lines.push(`Preferred-Languages: ${options.preferredLanguages}`);
  if (options.canonicalUrl) lines.push(`Canonical: ${options.canonicalUrl}`);
  return `${lines.join("\n")}\n`;
}

export function securityTxtResponse(options: SecurityTxtOptions): Response {
  return new Response(securityTxt(options), {
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "public, max-age=86400",
      "access-control-allow-origin": "*",
    },
  });
}

/**
 * One thing an agent can use, listed in the catalog.
 *
 * `type` is a media type, and it is how a reader decides whether it can consume the entry at
 * all — `application/mcp-server-card+json` for an MCP server, `application/json` for a REST
 * API with an OpenAPI description. Exactly one of `url` or `data` is allowed.
 */
export interface AiCatalogEntry {
  identifier: string;
  type: string;
  url?: string;
  data?: unknown;
  displayName?: string;
  description?: string;
  tags?: string[];
  /**
   * Two to five things somebody would actually ask, in their words. This is what makes an
   * entry findable rather than merely present, and it is the field most publishers skip.
   */
  representativeQueries?: string[];
}

export interface AiCatalogOptions {
  /** the publisher's own domain; `identifier` values are namespaced under it */
  host: { displayName: string; identifier: string; documentationUrl?: string };
  entries: AiCatalogEntry[];
}

/** `urn:air:{publisher}:{namespace}:{name}` — the publisher must be a domain you control. */
export function airUrn(publisher: string, namespace: string, name: string): string {
  return `urn:air:${publisher}:${namespace}:${name}`;
}

export function aiCatalog(options: AiCatalogOptions): Record<string, unknown> {
  return {
    specVersion: "1.0",
    host: options.host,
    entries: options.entries.map((e) => ({
      identifier: e.identifier,
      ...(e.displayName ? { displayName: e.displayName } : {}),
      type: e.type,
      ...(e.url ? { url: e.url } : {}),
      ...(e.data !== undefined ? { data: e.data } : {}),
      ...(e.description ? { description: e.description } : {}),
      ...(e.tags?.length ? { tags: e.tags } : {}),
      ...(e.representativeQueries?.length
        ? { representativeQueries: e.representativeQueries }
        : {}),
    })),
  };
}

export function aiCatalogResponse(options: AiCatalogOptions): Response {
  return new Response(`${JSON.stringify(aiCatalog(options), null, 2)}\n`, {
    headers: {
      // the spec's media type; unregistered with IANA, but it is what every live publisher sends
      "content-type": "application/ai-catalog+json",
      "cache-control": "public, max-age=3600",
      "access-control-allow-origin": "*",
    },
  });
}

/**
 * An MCP server card, served at `<streamable-http-url>/server-card`.
 *
 * `description` is capped at 100 characters by the schema, which is easy to violate and
 * awkward to debug, so it is enforced here instead of at whatever reads it.
 */
export interface ServerCardOptions {
  /** reverse-DNS with exactly one slash, e.g. `io.github.agentwares/stablecoin-attestations` */
  name: string;
  version: string;
  /** at most 100 characters */
  description: string;
  title?: string;
  websiteUrl?: string;
  repository?: { url: string; source?: string; id?: string };
  /** where the server actually answers */
  remotes?: { type: "streamable-http" | "sse"; url: string }[];
}

const SERVER_CARD_NAME = /^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/;

export function serverCard(options: ServerCardOptions): Record<string, unknown> {
  if (!SERVER_CARD_NAME.test(options.name)) {
    throw new Error(
      `server card name must be reverse-DNS with one slash, got ${JSON.stringify(options.name)}`,
    );
  }
  if (options.description.length > 100) {
    throw new Error(
      `server card description is capped at 100 characters, got ${options.description.length}`,
    );
  }
  return {
    // The schema pattern-requires this exact string. It 404s today, so publish the literal
    // and do not try to fetch it at runtime.
    $schema: "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json",
    name: options.name,
    version: options.version,
    description: options.description,
    ...(options.title ? { title: options.title } : {}),
    ...(options.websiteUrl ? { websiteUrl: options.websiteUrl } : {}),
    ...(options.repository ? { repository: options.repository } : {}),
    ...(options.remotes?.length ? { remotes: options.remotes } : {}),
  };
}

export function serverCardResponse(options: ServerCardOptions): Response {
  return new Response(`${JSON.stringify(serverCard(options), null, 2)}\n`, {
    headers: {
      "content-type": "application/mcp-server-card+json",
      "cache-control": "public, max-age=3600",
      "access-control-allow-origin": "*",
    },
  });
}
