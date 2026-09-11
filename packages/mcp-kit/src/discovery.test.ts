import { describe, expect, it } from "vitest";
import {
  aiCatalog,
  aiCatalogResponse,
  airUrn,
  securityTxt,
  serverCard,
  serverCardResponse,
} from "./discovery.js";

describe("security.txt", () => {
  it("puts Contact and Expires first, which are the only required fields", () => {
    const txt = securityTxt({
      contact: ["mailto:security@example.com", "https://example.com/security"],
      expires: "2027-06-30T23:59:59Z",
    });
    expect(txt.split("\n").slice(0, 3)).toEqual([
      "Contact: mailto:security@example.com",
      "Contact: https://example.com/security",
      "Expires: 2027-06-30T23:59:59Z",
    ]);
    expect(txt.endsWith("\n")).toBe(true);
  });

  it("spells Acknowledgments the way RFC 9116 does", () => {
    const txt = securityTxt({
      contact: ["mailto:a@b.c"],
      expires: "2027-01-01T00:00:00Z",
      acknowledgmentsUrl: "https://example.com/thanks",
    });
    expect(txt).toContain("Acknowledgments: https://example.com/thanks");
    expect(txt).not.toContain("Acknowledgements");
  });
});

describe("ai-catalog", () => {
  const catalog = () =>
    aiCatalog({
      host: { displayName: "Agentwares", identifier: "agentwares.dev" },
      entries: [
        {
          identifier: airUrn("agentwares.dev", "mcp", "stablecoin"),
          type: "application/mcp-server-card+json",
          url: "https://example.com/mcp/server-card",
          representativeQueries: ["what backs USDC", "is USDC fully reserved"],
        },
      ],
    });

  it("carries the two required top-level fields", () => {
    expect(catalog()).toMatchObject({ specVersion: "1.0", host: { identifier: "agentwares.dev" } });
    expect(Array.isArray(catalog().entries)).toBe(true);
  });

  it("namespaces identifiers under the publisher's domain", () => {
    expect(airUrn("agentwares.dev", "api", "deal-memo")).toBe(
      "urn:air:agentwares.dev:api:deal-memo",
    );
  });

  it("omits absent optional fields rather than emitting nulls", () => {
    const entry = (catalog().entries as Record<string, unknown>[])[0]!;
    expect(entry).not.toHaveProperty("data");
    expect(entry).not.toHaveProperty("description");
    expect(entry).toHaveProperty("representativeQueries");
  });

  it("sends the media type a reader dispatches on", async () => {
    const res = aiCatalogResponse({
      host: { displayName: "A", identifier: "a.dev" },
      entries: [],
    });
    // A 200 carrying HTML is the failure mode this exists to avoid, so the type is asserted.
    expect(res.headers.get("content-type")).toBe("application/ai-catalog+json");
    await expect(res.json()).resolves.toMatchObject({ specVersion: "1.0" });
  });
});

describe("server card", () => {
  const valid = {
    name: "io.github.agentwares/stablecoin-attestations",
    version: "0.1.2",
    description: "Stablecoin issuer reserve attestations as JSON, priced per lookup.",
  };

  it("refuses a name that is not reverse-DNS with one slash", () => {
    expect(() => serverCard({ ...valid, name: "stablecoin" })).toThrow(/reverse-DNS/);
    expect(() => serverCard({ ...valid, name: "a/b/c" })).toThrow(/reverse-DNS/);
  });

  it("refuses a description over the schema's 100-character cap", () => {
    expect(() => serverCard({ ...valid, description: "x".repeat(101) })).toThrow(/100 characters/);
    expect(() => serverCard({ ...valid, description: "x".repeat(100) })).not.toThrow();
  });

  it("publishes the schema URL literally, even though it 404s today", () => {
    expect(serverCard(valid).$schema).toBe(
      "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json",
    );
  });

  it("carries the remote an agent should actually connect to", () => {
    const card = serverCard({
      ...valid,
      remotes: [{ type: "streamable-http", url: "https://example.com/mcp" }],
    });
    expect(card.remotes).toEqual([{ type: "streamable-http", url: "https://example.com/mcp" }]);
  });

  it("sends the MCP server card media type", () => {
    expect(serverCardResponse(valid).headers.get("content-type")).toBe(
      "application/mcp-server-card+json",
    );
  });
});
