import { describe, expect, it } from "vitest";
import { buildSignatureBase, serializeSignatureParams, type MessageContext } from "./base.js";
import { WebBotAuthError } from "./errors.js";
import {
  B_2_6,
  E_2_1,
  E_2_2,
  E_2_3,
  RFC9421_FIGURE_1,
  TEST_REQUEST,
} from "./__fixtures__/test-vectors.js";

function testRequestContext(extraHeaders: Record<string, string> = {}): MessageContext {
  return {
    request: {
      method: TEST_REQUEST.method,
      url: TEST_REQUEST.url,
      headers: new Headers({ ...TEST_REQUEST.headers, ...extraHeaders }),
    },
  };
}

describe("buildSignatureBase — published test vectors", () => {
  it("reproduces RFC 9421 Figure 1 byte for byte", () => {
    const base = buildSignatureBase(
      [
        { name: "@method" },
        { name: "@authority" },
        { name: "@path" },
        { name: "content-digest" },
        { name: "content-length" },
        { name: "content-type" },
      ],
      [
        ["created", 1618884473],
        ["keyid", "test-key-rsa-pss"],
      ],
      testRequestContext(),
    );
    expect(base).toBe(RFC9421_FIGURE_1);
  });

  it("reproduces RFC 9421 B.2.6 (ed25519 over test-request)", () => {
    const base = buildSignatureBase(
      [
        { name: "date" },
        { name: "@method" },
        { name: "@path" },
        { name: "@authority" },
        { name: "content-type" },
        { name: "content-length" },
      ],
      [
        ["created", 1618884473],
        ["keyid", "test-key-ed25519"],
      ],
      testRequestContext(),
    );
    expect(base).toBe(B_2_6.base);
  });

  it("reproduces draft Appendix E.2.1 (dictionary Signature-Agent)", () => {
    const base = buildSignatureBase(
      [{ name: "@authority" }, { name: "signature-agent", params: [["key", "agent2"]] }],
      [
        ["created", E_2_1.created],
        ["keyid", "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"],
        ["alg", "ed25519"],
        ["expires", E_2_1.expires],
        ["nonce", E_2_1.nonce],
        ["tag", "web-bot-auth"],
      ],
      testRequestContext({ "Signature-Agent": E_2_1.signatureAgentHeader }),
    );
    expect(base).toBe(E_2_1.base);
  });

  it("reproduces draft Appendix E.2.2 (legacy sf-string Signature-Agent)", () => {
    const base = buildSignatureBase(
      [{ name: "@authority" }, { name: "signature-agent" }],
      [
        ["created", E_2_2.created],
        ["keyid", "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"],
        ["alg", "ed25519"],
        ["expires", E_2_2.expires],
        ["nonce", E_2_2.nonce],
        ["tag", "web-bot-auth"],
      ],
      testRequestContext({ "Signature-Agent": E_2_2.signatureAgentHeader }),
    );
    expect(base).toBe(E_2_2.base);
  });

  it("reproduces draft Appendix E.2.3 (signed directory response, @authority;req)", () => {
    const context: MessageContext = {
      request: {
        method: "GET",
        url: E_2_3.url,
        headers: new Headers({ Accept: "application/http-message-signatures-directory+json" }),
      },
      response: {
        status: 200,
        headers: new Headers({ "Content-Digest": E_2_3.contentDigest }),
      },
    };
    const base = buildSignatureBase(
      [{ name: "@authority", params: [["req", true]] }, { name: "content-digest" }],
      [
        ["created", E_2_3.created],
        ["expires", E_2_3.expires],
        ["keyid", "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"],
        ["tag", "http-message-signatures-directory"],
      ],
      context,
    );
    expect(base).toBe(E_2_3.base);
  });
});

describe("buildSignatureBase — derived components", () => {
  const context: MessageContext = {
    request: {
      method: "get",
      url: "https://Example.COM:443/foo/bar?b=1&a=2",
      headers: new Headers(),
    },
  };

  it("normalizes @authority to lowercase and drops the default port", () => {
    const base = buildSignatureBase([{ name: "@authority" }], [], context);
    expect(base.split("\n")[0]).toBe('"@authority": example.com');
  });

  it("keeps a non-default port on @authority", () => {
    const base = buildSignatureBase([{ name: "@authority" }], [], {
      request: { method: "GET", url: "https://example.com:8443/", headers: new Headers() },
    });
    expect(base.split("\n")[0]).toBe('"@authority": example.com:8443');
  });

  it("uppercases @method and keeps @path and @query separate", () => {
    const base = buildSignatureBase(
      [{ name: "@method" }, { name: "@path" }, { name: "@query" }],
      [],
      context,
    );
    expect(base.split("\n").slice(0, 3)).toEqual([
      '"@method": GET',
      '"@path": /foo/bar',
      '"@query": ?b=1&a=2',
    ]);
  });

  it("renders an empty query as a bare question mark", () => {
    const base = buildSignatureBase([{ name: "@query" }], [], {
      request: { method: "GET", url: "https://example.com/x", headers: new Headers() },
    });
    expect(base.split("\n")[0]).toBe('"@query": ?');
  });
});

describe("buildSignatureBase — dictionary members (RFC 9421 section 2.1.2)", () => {
  const context: MessageContext = {
    request: {
      method: "GET",
      url: "https://example.com/",
      headers: new Headers({ "Example-Dict": "a=1, b=2;x=1;y=2, c=(a   b    c), d" }),
    },
  };

  it.each([
    ["a", '"example-dict";key="a": 1'],
    ["d", '"example-dict";key="d": ?1'],
    ["b", '"example-dict";key="b": 2;x=1;y=2'],
    ["c", '"example-dict";key="c": (a b c)'],
  ])("re-serializes member %s strictly", (key, expected) => {
    const base = buildSignatureBase(
      [{ name: "example-dict", params: [["key", key]] }],
      [],
      context,
    );
    expect(base.split("\n")[0]).toBe(expected);
  });
});

describe("buildSignatureBase — errors", () => {
  const context = testRequestContext();

  it("rejects a repeated component identifier", () => {
    expect(() =>
      buildSignatureBase([{ name: "@authority" }, { name: "@authority" }], [], context),
    ).toThrowError(WebBotAuthError);
  });

  it("rejects `req` on a request message", () => {
    expect(() =>
      buildSignatureBase([{ name: "@authority", params: [["req", true]] }], [], context),
    ).toThrowError(/req/);
  });

  it("rejects the `sf` and `bs` parameters Cloudflare does not support", () => {
    for (const param of ["sf", "bs"] as const) {
      expect(() =>
        buildSignatureBase([{ name: "content-type", params: [[param, true]] }], [], context),
      ).toThrowError(/not supported/);
    }
  });

  it("rejects a field that is not in the message", () => {
    expect(() => buildSignatureBase([{ name: "x-absent" }], [], context)).toThrowError(
      /not present/,
    );
  });

  it("rejects an uppercase field name", () => {
    expect(() => buildSignatureBase([{ name: "Content-Type" }], [], context)).toThrowError(
      /lowercased/,
    );
  });

  it("rejects a non-ASCII field value rather than signing it", () => {
    expect(() =>
      buildSignatureBase([{ name: "x-note" }], [], testRequestContext({ "X-Note": "café" })),
    ).toThrowError(/non-ASCII/);
  });

  it("rejects an unknown derived component", () => {
    expect(() => buildSignatureBase([{ name: "@nope" }], [], context)).toThrowError(
      /unknown derived component/,
    );
  });
});

describe("serializeSignatureParams", () => {
  it("matches the Signature-Input value from Appendix E.2.2", () => {
    const value = serializeSignatureParams(
      [{ name: "@authority" }, { name: "signature-agent" }],
      [
        ["created", E_2_2.created],
        ["keyid", "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"],
        ["alg", "ed25519"],
        ["expires", E_2_2.expires],
        ["nonce", E_2_2.nonce],
        ["tag", "web-bot-auth"],
      ],
    );
    // The Signature-Input value is exactly the inner list that ends the signature base.
    expect(`"@signature-params": ${value}`).toBe(E_2_2.base.split("\n")[2]);
  });
});
