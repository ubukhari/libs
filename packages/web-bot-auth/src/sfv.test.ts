import { describe, expect, it } from "vitest";
import { WebBotAuthError } from "./errors.js";
import {
  SfToken,
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  isInnerList,
  parseDictionary,
  parseItem,
  serializeDictionary,
  serializeInnerList,
  serializeItem,
  serializeNumber,
  serializeParams,
  serializeString,
  serializeToken,
} from "./sfv.js";
import { E_2_2 } from "./__fixtures__/test-vectors.js";

describe("serialization (RFC 9651 section 4.1)", () => {
  it("quotes strings and escapes backslash and double quote", () => {
    expect(serializeString("https://signature-agent.test")).toBe('"https://signature-agent.test"');
    expect(serializeString('a"b\\c')).toBe('"a\\"b\\\\c"');
  });

  it("refuses a string with characters outside %x20-%x7E", () => {
    expect(() => serializeString("café")).toThrowError(WebBotAuthError);
    expect(() => serializeString("a\nb")).toThrowError(/printable ASCII/);
  });

  it("serializes tokens bare and rejects invalid ones", () => {
    expect(serializeToken("directory")).toBe("directory");
    expect(serializeToken("sha-256")).toBe("sha-256");
    expect(() => serializeToken("1bad")).toThrowError(/not a valid structured-field token/);
  });

  it("serializes integers and decimals", () => {
    expect(serializeNumber(1735689600)).toBe("1735689600");
    expect(serializeNumber(-42)).toBe("-42");
    expect(serializeNumber(1.5)).toBe("1.5");
    expect(() => serializeNumber(1e18)).toThrowError(/outside the structured-field range/);
  });

  it("omits the value of a boolean-true parameter", () => {
    expect(serializeParams([["req", true]])).toBe(";req");
    expect(serializeParams([["req", false]])).toBe(";req=?0");
    expect(serializeParams([["key", "sig1"]])).toBe(';key="sig1"');
  });

  it("serializes byte sequences between colons", () => {
    const bytes = new Uint8Array([0, 1, 250, 255]);
    expect(serializeItem({ value: bytes, params: [] })).toBe(`:${base64Encode(bytes)}:`);
  });

  it("serializes inner lists with a single space between items", () => {
    expect(
      serializeInnerList({
        items: [
          { value: "@authority", params: [] },
          { value: "signature-agent", params: [["key", "sig1"]] },
        ],
        params: [["tag", "web-bot-auth"]],
      }),
    ).toBe('("@authority" "signature-agent";key="sig1");tag="web-bot-auth"');
  });

  it("serializes a dictionary, omitting a bare true member value", () => {
    expect(
      serializeDictionary([
        ["a", { value: 1, params: [] }],
        ["d", { value: true, params: [] }],
        ["c", { items: [{ value: new SfToken("a"), params: [] }], params: [] }],
      ]),
    ).toBe("a=1, d, c=(a)");
  });
});

describe("parsing (RFC 9651 section 4.2)", () => {
  it("parses the dictionary from RFC 9421 section 2.1.2", () => {
    const dict = parseDictionary("a=1, b=2;x=1;y=2, c=(a   b    c), d");
    expect([...dict.keys()]).toEqual(["a", "b", "c", "d"]);

    const a = dict.get("a");
    expect(a && !isInnerList(a) && a.value).toBe(1);

    const d = dict.get("d");
    expect(d && !isInnerList(d) && d.value).toBe(true);

    const c = dict.get("c");
    expect(c && isInnerList(c) && c.items.map((item) => (item.value as SfToken).value)).toEqual([
      "a",
      "b",
      "c",
    ]);
  });

  it("parses the Signature-Input from Appendix E.2.2 back into components and params", () => {
    const header = `${E_2_2.label}=("@authority" "signature-agent");created=${E_2_2.created};keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=${E_2_2.expires};nonce="${E_2_2.nonce}";tag="web-bot-auth"`;
    const member = parseDictionary(header).get("sig2");
    if (!member || !isInnerList(member)) throw new Error("expected an inner list");
    expect(member.items.map((item) => item.value)).toEqual(["@authority", "signature-agent"]);
    expect(member.params).toEqual([
      ["created", 1735689600],
      ["keyid", "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"],
      ["alg", "ed25519"],
      ["expires", 1735693200],
      ["nonce", E_2_2.nonce],
      ["tag", "web-bot-auth"],
    ]);
  });

  it("round-trips a signature header as a byte sequence", () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const header = serializeDictionary([["sig1", { value: bytes, params: [] }]]);
    const member = parseDictionary(header).get("sig1");
    if (!member || isInnerList(member)) throw new Error("expected an item");
    expect(member.value).toEqual(bytes);
  });

  it("parses the legacy sf-string Signature-Agent", () => {
    expect(parseItem('"https://signature-agent.test"').value).toBe("https://signature-agent.test");
  });

  it("distinguishes the dictionary Signature-Agent from the sf-string form", () => {
    const dict = parseDictionary('sig1="https://signature-agent.test";type=jwks_uri');
    const member = dict.get("sig1");
    if (!member || isInnerList(member)) throw new Error("expected an item");
    expect(member.value).toBe("https://signature-agent.test");
    expect(member.params[0]?.[0]).toBe("type");
    expect((member.params[0]?.[1] as SfToken).value).toBe("jwks_uri");
  });

  it("rejects malformed fields instead of guessing", () => {
    for (const bad of ['sig1=("@authority"', "sig1=:not base64:", "sig1=", "sig1=?2", "=1"]) {
      expect(() => parseDictionary(bad), bad).toThrowError(WebBotAuthError);
    }
  });

  it("unescapes strings on the way back in", () => {
    expect(parseItem('"a\\"b\\\\c"').value).toBe('a"b\\c');
  });
});

describe("base64 helpers", () => {
  it("round-trips base64 and base64url", () => {
    const bytes = new Uint8Array(Array.from({ length: 64 }, (_, i) => (i * 7) % 256));
    expect(base64Decode(base64Encode(bytes))).toEqual(bytes);
    expect(base64UrlDecode(base64UrlEncode(bytes))).toEqual(bytes);
  });

  it("emits base64url without padding or +/ characters", () => {
    const encoded = base64UrlEncode(new Uint8Array([251, 255, 190, 255]));
    expect(encoded).not.toMatch(/[+/=]/);
  });
});
