import { describe, expect, it } from "vitest";
import { importSigningKey, type SigningKey } from "./keys.js";
import { attachSignature, directoryOrigin, directoryUrl, signRequest } from "./sign.js";
import { verifyRequest } from "./verify.js";
import {
  E_2_2,
  RFC9421_ED25519_JWK,
  RFC9421_ED25519_THUMBPRINT,
} from "./__fixtures__/test-vectors.js";

const key: SigningKey = await importSigningKey(RFC9421_ED25519_JWK);

function testRequest(): Request {
  return new Request("https://example.com/foo?param=Value&Pet=dog", { method: "POST" });
}

describe("signRequest — Appendix E.2.2 / Cloudflare's documented example", () => {
  it("produces the published headers byte for byte", async () => {
    const headers = await signRequest(testRequest(), key, {
      directory: E_2_2.directory,
      label: E_2_2.label,
      created: E_2_2.created,
      expires: E_2_2.expires,
      nonce: E_2_2.nonce,
    });

    expect(headers["signature-agent"]).toBe(E_2_2.signatureAgentHeader);
    expect(headers["signature-input"]).toBe(
      `sig2=("@authority" "signature-agent");created=1735689600;keyid="${RFC9421_ED25519_THUMBPRINT}";alg="ed25519";expires=1735693200;nonce="${E_2_2.nonce}";tag="web-bot-auth"`,
    );
    expect(headers.signature).toBe(`sig2=:${E_2_2.signature}:`);
  });
});

describe("signRequest — defaults", () => {
  it("emits the three headers Web Bot Auth requires, in the Cloudflare-accepted form", async () => {
    const headers = await signRequest(testRequest(), key, { directory: "https://bot.example" });
    expect(Object.keys(headers).sort()).toEqual([
      "signature",
      "signature-agent",
      "signature-input",
    ]);
    // Cloudflare fails a message whose Signature-Agent uses the dictionary form.
    expect(headers["signature-agent"]).toBe('"https://bot.example"');
    expect(headers["signature-input"]).toContain('tag="web-bot-auth"');
    expect(headers["signature-input"]).toContain('("@authority" "signature-agent")');
    expect(headers["signature-input"]).toContain(`keyid="${RFC9421_ED25519_THUMBPRINT}"`);
  });

  it("defaults to a 60 second window, Cloudflare's recommended replay bound", async () => {
    const created = 1_800_000_000;
    const headers = await signRequest(testRequest(), key, {
      directory: "https://bot.example",
      created,
    });
    expect(headers["signature-input"]).toContain(`;expires=${created + 60};`);
  });

  it("includes a fresh 64-byte nonce by default and omits it on request", async () => {
    const withNonce = await signRequest(testRequest(), key, { directory: "https://bot.example" });
    const again = await signRequest(testRequest(), key, { directory: "https://bot.example" });
    const nonceOf = (input: string): string => /nonce="([^"]+)"/.exec(input)?.[1] ?? "";
    expect(nonceOf(withNonce["signature-input"])).not.toBe(nonceOf(again["signature-input"]));

    const without = await signRequest(testRequest(), key, {
      directory: "https://bot.example",
      nonce: false,
    });
    expect(without["signature-input"]).not.toContain("nonce=");
  });

  it("accepts the well-known URL and still sends the origin", async () => {
    const headers = await signRequest(testRequest(), key, {
      directory: "https://bot.example/.well-known/http-message-signatures-directory",
    });
    expect(headers["signature-agent"]).toBe('"https://bot.example"');
  });

  it("covers extra components on request", async () => {
    const headers = await signRequest(testRequest(), key, {
      directory: "https://bot.example",
      alsoCover: [{ name: "@method" }, { name: "@path" }],
    });
    expect(headers["signature-input"]).toContain(
      '("@authority" "signature-agent" "@method" "@path")',
    );
  });
});

describe("signRequest — dictionary Signature-Agent (current draft)", () => {
  it("keys the member to the signature label and covers it with `key`", async () => {
    const headers = await signRequest(testRequest(), key, {
      directory: "https://bot.example",
      label: "agent",
      signatureAgentForm: "dictionary",
    });
    expect(headers["signature-agent"]).toBe('agent="https://bot.example"');
    expect(headers["signature-input"]).toContain('("@authority" "signature-agent";key="agent")');
  });
});

describe("signRequest — round trip through the verifier", () => {
  it.each(["sf-string", "dictionary"] as const)("verifies a %s signature", async (form) => {
    const request = testRequest();
    const headers = await signRequest(request, key, {
      directory: "https://bot.example",
      signatureAgentForm: form,
    });
    const signed = attachSignature(request, headers);

    const result = await verifyRequest(signed, { keys: [key.publicJwk] });
    expect(result).toMatchObject({
      ok: true,
      keyid: RFC9421_ED25519_THUMBPRINT,
      signatureAgent: "https://bot.example",
    });
  });

  it("leaves the original request untouched", async () => {
    const request = testRequest();
    const headers = await signRequest(request, key, { directory: "https://bot.example" });
    expect(request.headers.get("signature")).toBeNull();
    expect(attachSignature(request, headers).headers.get("signature")).toBe(headers.signature);
  });
});

describe("directory URL handling", () => {
  it("normalizes an origin and builds the well-known URL", () => {
    expect(directoryOrigin("https://bot.example/")).toBe("https://bot.example");
    expect(directoryUrl("https://bot.example")).toBe(
      "https://bot.example/.well-known/http-message-signatures-directory",
    );
    expect(directoryUrl("https://bot.example:8443")).toBe(
      "https://bot.example:8443/.well-known/http-message-signatures-directory",
    );
  });

  it("refuses anything a verifier would ignore", () => {
    expect(() => directoryOrigin("http://bot.example")).toThrowError(/must be https/);
    expect(() => directoryOrigin("https://bot.example/keys.json")).toThrowError(
      /must be an origin/,
    );
    expect(() => directoryOrigin("https://bot.example?x=1")).toThrowError(/query or fragment/);
    expect(() => directoryOrigin("bot.example")).toThrowError(/not a URL/);
  });
});

describe("signRequest — errors", () => {
  it("refuses a signature that expires before it is created", async () => {
    await expect(
      signRequest(testRequest(), key, {
        directory: "https://bot.example",
        created: 100,
        expires: 100,
      }),
    ).rejects.toThrowError(/not after created/);
  });
});
