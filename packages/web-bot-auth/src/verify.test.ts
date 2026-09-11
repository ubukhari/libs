import { describe, expect, it } from "vitest";
import { generateSigningKey, importSigningKey, publicJwkFrom, type SigningKey } from "./keys.js";
import { attachSignature, signRequest } from "./sign.js";
import { verifyRequest, type VerifyResult } from "./verify.js";
import {
  E_2_2,
  RFC9421_ED25519_JWK,
  RFC9421_ED25519_THUMBPRINT,
} from "./__fixtures__/test-vectors.js";

const key: SigningKey = await importSigningKey(RFC9421_ED25519_JWK);
const publicJwk = publicJwkFrom(RFC9421_ED25519_JWK);

/** The request from Appendix E.2.2, rebuilt from the headers exactly as published. */
function publishedRequest(): Request {
  return new Request("https://example.com/foo?param=Value&Pet=dog", {
    method: "POST",
    headers: {
      "signature-agent": E_2_2.signatureAgentHeader,
      "signature-input": `sig2=("@authority" "signature-agent");created=${E_2_2.created};keyid="${RFC9421_ED25519_THUMBPRINT}";alg="ed25519";expires=${E_2_2.expires};nonce="${E_2_2.nonce}";tag="web-bot-auth"`,
      signature: `sig2=:${E_2_2.signature}:`,
    },
  });
}

async function signed(options: Parameters<typeof signRequest>[2]): Promise<Request> {
  const request = new Request("https://example.com/resource");
  return attachSignature(request, await signRequest(request, key, options));
}

function failure(result: VerifyResult): { code: string; cause: string } {
  if (result.ok) throw new Error("expected a failure");
  return { code: result.code, cause: result.cause };
}

describe("verifyRequest — a signature produced elsewhere", () => {
  it("accepts the published Appendix E.2.2 signature", async () => {
    const result = await verifyRequest(publishedRequest(), {
      keys: [publicJwk],
      now: E_2_2.created,
    });
    expect(result).toMatchObject({
      ok: true,
      label: "sig2",
      keyid: RFC9421_ED25519_THUMBPRINT,
      signatureAgent: "https://signature-agent.test",
      created: E_2_2.created,
      expires: E_2_2.expires,
      components: ['"@authority"', '"signature-agent"'],
    });
  });

  it("resolves the key through a resolver as well as a JWKS array", async () => {
    const result = await verifyRequest(publishedRequest(), {
      keys: (keyid) => (keyid === RFC9421_ED25519_THUMBPRINT ? publicJwk : undefined),
      now: E_2_2.created,
    });
    expect(result.ok).toBe(true);
  });

  it("rejects it once it has expired", async () => {
    const result = await verifyRequest(publishedRequest(), {
      keys: [publicJwk],
      now: E_2_2.expires + 3600,
    });
    expect(failure(result).code).toBe("STALE");
  });
});

describe("verifyRequest — what a signature does not let through", () => {
  it("rejects a signature replayed against a different authority", async () => {
    const request = await signed({ directory: "https://bot.example" });
    const moved = new Request("https://victim.example/resource", { headers: request.headers });
    expect(failure(await verifyRequest(moved, { keys: [key.publicJwk] })).code).toBe(
      "BAD_SIGNATURE",
    );
  });

  it("rejects a rewritten Signature-Agent", async () => {
    const request = await signed({ directory: "https://bot.example" });
    const headers = new Headers(request.headers);
    headers.set("signature-agent", '"https://impostor.example"');
    const tampered = new Request(request.url, { headers });
    expect(failure(await verifyRequest(tampered, { keys: [key.publicJwk] })).code).toBe(
      "BAD_SIGNATURE",
    );
  });

  it("rejects a signature from a key the verifier does not publish", async () => {
    const request = await signed({ directory: "https://bot.example" });
    const stranger = await generateSigningKey();
    expect(failure(await verifyRequest(request, { keys: [stranger.publicJwk] })).code).toBe(
      "UNKNOWN_KEY",
    );
  });

  it("rejects a key whose kid is not its own thumbprint", async () => {
    const request = await signed({ directory: "https://bot.example" });
    const lying = { ...key.publicJwk, kid: "not-the-thumbprint" };
    const result = await verifyRequest(request, {
      keys: (keyid) => (keyid === key.keyid ? lying : undefined),
    });
    expect(failure(result).code).toBe("UNKNOWN_KEY");
  });

  it("rejects a signature that does not cover Signature-Agent", async () => {
    const request = await signed({
      directory: "https://bot.example",
      components: [{ name: "@authority" }],
    });
    const result = await verifyRequest(request, { keys: [key.publicJwk] });
    expect(failure(result)).toMatchObject({
      code: "MISSING_COMPONENT",
      cause: expect.stringContaining("signature-agent"),
    });
  });

  it("rejects a signature that binds to no authority at all", async () => {
    const request = await signed({
      directory: "https://bot.example",
      components: [{ name: "signature-agent" }],
    });
    expect(failure(await verifyRequest(request, { keys: [key.publicJwk] })).code).toBe(
      "MISSING_COMPONENT",
    );
  });

  it("accepts @target-uri in place of @authority", async () => {
    const request = await signed({
      directory: "https://bot.example",
      components: [{ name: "@target-uri" }, { name: "signature-agent" }],
    });
    expect((await verifyRequest(request, { keys: [key.publicJwk] })).ok).toBe(true);
  });

  it("ignores a signature tagged for another protocol", async () => {
    const request = await signed({ directory: "https://bot.example" });
    const result = await verifyRequest(request, {
      keys: [key.publicJwk],
      tag: "http-message-signatures-directory",
    });
    expect(failure(result).code).toBe("NO_SIGNATURE");
  });

  it("reports an unsigned request", async () => {
    const result = await verifyRequest(new Request("https://example.com/"), {
      keys: [key.publicJwk],
    });
    expect(failure(result).code).toBe("NO_SIGNATURE");
  });

  it("reports a Signature-Input that does not parse", async () => {
    const request = new Request("https://example.com/", {
      headers: { "signature-input": 'sig1=("@authority"', signature: "sig1=:AAAA:" },
    });
    expect(failure(await verifyRequest(request, { keys: [key.publicJwk] })).code).toBe("MALFORMED");
  });

  it("reports a Signature-Input with no matching Signature member", async () => {
    const request = await signed({ directory: "https://bot.example" });
    const headers = new Headers(request.headers);
    headers.set("signature", "other=:AAAA:");
    const result = await verifyRequest(new Request(request.url, { headers }), {
      keys: [key.publicJwk],
    });
    expect(failure(result).code).toBe("MALFORMED");
  });

  it("rejects a signature with no expires", async () => {
    const request = new Request("https://example.com/", {
      headers: {
        "signature-agent": '"https://bot.example"',
        "signature-input": `sig1=("@authority" "signature-agent");created=1735689600;keyid="${RFC9421_ED25519_THUMBPRINT}";tag="web-bot-auth"`,
        signature: "sig1=:AAAA:",
      },
    });
    const result = await verifyRequest(request, { keys: [publicJwk], now: 1735689600 });
    expect(failure(result)).toMatchObject({
      code: "MALFORMED",
      cause: expect.stringContaining("expires"),
    });
  });

  it("rejects a signature created in the future", async () => {
    const created = 2_000_000_000;
    const request = await signed({ directory: "https://bot.example", created });
    expect(
      failure(await verifyRequest(request, { keys: [key.publicJwk], now: created - 3600 })).code,
    ).toBe("STALE");
  });
});

describe("verifyRequest — multiple signatures", () => {
  it("verifies the label the caller names and ignores the rest", async () => {
    const request = new Request("https://example.com/resource");
    const mine = await signRequest(request, key, { directory: "https://bot.example", label: "a" });
    const theirs = await signRequest(request, await generateSigningKey(), {
      directory: "https://other.example",
      label: "b",
      signatureAgentForm: "dictionary",
    });
    const headers = new Headers({
      "signature-agent": `${mine["signature-agent"]}`,
      "signature-input": `${mine["signature-input"]}, ${theirs["signature-input"]}`,
      signature: `${mine.signature}, ${theirs.signature}`,
    });
    const combined = new Request(request.url, { headers });

    const result = await verifyRequest(combined, { keys: [key.publicJwk], label: "a" });
    expect(result).toMatchObject({ ok: true, label: "a" });

    // The other signer's key is not published here, so its label must not verify.
    expect(failure(await verifyRequest(combined, { keys: [key.publicJwk], label: "b" })).code).toBe(
      "UNKNOWN_KEY",
    );
  });
});
