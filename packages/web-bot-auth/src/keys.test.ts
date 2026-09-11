import { describe, expect, it } from "vitest";
import { WebBotAuthError } from "./errors.js";
import {
  DIRECTORY_MEDIA_TYPE,
  DIRECTORY_PATH,
  DIRECTORY_TAG,
  REQUEST_TAG,
  generateSigningKey,
  importSigningKey,
  importVerifyingKey,
  jwkThumbprint,
  publicJwkFrom,
  signBytes,
  verifyBytes,
  type Ed25519PublicJwk,
} from "./keys.js";
import {
  B_2_6,
  RFC9421_ED25519_JWK,
  RFC9421_ED25519_THUMBPRINT,
} from "./__fixtures__/test-vectors.js";
import { base64Encode } from "./sfv.js";

describe("protocol constants", () => {
  it("matches the well-known path, media type and tags the specs fix", () => {
    expect(DIRECTORY_PATH).toBe("/.well-known/http-message-signatures-directory");
    expect(DIRECTORY_MEDIA_TYPE).toBe("application/http-message-signatures-directory+json");
    expect(REQUEST_TAG).toBe("web-bot-auth");
    expect(DIRECTORY_TAG).toBe("http-message-signatures-directory");
  });
});

describe("jwkThumbprint (RFC 7638 section 3.2 / RFC 8037 Appendix A.3)", () => {
  it("derives the published thumbprint of RFC 9421's test-key-ed25519", async () => {
    await expect(jwkThumbprint(RFC9421_ED25519_JWK)).resolves.toBe(RFC9421_ED25519_THUMBPRINT);
  });

  it("ignores members outside {crv, kty, x}", async () => {
    const noisy: Ed25519PublicJwk = {
      ...publicJwkFrom(RFC9421_ED25519_JWK),
      kid: "something-else",
      use: "sig",
      nbf: 1712793600,
      exp: 1715385600,
    };
    await expect(jwkThumbprint(noisy)).resolves.toBe(RFC9421_ED25519_THUMBPRINT);
  });

  it("rejects a key that is not OKP/Ed25519", async () => {
    await expect(
      jwkThumbprint({ kty: "EC", crv: "P-256", x: "abc" } as unknown as Ed25519PublicJwk),
    ).rejects.toThrowError(WebBotAuthError);
  });
});

describe("key import", () => {
  it("signs RFC 9421 B.2.6 with the imported test key, byte for byte", async () => {
    const key = await importSigningKey(RFC9421_ED25519_JWK);
    expect(key.keyid).toBe(RFC9421_ED25519_THUMBPRINT);
    const signature = await signBytes(key, new TextEncoder().encode(B_2_6.base));
    expect(base64Encode(signature)).toBe(B_2_6.signature);
  });

  it("strips `d` from the public JWK it exposes", async () => {
    const key = await importSigningKey(RFC9421_ED25519_JWK);
    expect(key.publicJwk).not.toHaveProperty("d");
    expect(publicJwkFrom(RFC9421_ED25519_JWK)).toEqual({
      kty: "OKP",
      crv: "Ed25519",
      x: RFC9421_ED25519_JWK.x,
    });
  });

  it("refuses a public JWK where it needs a private one", async () => {
    await expect(
      importSigningKey(publicJwkFrom(RFC9421_ED25519_JWK) as never),
    ).rejects.toThrowError(/cannot sign/);
  });

  it("refuses a JWK whose kid disagrees with its thumbprint", async () => {
    await expect(
      importVerifyingKey({ ...publicJwkFrom(RFC9421_ED25519_JWK), kid: "wrong" }),
    ).rejects.toThrowError(/not the thumbprint/);
  });
});

describe("generateSigningKey", () => {
  it("produces a usable keypair whose keyid is its own thumbprint", async () => {
    const key = await generateSigningKey();
    expect(key.keyid).toBe(await jwkThumbprint(key.publicJwk));
    expect(key.publicJwk.kid).toBe(key.keyid);
    expect(key.privateJwk.d).toBeTypeOf("string");
    expect(key.publicJwk).not.toHaveProperty("d");

    const message = new TextEncoder().encode("the signature base would go here");
    const signature = await signBytes(key, message);
    const verifier = await importVerifyingKey(key.publicJwk);
    await expect(verifyBytes(verifier, message, signature)).resolves.toBe(true);

    const tampered = new TextEncoder().encode("the signature base would go here!");
    await expect(verifyBytes(verifier, tampered, signature)).resolves.toBe(false);
  });

  it("round-trips through the private JWK a keygen script would persist", async () => {
    const generated = await generateSigningKey();
    const reloaded = await importSigningKey(generated.privateJwk);
    expect(reloaded.keyid).toBe(generated.keyid);

    const message = new TextEncoder().encode("same key, same bytes");
    // Ed25519 is deterministic, so the same key over the same message is the same signature.
    expect(base64Encode(await signBytes(reloaded, message))).toBe(
      base64Encode(await signBytes(generated, message)),
    );
  });

  it("produces a different key every time", async () => {
    const [a, b] = await Promise.all([generateSigningKey(), generateSigningKey()]);
    expect(a.keyid).not.toBe(b.keyid);
  });
});
