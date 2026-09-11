/**
 * Ed25519 keys for Web Bot Auth, through Web Crypto only.
 *
 * Cloudflare's Web Bot Auth documentation is explicit that Ed25519 is the supported key
 * algorithm, and the protocol draft fixes `keyid` as the base64url JWK SHA-256 thumbprint
 * (RFC 7638 section 3.2, with the OKP member set from RFC 8037 Appendix A.3).
 */
import { invalid } from "./errors.js";
import { base64UrlEncode } from "./sfv.js";

/** The `alg` value from the HTTP Signature Algorithms registry (RFC 9421 section 3.3.6). */
export const ED25519_ALG = "ed25519";

/** The well-known path the key directory MUST be served at. */
export const DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";

/** The media type the key directory MUST be served with. */
export const DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json";

/** The `tag` on an outbound bot request signature. */
export const REQUEST_TAG = "web-bot-auth";

/** The `tag` on the key directory's own response signature. */
export const DIRECTORY_TAG = "http-message-signatures-directory";

export interface Ed25519PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  /** base64url public key, no padding. */
  x: string;
  /** When present this MUST equal the thumbprint, so a verifier can select by `keyid`. */
  kid?: string;
  use?: "sig";
  alg?: string;
  /** Not-before / expiry, seconds since the epoch, as shown in the draft's directory example. */
  nbf?: number;
  exp?: number;
}

export interface Ed25519PrivateJwk extends Ed25519PublicJwk {
  /** base64url private scalar. Never log this, never commit it, never put it in an env var. */
  d: string;
}

/** A key this process can sign with. */
export interface SigningKey {
  /** The base64url JWK thumbprint; the `keyid` signature parameter on the wire. */
  keyid: string;
  publicJwk: Ed25519PublicJwk;
  privateKey: CryptoKey;
}

export interface GeneratedSigningKey extends SigningKey {
  /** Only returned by `generateSigningKey`, so the caller can persist it to 0600 storage. */
  privateJwk: Ed25519PrivateJwk;
}

/** A key this process can verify against. */
export interface VerifyingKey {
  keyid: string;
  publicJwk: Ed25519PublicJwk;
  publicKey: CryptoKey;
}

const ED25519: Algorithm = { name: "Ed25519" };

/**
 * RFC 7638 section 3.2 / RFC 8037 Appendix A.3: SHA-256 over the JSON object containing
 * exactly `crv`, `kty` and `x`, with no whitespace and members in lexicographic order.
 */
export async function jwkThumbprint(jwk: Ed25519PublicJwk): Promise<string> {
  assertEd25519Jwk(jwk);
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return base64UrlEncode(new Uint8Array(digest));
}

/** Generate a fresh Ed25519 keypair. The private JWK is returned, never printed. */
export async function generateSigningKey(): Promise<GeneratedSigningKey> {
  const generated = await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"]);
  if (!("privateKey" in generated)) {
    throw invalid(
      "CRYPTO_ERROR",
      "Web Crypto returned a single key for Ed25519 instead of a keypair",
      "Upgrade to a runtime with Ed25519 support (Node 20+, Cloudflare Workers, Deno, modern browsers).",
    );
  }
  const privateJwk = toPrivateJwk(await crypto.subtle.exportKey("jwk", generated.privateKey));
  const publicJwk = publicJwkFrom(privateJwk);
  const keyid = await jwkThumbprint(publicJwk);
  return {
    keyid,
    // No `alg`: the directory draft restricts a published JWK's `alg` to the HTTP
    // Signature Algorithms registry ("ed25519"), not the JOSE name ("EdDSA"), and Cloudflare
    // ignores the member entirely. Asserting neither is safer than asserting the wrong one.
    publicJwk: { ...publicJwk, kid: keyid, use: "sig" },
    privateJwk,
    privateKey: generated.privateKey,
  };
}

/** Load a signing key from a stored private JWK. */
export async function importSigningKey(jwk: Ed25519PrivateJwk): Promise<SigningKey> {
  if (typeof jwk.d !== "string" || jwk.d === "") {
    throw invalid(
      "INVALID_KEY",
      "the JWK has no `d` member, so it cannot sign",
      "Pass the private JWK written by `generateSigningKey`, not the public one.",
    );
  }
  const publicJwk = publicJwkFrom(jwk);
  const keyid = await jwkThumbprint(publicJwk);
  const privateKey = await importKey({ ...publicJwk, d: jwk.d }, ["sign"]);
  return { keyid, publicJwk: { ...publicJwk, kid: keyid }, privateKey };
}

/** Load a verifying key from a public JWK, e.g. one read out of a fetched directory. */
export async function importVerifyingKey(jwk: Ed25519PublicJwk): Promise<VerifyingKey> {
  const publicJwk = publicJwkFrom(jwk);
  const keyid = await jwkThumbprint(publicJwk);
  if (jwk.kid !== undefined && jwk.kid !== keyid) {
    throw invalid(
      "INVALID_KEY",
      `the JWK's kid "${jwk.kid}" is not the thumbprint of its key material`,
      "Set `kid` to the RFC 7638 thumbprint, or omit it; a verifier selects keys by thumbprint.",
    );
  }
  return {
    keyid,
    publicJwk: { ...publicJwk, kid: keyid },
    publicKey: await importKey(publicJwk, ["verify"]),
  };
}

/** Strip `d` and any non-key metadata, leaving the members the thumbprint is taken over. */
export function publicJwkFrom(jwk: Ed25519PublicJwk): Ed25519PublicJwk {
  assertEd25519Jwk(jwk);
  return { kty: "OKP", crv: "Ed25519", x: jwk.x };
}

export async function signBytes(key: SigningKey, message: Uint8Array): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(ED25519, key.privateKey, toBufferSource(message));
  return new Uint8Array(signature);
}

export async function verifyBytes(
  key: VerifyingKey,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  return crypto.subtle.verify(
    ED25519,
    key.publicKey,
    toBufferSource(signature),
    toBufferSource(message),
  );
}

function assertEd25519Jwk(jwk: Ed25519PublicJwk): void {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw invalid(
      "INVALID_KEY",
      `expected an OKP/Ed25519 JWK, got kty="${String(jwk.kty)}" crv="${String(jwk.crv)}"`,
      "Cloudflare's Web Bot Auth accepts Ed25519 only; generate one with `generateSigningKey`.",
    );
  }
  if (typeof jwk.x !== "string" || jwk.x === "") {
    throw invalid(
      "INVALID_KEY",
      "the JWK has no `x` member",
      "`x` is the base64url public key and is required for both signing and verification.",
    );
  }
}

async function importKey(
  jwk: Ed25519PublicJwk & { d?: string },
  usages: KeyUsage[],
): Promise<CryptoKey> {
  // Import a minimal JWK: some runtimes reject members they do not recognise, and `nbf` /
  // `exp` / `kid` are directory metadata rather than key material.
  const minimal: JsonWebKey = jwk.d
    ? { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d }
    : { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
  try {
    return await crypto.subtle.importKey("jwk", minimal, ED25519, true, usages);
  } catch (error) {
    throw invalid(
      "CRYPTO_ERROR",
      "Web Crypto rejected the Ed25519 JWK",
      "Check that `x` (and `d` for a signing key) are unpadded base64url of the right length, and that the runtime supports Ed25519.",
      error,
    );
  }
}

function toPrivateJwk(exported: JsonWebKey): Ed25519PrivateJwk {
  if (exported.kty !== "OKP" || exported.crv !== "Ed25519" || !exported.x || !exported.d) {
    throw invalid(
      "CRYPTO_ERROR",
      "Web Crypto exported something that is not an Ed25519 private JWK",
      "Upgrade to a runtime with Ed25519 support (Node 20+, Cloudflare Workers, Deno, modern browsers).",
    );
  }
  return { kty: "OKP", crv: "Ed25519", x: exported.x, d: exported.d };
}

/**
 * Web Crypto wants an ArrayBuffer view; hand it one that is exactly the bytes we mean,
 * which a `Uint8Array` over a larger pooled buffer (as Node produces) otherwise is not.
 */
function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
