/**
 * The key directory at `/.well-known/http-message-signatures-directory`.
 *
 * The response is a JWKS, and it signs itself: one HTTP Message Signature per published
 * key, covering `@authority` from the request that fetched it. That is what stops someone
 * re-serving your key set under their own domain and registering as you.
 */
import {
  buildSignatureBase,
  serializeSignatureParams,
  type ComponentIdentifier,
  type MessageContext,
} from "./base.js";
import { invalid } from "./errors.js";
import {
  DIRECTORY_MEDIA_TYPE,
  DIRECTORY_PATH,
  DIRECTORY_TAG,
  ED25519_ALG,
  signBytes,
  type Ed25519PublicJwk,
  type SigningKey,
} from "./keys.js";
import { base64Encode, serializeDictionary, type SfParams } from "./sfv.js";

/**
 * Which covered components the directory response signature uses.
 *
 * - `"cloudflare"` — `("@authority";req)`, exactly what Cloudflare's Web Bot Auth docs
 *   require. This is the default, because Cloudflare is the verifier that gates the
 *   Verified Bots programme today.
 * - `"ietf-draft"` — `("@authority";req "content-digest")`, which
 *   draft-ietf-webbotauth-httpsig-protocol-00 Appendix B.1 makes a MUST. Covering the
 *   digest also stops the key set being swapped under a captured signature.
 *
 * `Content-Digest` is sent in both profiles; only the profile decides whether it is signed.
 */
export type DirectoryProfile = "cloudflare" | "ietf-draft";

/** A key to publish, with the optional validity window the draft's example shows. */
export interface DirectoryKey {
  key: SigningKey;
  /** Not-before, seconds since the epoch. */
  nbf?: number;
  /** Expiry, seconds since the epoch. */
  exp?: number;
}

export interface DirectoryOptions {
  profile?: DirectoryProfile;
  /** `created`, seconds since the epoch. Defaults to now. */
  created?: number;
  /** Absolute `expires`, seconds since the epoch. Overrides `expiresIn`. */
  expires?: number;
  /**
   * Seconds of validity for the response signature. Defaults to 7 days: the draft's
   * Appendix C.8 warns that a short expiry here buys nothing and costs availability.
   */
  expiresIn?: number;
  /** `nonce`. Omitted by default — a directory response signature has no replay window to close. */
  nonce?: string;
  /** Include `alg="ed25519"`. Defaults to true. */
  includeAlg?: boolean;
  /** `Cache-Control` on the response. Defaults to `max-age=86400`; pass `false` to omit. */
  cacheControl?: string | false;
  /** Prefix for signature labels, which become `sig1`, `sig2`, … Defaults to `sig`. */
  labelPrefix?: string;
}

const DEFAULT_EXPIRES_IN = 7 * 24 * 60 * 60;

/** Serialize the JWKS exactly as it will be sent. The bytes are what `Content-Digest` covers. */
export function directoryBody(keys: Array<SigningKey | DirectoryKey>): string {
  const jwks = {
    keys: keys.map((entry) => {
      const { key, nbf, exp } = normalizeKey(entry);
      const jwk: Ed25519PublicJwk = {
        kty: "OKP",
        crv: "Ed25519",
        // The draft: when a JWK at the well-known URI carries `kid` it MUST be the
        // thumbprint, so a verifier can select by `keyid` without trusting the label.
        kid: key.keyid,
        x: key.publicJwk.x,
        use: "sig",
      };
      if (nbf !== undefined) jwk.nbf = nbf;
      if (exp !== undefined) jwk.exp = exp;
      return jwk;
    }),
  };
  return JSON.stringify(jwks);
}

/** `sha-256=:…:`, the RFC 9530 Content-Digest field value for `body`. */
export async function contentDigest(body: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
  return `sha-256=:${base64Encode(new Uint8Array(digest))}:`;
}

/**
 * Build the signed key-directory response for an incoming request.
 *
 * The response must be generated per request: `@authority` is taken from the request that
 * fetched the directory, which is what binds the key set to your domain.
 */
export async function signedDirectoryResponse(
  request: Request,
  keys: Array<SigningKey | DirectoryKey>,
  options: DirectoryOptions = {},
): Promise<Response> {
  if (keys.length === 0) {
    throw invalid(
      "INVALID_INPUT",
      "the key directory would be empty",
      "Publish at least one Ed25519 key; a directory with no keys verifies nothing.",
    );
  }

  const profile = options.profile ?? "cloudflare";
  const body = directoryBody(keys);
  const digest = await contentDigest(body);
  const created = options.created ?? Math.floor(Date.now() / 1000);
  const expires = options.expires ?? created + (options.expiresIn ?? DEFAULT_EXPIRES_IN);
  if (expires <= created) {
    throw invalid(
      "INVALID_INPUT",
      `expires (${expires}) is not after created (${created})`,
      "Give the directory signature a long lifetime; draft Appendix C.8 recommends well beyond the cache lifetime.",
    );
  }

  const components: ComponentIdentifier[] = [{ name: "@authority", params: [["req", true]] }];
  if (profile === "ietf-draft") components.push({ name: "content-digest" });

  const headers = new Headers({
    "content-type": DIRECTORY_MEDIA_TYPE,
    "content-digest": digest,
  });
  const cacheControl = options.cacheControl ?? "max-age=86400";
  if (cacheControl !== false) headers.set("cache-control", cacheControl);

  const context: MessageContext = {
    request: { method: request.method, url: request.url, headers: request.headers },
    response: { status: 200, headers },
  };

  const labelPrefix = options.labelPrefix ?? "sig";
  const inputs: string[] = [];
  const signatures: Array<[string, { value: Uint8Array; params: SfParams }]> = [];

  for (const [index, entry] of keys.entries()) {
    const { key } = normalizeKey(entry);
    const label = `${labelPrefix}${index + 1}`;
    const params: SfParams = [
      ["created", created],
      ["keyid", key.keyid],
    ];
    if (options.includeAlg !== false) params.push(["alg", ED25519_ALG]);
    params.push(["expires", expires]);
    if (options.nonce !== undefined) params.push(["nonce", options.nonce]);
    params.push(["tag", DIRECTORY_TAG]);

    const base = buildSignatureBase(components, params, context);
    const signature = await signBytes(key, new TextEncoder().encode(base));
    // The Signature-Input value is a dictionary member whose value is the same inner list
    // that ends the signature base, so serialize it from the same function.
    inputs.push(`${label}=${serializeSignatureParams(components, params)}`);
    signatures.push([label, { value: signature, params: [] }]);
  }

  headers.set("signature-input", inputs.join(", "));
  headers.set("signature", serializeDictionary(signatures));

  return new Response(body, { status: 200, headers });
}

/**
 * A ready-made handler: answers the well-known path with a signed directory and 404s
 * everything else, so an app can mount it without repeating the path.
 */
export function directoryHandler(
  keys: Array<SigningKey | DirectoryKey>,
  options?: DirectoryOptions,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    if (new URL(request.url).pathname !== DIRECTORY_PATH) {
      return new Response("not found", { status: 404 });
    }
    return signedDirectoryResponse(request, keys, options);
  };
}

function normalizeKey(entry: SigningKey | DirectoryKey): DirectoryKey {
  return "key" in entry ? entry : { key: entry };
}
