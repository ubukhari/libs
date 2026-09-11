/**
 * Signing an outbound request so a verifier — Cloudflare, today — can attribute it.
 *
 * A signed request carries exactly three headers (protocol draft section 5.2.5):
 * `Signature-Agent`, `Signature-Input` and `Signature`.
 */
import {
  buildSignatureBase,
  serializeSignatureParams,
  type ComponentIdentifier,
  type MessageContext,
} from "./base.js";
import { invalid } from "./errors.js";
import { DIRECTORY_PATH, ED25519_ALG, REQUEST_TAG, signBytes, type SigningKey } from "./keys.js";
import { base64Encode, serializeString, type SfParams } from "./sfv.js";

/**
 * How the `Signature-Agent` field is serialized.
 *
 * - `"sf-string"` — a bare String Item, `Signature-Agent: "https://bot.example"`, covered as
 *   `"signature-agent"`. This is what Cloudflare implements today and the only form it
 *   accepts: its docs state verification fails for "the dictionary form from later drafts".
 * - `"dictionary"` — `Signature-Agent: sig1="https://bot.example"`, covered as
 *   `"signature-agent";key="sig1"`. This is what draft-ietf-webbotauth-httpsig-protocol-00
 *   requires signers to send. Cloudflare rejects it as of this writing.
 */
export type SignatureAgentForm = "sf-string" | "dictionary";

export interface SignRequestOptions {
  /**
   * Where the key directory lives. Pass the https origin (`https://bot.example`) or the
   * full well-known URL; either way the header carries the origin, which is what the
   * `directory` discovery type requires.
   */
  directory: string;
  /** Signature label. Defaults to `sig1`. */
  label?: string;
  /** `created`, seconds since the epoch. Defaults to now. */
  created?: number;
  /** Absolute `expires`, seconds since the epoch. Overrides `expiresIn`. */
  expires?: number;
  /** Seconds of validity. Defaults to 60 — Cloudflare's recommended replay window. */
  expiresIn?: number;
  /** `nonce`. Defaults to 64 random bytes, base64. Pass `false` to omit it. */
  nonce?: string | false;
  /**
   * The full covered-components list. Defaults to `@authority` plus the `Signature-Agent`
   * field, which is the minimum both the draft and Cloudflare require.
   */
  components?: ComponentIdentifier[];
  /** Extra components appended to the default list. Ignored when `components` is given. */
  alsoCover?: ComponentIdentifier[];
  /** Defaults to `"sf-string"`, the form Cloudflare verifies. */
  signatureAgentForm?: SignatureAgentForm;
  /** Include `alg="ed25519"`. Defaults to true. */
  includeAlg?: boolean;
}

/** The three headers to attach to the request, lowercased and ready for `new Headers()`. */
export interface SignedRequestHeaders {
  "signature-agent": string;
  "signature-input": string;
  signature: string;
}

const DEFAULT_LABEL = "sig1";
const DEFAULT_EXPIRES_IN = 60;

/**
 * Sign `request` with `key` and return the headers to add. The request itself is not
 * mutated; `attachSignature` returns a copy carrying them.
 */
export async function signRequest(
  request: Request,
  key: SigningKey,
  options: SignRequestOptions,
): Promise<SignedRequestHeaders> {
  const label = options.label ?? DEFAULT_LABEL;
  const form = options.signatureAgentForm ?? "sf-string";
  const origin = directoryOrigin(options.directory);

  const signatureAgent =
    form === "dictionary" ? `${label}=${serializeString(origin)}` : serializeString(origin);

  const agentComponent: ComponentIdentifier =
    form === "dictionary"
      ? { name: "signature-agent", params: [["key", label]] }
      : { name: "signature-agent" };

  const components = options.components ?? [
    { name: "@authority" },
    agentComponent,
    ...(options.alsoCover ?? []),
  ];

  const created = options.created ?? Math.floor(Date.now() / 1000);
  const expires = options.expires ?? created + (options.expiresIn ?? DEFAULT_EXPIRES_IN);
  if (expires <= created) {
    throw invalid(
      "INVALID_INPUT",
      `expires (${expires}) is not after created (${created})`,
      "Give the signature a positive lifetime; 60 seconds is Cloudflare's recommendation.",
    );
  }

  // Parameter order is part of the signed bytes. This order matches both the Web Bot Auth
  // test vectors and the example in Cloudflare's documentation.
  const params: SfParams = [
    ["created", created],
    ["keyid", key.keyid],
  ];
  if (options.includeAlg !== false) params.push(["alg", ED25519_ALG]);
  params.push(["expires", expires]);
  const nonce = options.nonce === undefined ? randomNonce() : options.nonce;
  if (nonce !== false) params.push(["nonce", nonce]);
  params.push(["tag", REQUEST_TAG]);

  // The signature covers Signature-Agent, so it has to be in the message before the base
  // is built. The caller's request does not have it yet.
  const headers = new Headers(request.headers);
  headers.set("signature-agent", signatureAgent);
  const context: MessageContext = {
    request: { method: request.method, url: request.url, headers },
  };

  const base = buildSignatureBase(components, params, context);
  const signature = await signBytes(key, new TextEncoder().encode(base));

  return {
    "signature-agent": signatureAgent,
    "signature-input": `${label}=${serializeSignatureParams(components, params)}`,
    signature: `${label}=:${base64Encode(signature)}:`,
  };
}

/** Return a copy of `request` carrying the signature headers. */
export function attachSignature(request: Request, headers: SignedRequestHeaders): Request {
  const merged = new Headers(request.headers);
  for (const [name, value] of Object.entries(headers)) merged.set(name, value);
  return new Request(request, { headers: merged });
}

/**
 * The `directory` discovery type requires the ASCII serialization of an origin, so accept
 * the origin or the well-known URL and emit the origin either way.
 */
export function directoryOrigin(directory: string): string {
  let url: URL;
  try {
    url = new URL(directory);
  } catch (error) {
    throw invalid(
      "INVALID_INPUT",
      `"${directory}" is not a URL`,
      "Pass the https origin that serves your key directory, e.g. https://bot.example.",
      error,
    );
  }
  if (url.protocol !== "https:") {
    throw invalid(
      "INVALID_INPUT",
      `the key directory must be https, got "${url.protocol}//"`,
      "Serve the directory over HTTPS; Cloudflare fails verification for any other scheme.",
    );
  }
  if (url.pathname !== "/" && url.pathname !== "" && url.pathname !== DIRECTORY_PATH) {
    throw invalid(
      "INVALID_INPUT",
      `the Signature-Agent value must be an origin, but "${directory}" has the path "${url.pathname}"`,
      `Pass the origin, or the full ${DIRECTORY_PATH} URL; a verifier ignores anything else.`,
    );
  }
  if (url.search !== "" || url.hash !== "") {
    throw invalid(
      "INVALID_INPUT",
      `the Signature-Agent value must not carry a query or fragment ("${directory}")`,
      "Pass the bare origin, e.g. https://bot.example.",
    );
  }
  return url.origin;
}

/** The URL an operator registers with Cloudflare, and the URL a verifier fetches. */
export function directoryUrl(directory: string): string {
  return `${directoryOrigin(directory)}${DIRECTORY_PATH}`;
}

function randomNonce(): string {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  return base64Encode(bytes);
}
