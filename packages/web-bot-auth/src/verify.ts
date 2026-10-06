/**
 * Verification, so the tests can prove a signature this library produces actually
 * validates rather than merely being well-formed — and so a service can check inbound
 * Web Bot Auth signatures itself.
 */
import {
  buildSignatureBase,
  serializeComponentIdentifier,
  type ComponentIdentifier,
  type MessageContext,
} from "./base.js";
import { contentDigest } from "./directory.js";
import {
  DIRECTORY_TAG,
  REQUEST_TAG,
  importVerifyingKey,
  jwkThumbprint,
  verifyBytes,
  type Ed25519PublicJwk,
  type VerifyingKey,
} from "./keys.js";
import {
  isInnerList,
  parseDictionary,
  parseItem,
  SfToken,
  type SfInnerList,
  type SfMemberValue,
  type SfParams,
} from "./sfv.js";

export type VerifyFailureCode =
  /** No `Signature` / `Signature-Input` pair carrying the expected tag. */
  | "NO_SIGNATURE"
  /** A header did not parse, or carried something the signature base cannot use. */
  | "MALFORMED"
  /** `keyid` did not resolve to a key. */
  | "UNKNOWN_KEY"
  /** `expires` has passed, or `created` is in the future. */
  | "STALE"
  /** A component the profile requires was not covered. */
  | "MISSING_COMPONENT"
  /** `Content-Digest` does not match the body. */
  | "DIGEST_MISMATCH"
  /** The bytes did not verify under the resolved key. */
  | "BAD_SIGNATURE";

export interface VerifyFailure {
  ok: false;
  code: VerifyFailureCode;
  cause: string;
  fix: string;
  label?: string;
}

export interface VerifySuccess {
  ok: true;
  label: string;
  keyid: string;
  /** The `Signature-Agent` URL this signature covered, when it covered one. */
  signatureAgent?: string;
  created?: number;
  expires?: number;
  /** The covered components, as they were serialized into the signature base. */
  components: string[];
}

export type VerifyResult = VerifySuccess | VerifyFailure;

export type KeyResolver = (
  keyid: string,
) => Ed25519PublicJwk | undefined | Promise<Ed25519PublicJwk | undefined>;

export interface VerifyOptions {
  /**
   * The keys the directory publishes. Raw JWKs, or the `VerifyingKey`s that
   * `importVerifyingKey` returns — both work, because passing the second and getting
   * `UNKNOWN_KEY` back is a confusing way to learn about a type mismatch.
   */
  keys: Array<Ed25519PublicJwk | VerifyingKey> | KeyResolver;
  /** Seconds since the epoch. Defaults to now. */
  now?: number;
  /** Clock-skew tolerance in seconds. Defaults to 5. */
  tolerance?: number;
  /** Required `tag`. Defaults to `web-bot-auth`. */
  tag?: string;
  /** Only verify this label. */
  label?: string;
  /**
   * Require that the signature covers the `Signature-Agent` field. Defaults to true:
   * Cloudflare fails a message that carries the header without covering it.
   */
  requireSignatureAgent?: boolean;
}

const DEFAULT_TOLERANCE = 5;

/** Verify the Web Bot Auth signature on an inbound request. */
export async function verifyRequest(
  request: Request,
  options: VerifyOptions,
): Promise<VerifyResult> {
  const context: MessageContext = {
    request: { method: request.method, url: request.url, headers: request.headers },
  };
  return verifyMessage(request.headers, context, {
    ...options,
    tag: options.tag ?? REQUEST_TAG,
  });
}

export interface DirectoryVerifyOptions {
  now?: number;
  tolerance?: number;
  tag?: string;
  /**
   * Require that the signature covers `content-digest`, as
   * draft-ietf-webbotauth-httpsig-protocol-00 Appendix B.1 does. Cloudflare's documented
   * requirement is `@authority;req` alone, so this defaults to false.
   */
  requireContentDigest?: boolean;
}

export interface DirectoryVerifyResult {
  /** True when every published Ed25519 key carried a valid possession proof. */
  ok: boolean;
  /** Every key in the served JWKS. */
  keys: Ed25519PublicJwk[];
  /** Thumbprints whose possession proof validated. */
  proven: string[];
  failures: VerifyFailure[];
}

/**
 * Verify a key directory's own response signatures: the possession proof from Appendix B
 * of the protocol draft. `request` is the request that fetched `response`, because
 * `@authority;req` resolves against it.
 */
export async function verifyDirectoryResponse(
  request: Request,
  response: Response,
  options: DirectoryVerifyOptions = {},
): Promise<DirectoryVerifyResult> {
  const body = await response.clone().text();
  const failures: VerifyFailure[] = [];
  let keys: Ed25519PublicJwk[];
  try {
    keys = parseJwks(body);
  } catch (error) {
    return {
      ok: false,
      keys: [],
      proven: [],
      failures: [
        {
          ok: false,
          code: "MALFORMED",
          cause: `the directory body is not a JWKS (${String(error)})`,
          fix: 'Serve `{"keys":[…]}` with at least one OKP/Ed25519 key.',
        },
      ],
    };
  }

  const declared = response.headers.get("content-digest");
  if (declared !== null && declared !== (await contentDigest(body))) {
    failures.push({
      ok: false,
      code: "DIGEST_MISMATCH",
      cause: "the Content-Digest header does not match the response body",
      fix: "Compute the digest over the exact bytes you send, with no re-serialization in between.",
    });
    return { ok: false, keys, proven: [], failures };
  }

  const context: MessageContext = {
    request: { method: request.method, url: request.url, headers: request.headers },
    response: { status: response.status, headers: response.headers },
  };

  const proven: string[] = [];
  for (const jwk of keys) {
    const keyid = await jwkThumbprint(jwk);
    const result = await verifyMessage(response.headers, context, {
      keys: [jwk],
      now: options.now,
      tolerance: options.tolerance,
      tag: options.tag ?? DIRECTORY_TAG,
      requireSignatureAgent: false,
      requiredComponents: options.requireContentDigest
        ? ['"@authority";req', '"content-digest"']
        : ['"@authority";req'],
    });
    if (result.ok) proven.push(keyid);
    else failures.push({ ...result, label: result.label ?? keyid });
  }

  return { ok: keys.length > 0 && proven.length === keys.length, keys, proven, failures };
}

interface InternalVerifyOptions extends VerifyOptions {
  /** Serialized component identifiers that must appear in the covered components. */
  requiredComponents?: string[];
}

async function verifyMessage(
  headers: Headers,
  context: MessageContext,
  options: InternalVerifyOptions,
): Promise<VerifyResult> {
  const inputHeader = headers.get("signature-input");
  const signatureHeader = headers.get("signature");
  if (inputHeader === null || signatureHeader === null) {
    return fail(
      "NO_SIGNATURE",
      "the message has no Signature-Input / Signature pair",
      "Attach all three headers: Signature-Agent, Signature-Input and Signature.",
    );
  }

  let inputs: Map<string, SfMemberValue>;
  let signatures: Map<string, SfMemberValue>;
  try {
    inputs = parseDictionary(inputHeader);
    signatures = parseDictionary(signatureHeader);
  } catch (error) {
    return fail(
      "MALFORMED",
      `Signature-Input or Signature did not parse (${String(error)})`,
      "Both are structured-field dictionaries; check the quoting and the commas.",
    );
  }

  const tag = options.tag ?? REQUEST_TAG;
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE;
  let lastFailure: VerifyFailure | undefined;
  let candidates = 0;

  for (const [label, member] of inputs) {
    if (options.label !== undefined && label !== options.label) continue;
    if (!isInnerList(member)) continue;
    if (stringParam(member.params, "tag") !== tag) continue;
    candidates += 1;

    const result = await verifyOne(label, member, signatures, context, {
      ...options,
      tag,
      now,
      tolerance,
    });
    if (result.ok) return result;
    lastFailure = result;
  }

  if (candidates === 0) {
    return fail(
      "NO_SIGNATURE",
      `no signature carries tag="${tag}"`,
      `Set tag="${tag}" in Signature-Input; a verifier ignores signatures tagged for another protocol.`,
    );
  }
  return lastFailure ?? fail("BAD_SIGNATURE", "no signature verified", "Re-sign the message.");
}

async function verifyOne(
  label: string,
  member: SfInnerList,
  signatures: Map<string, SfMemberValue>,
  context: MessageContext,
  options: InternalVerifyOptions & { tag: string; now: number; tolerance: number },
): Promise<VerifyResult> {
  const signatureMember = signatures.get(label);
  if (!signatureMember || isInnerList(signatureMember)) {
    return fail(
      "MALFORMED",
      `Signature has no byte-sequence member "${label}"`,
      "Every Signature-Input label needs a matching Signature member.",
      label,
    );
  }
  const signature = signatureMember.value;
  if (!(signature instanceof Uint8Array)) {
    return fail(
      "MALFORMED",
      `Signature member "${label}" is not a byte sequence`,
      "Serialize the signature as `label=:base64:`.",
      label,
    );
  }

  const components: ComponentIdentifier[] = [];
  for (const item of member.items) {
    if (typeof item.value !== "string") {
      return fail(
        "MALFORMED",
        "a covered component is not a string",
        'Component identifiers are sf-strings, e.g. "@authority".',
        label,
      );
    }
    components.push({ name: item.value, params: item.params });
  }

  const created = numberParam(member.params, "created");
  const expires = numberParam(member.params, "expires");
  if (created === undefined || expires === undefined) {
    return fail(
      "MALFORMED",
      "the signature is missing `created` or `expires`",
      "Web Bot Auth requires both; without `expires` the signature never ages out.",
      label,
    );
  }
  if (created > options.now + options.tolerance) {
    return fail(
      "STALE",
      `created (${created}) is in the future`,
      "Fix the signer's clock; a future-dated signature is rejected like a not-yet-valid certificate.",
      label,
    );
  }
  if (expires < options.now - options.tolerance) {
    return fail(
      "STALE",
      `the signature expired at ${expires}`,
      "Sign closer to send time, or widen `expiresIn`; 60 seconds is the usual window.",
      label,
    );
  }

  const serialized = components.map(serializeComponentIdentifier);
  const required = options.requiredComponents ?? defaultRequiredComponents(options, serialized);
  for (const requirement of required) {
    if (!serialized.includes(requirement)) {
      return fail(
        "MISSING_COMPONENT",
        `the signature does not cover ${requirement}`,
        `Add ${requirement} to the covered components.`,
        label,
      );
    }
  }

  const keyid = stringParam(member.params, "keyid");
  if (keyid === undefined) {
    return fail(
      "MALFORMED",
      "the signature has no `keyid`",
      "Set `keyid` to the base64url JWK thumbprint of the signing key.",
      label,
    );
  }
  const jwk = await resolveKey(options.keys, keyid);
  if (!jwk) {
    return fail(
      "UNKNOWN_KEY",
      `no key published under keyid "${keyid}"`,
      "Publish the key in the directory, or wait for the verifier's cached copy to refresh.",
      label,
    );
  }

  let base: string;
  try {
    base = buildSignatureBase(components, member.params, context);
  } catch (error) {
    return fail(
      "MALFORMED",
      `the signature base could not be rebuilt (${String(error)})`,
      "Only sign components the verifier can resolve from the message it receives.",
      label,
    );
  }

  // A resolver can hand back anything — a JWK from a fetched directory is untrusted input,
  // so a bad one has to become a verification failure, never an exception.
  let key: VerifyingKey;
  try {
    key = await importVerifyingKey(jwk);
  } catch (error) {
    return fail(
      "UNKNOWN_KEY",
      `keyid "${keyid}" resolved to an unusable key (${String(error)})`,
      "Publish an OKP/Ed25519 JWK whose `kid`, if present, is its RFC 7638 thumbprint.",
      label,
    );
  }
  if (key.keyid !== keyid) {
    return fail(
      "UNKNOWN_KEY",
      `keyid "${keyid}" is not the thumbprint of the resolved key`,
      "Select keys by RFC 7638 thumbprint, not by an operator-chosen label.",
      label,
    );
  }

  const valid = await verifyBytes(key, new TextEncoder().encode(base), signature);
  if (!valid) {
    return fail(
      "BAD_SIGNATURE",
      "the signature did not verify over the rebuilt base",
      "Check that every covered component reaches the verifier byte for byte, unchanged by intermediaries.",
      label,
    );
  }

  return {
    ok: true,
    label,
    keyid,
    signatureAgent: signatureAgentValue(context, components, label),
    created,
    expires,
    components: serialized,
  };
}

/** The draft requires at least `@authority` or `@target-uri`; Cloudflare also wants `signature-agent`. */
function defaultRequiredComponents(options: InternalVerifyOptions, serialized: string[]): string[] {
  const required: string[] = [];
  if (!serialized.includes('"@authority"') && !serialized.includes('"@target-uri"')) {
    required.push('"@authority"');
  }
  if (options.requireSignatureAgent !== false) {
    const covered = serialized.some((identifier) => identifier.startsWith('"signature-agent"'));
    if (!covered) required.push('"signature-agent"');
  }
  return required;
}

function signatureAgentValue(
  context: MessageContext,
  components: ComponentIdentifier[],
  label: string,
): string | undefined {
  if (!components.some((component) => component.name === "signature-agent")) return undefined;
  const raw = context.request.headers.get("signature-agent");
  if (raw === null) return undefined;
  try {
    // The legacy form is a bare String Item; the current draft's form is a Dictionary
    // keyed by the signature label. They are distinguishable on the wire by the quote.
    if (raw.trimStart().startsWith('"')) {
      const item = parseItem(raw);
      return typeof item.value === "string" ? item.value : undefined;
    }
    const member = parseDictionary(raw).get(label);
    if (!member || isInnerList(member)) return undefined;
    return typeof member.value === "string" ? member.value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A `VerifyingKey` carries its JWK, so accept either.
 *
 * `importVerifyingKey` is exported, and doing the natural thing — import the key, then hand it
 * to `verifyRequest` — used to fail with `UNKNOWN_KEY`, which reads as "the directory does not
 * publish this key" rather than "you passed the wrong shape". Exporting a function whose
 * output the main entry point rejects is a trap; this closes it.
 */
function asJwk(key: Ed25519PublicJwk | VerifyingKey): Ed25519PublicJwk | undefined {
  if ("publicJwk" in key) return key.publicJwk;
  return "kty" in key ? key : undefined;
}

async function resolveKey(
  keys: Array<Ed25519PublicJwk | VerifyingKey> | KeyResolver,
  keyid: string,
): Promise<Ed25519PublicJwk | undefined> {
  if (typeof keys === "function") return keys(keyid);
  for (const entry of keys) {
    const jwk = asJwk(entry);
    if (!jwk) continue;
    if (jwk.kid === keyid) return jwk;
    try {
      if ((await jwkThumbprint(jwk)) === keyid) return jwk;
    } catch {
      // A directory may publish key types this verifier does not handle; skip them.
    }
  }
  return undefined;
}

function parseJwks(body: string): Ed25519PublicJwk[] {
  const parsed: unknown = JSON.parse(body);
  if (typeof parsed !== "object" || parsed === null || !("keys" in parsed)) {
    throw new Error("no `keys` member");
  }
  const { keys } = parsed as { keys: unknown };
  if (!Array.isArray(keys)) throw new Error("`keys` is not an array");
  const out: Ed25519PublicJwk[] = [];
  for (const candidate of keys) {
    if (typeof candidate !== "object" || candidate === null) continue;
    const jwk = candidate as Partial<Ed25519PublicJwk>;
    // A directory may publish other key types; a verifier that only does Ed25519 skips them.
    if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string") {
      out.push(jwk as Ed25519PublicJwk);
    }
  }
  if (out.length === 0) throw new Error("no Ed25519 keys");
  return out;
}

function stringParam(params: SfParams, name: string): string | undefined {
  const found = params.find(([key]) => key === name);
  if (!found) return undefined;
  const value = found[1];
  if (typeof value === "string") return value;
  if (value instanceof SfToken) return value.value;
  return undefined;
}

function numberParam(params: SfParams, name: string): number | undefined {
  const found = params.find(([key]) => key === name);
  return found && typeof found[1] === "number" ? found[1] : undefined;
}

function fail(code: VerifyFailureCode, cause: string, fix: string, label?: string): VerifyFailure {
  return { ok: false, code, cause, fix, label };
}
