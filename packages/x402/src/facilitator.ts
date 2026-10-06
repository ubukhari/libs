/**
 * x402 verification and settlement through a facilitator.
 *
 * The facilitator is the only piece we do not run: it checks the buyer's signature and
 * submits the on-chain transfer. It never holds the money — USDC moves from the buyer
 * straight to `payTo`, an address we control — so this is not custody, and swapping
 * facilitators is changing one URL.
 *
 * PayAI (https://facilitator.payai.network) is the default because it needs no account,
 * no API key and no business relationship, which is the property that matters: an
 * account is a dependency that can be closed. Coinbase's CDP facilitator implements the
 * same two endpoints and can be dropped in by setting X402_FACILITATOR_URL.
 *
 * Verification is free and moves nothing. Settlement moves money, so it is deliberately
 * a separate call the caller makes only after the work succeeded — a failed call is then
 * never charged at all, which is better than charging and refunding.
 */
import type { PaymentRail, PaymentRequirement, PaymentVerifier, VerifyResult } from "./index.js";

export const PAYAI_FACILITATOR_URL = "https://facilitator.payai.network";

/** Circle's native USDC on Base mainnet. */
export const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/** USDC is a 6-decimal token everywhere it is issued. */
export const USDC_DECIMALS = 6;

/**
 * The EIP-712 domain of the asset being signed over. The facilitator needs it to reconstruct
 * the buyer's signature; without it, verification fails with
 * `invalid_exact_evm_missing_eip712_domain` and no payment can ever succeed.
 */
export const USDC_EIP712_DOMAIN = { name: "USD Coin", version: "2" };

/**
 * CAIP-2 to the short network names the **v1** verify/settle envelope uses.
 *
 * Only the v1 path needs this. v2 carries CAIP-2 end to end, which is one of the reasons to
 * prefer it: no translation layer between what the 402 advertises and what the facilitator
 * is told.
 */
const SHORT_NETWORK: Record<string, string> = {
  "eip155:8453": "base",
  "eip155:84532": "base-sepolia",
  "eip155:137": "polygon",
  "eip155:80002": "polygon-amoy",
  "eip155:42161": "arbitrum",
  "eip155:43114": "avalanche",
};

export function toShortNetwork(network: string): string {
  return SHORT_NETWORK[network] ?? network;
}

/**
 * The x402 `bazaar` extension — how a resource gets into a discovery catalog.
 *
 * There is no registration endpoint (the facilitator's OpenAPI description has only GETs
 * under /discovery). Settling a payment is necessary but **not** sufficient: the catalog is
 * built from this extension, which the resource server declares and the facilitator either
 * accepts or rejects. Without it a resource can be paid for indefinitely and never appear.
 *
 * The facilitator answers in an `EXTENSION-RESPONSES` header — base64 JSON keyed by
 * extension name, `{ bazaar: { status: "success" | "processing" | "rejected", … } }`. That
 * is the only direct feedback there is, so it is surfaced rather than discarded.
 */
export interface BazaarExtension {
  info: {
    input: Record<string, unknown>;
    output?: Record<string, unknown>;
  };
  /** JSON Schema (draft 2020-12) that validates `info`. Required by the extension. */
  schema: Record<string, unknown>;
  /** canonical route pattern for a parameterised path, e.g. `/v1/reserves/:symbol` */
  routeTemplate?: string;
}

export interface BazaarStatus {
  status?: "success" | "processing" | "rejected";
  rejectedReason?: string;
}

/**
 * A `bazaar` extension for a plain GET endpoint that answers JSON.
 *
 * The schema is deliberately permissive: its job is to be a valid draft 2020-12 document
 * that `info` satisfies, not to constrain a shape only we produce.
 */
export function httpGetBazaar(options: {
  queryParams?: Record<string, string>;
  pathParams?: Record<string, string>;
  routeTemplate?: string;
  outputExample?: unknown;
}): BazaarExtension {
  return {
    info: {
      input: {
        type: "http",
        method: "GET",
        ...(options.queryParams ? { queryParams: options.queryParams } : {}),
        ...(options.pathParams ? { pathParams: options.pathParams } : {}),
      },
      ...(options.outputExample !== undefined
        ? { output: { type: "json", example: options.outputExample } }
        : {}),
    },
    schema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      required: ["input"],
      properties: {
        input: { type: "object", required: ["type"], properties: { type: { type: "string" } } },
        output: { type: "object" },
      },
    },
    ...(options.routeTemplate ? { routeTemplate: options.routeTemplate } : {}),
  };
}

export interface FacilitatorVerifierOptions {
  /** the address USDC is paid to — ours, self-custody */
  payTo: string;
  /** CAIP-2 chain, e.g. eip155:8453 */
  network: string;
  /** token contract; defaults to native USDC on Base */
  asset?: string;
  /** defaults to PayAI */
  facilitatorUrl?: string;
  /** optional bearer token; PayAI works without one, some facilitators require it */
  apiKey?: string;
  /** EIP-712 domain of the asset; defaults to USDC's. Required by the facilitator. */
  assetDomain?: { name: string; version: string };
  /**
   * Decimals of that asset. Defaults to USDC's six.
   *
   * Set it whenever `asset` is set. The price is signed in atomic units, so the wrong decimals
   * do not fail loudly — they authorise a transfer for the wrong amount, off by a factor of a
   * thousand or a million in whichever direction hurts.
   */
  assetDecimals?: number;
  /**
   * Envelope to speak to the facilitator. Defaults to 2.
   *
   * Both settle money identically — the buyer's signature is the same either way — but only
   * v2 settlements appear in the Bazaar discovery catalog, so v1 is a rail that works and
   * cannot be found. Set it to 1 only for a facilitator that rejects v2.
   */
  protocolVersion?: 1 | 2;
  /**
   * Discovery metadata for this resource. Without it the resource is payable but not
   * listable — see BazaarExtension. Ignored on the v1 path, which has no extensions.
   */
  bazaar?: BazaarExtension;
  fetchImpl?: typeof fetch;
  log?: (message: string, data?: Record<string, unknown>) => void;
}

export interface SettleResult {
  ok: boolean;
  /** on-chain transaction hash when the transfer landed */
  transaction?: string;
  payer?: string;
  reason?: string;
  /** whether the facilitator catalogued the resource, when it said so */
  bazaar?: BazaarStatus;
}

/** What the buyer base64s into the X-PAYMENT header; forwarded to the facilitator verbatim. */
interface PaymentPayload {
  x402Version?: number;
  scheme?: string;
  network?: string;
  payload?: unknown;
  /** the client's echo of the server's extensions; its presence is what enables them */
  extensions?: Record<string, unknown>;
}

interface VerifyResponse {
  isValid?: boolean;
  invalidReason?: string;
  invalidMessage?: string;
  payer?: string;
}

interface SettleResponse {
  success?: boolean;
  errorReason?: string;
  errorMessage?: string;
  transaction?: string;
  network?: string;
  payer?: string;
}

/**
 * Decimal USD string to the token's atomic units.
 *
 * Done on the string rather than via floating point: 0.07 * 1e6 is 70000.00000000001, and
 * a price that rounds wrong is a payment the facilitator rejects for the wrong amount.
 */
export function toAtomicUnits(amountUsd: string, decimals = USDC_DECIMALS): string {
  const trimmed = amountUsd.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) throw new Error(`not a decimal amount: ${amountUsd}`);
  const [whole = "0", fraction = ""] = trimmed.split(".");
  if (fraction.length > decimals) {
    throw new Error(`${amountUsd} has more than ${decimals} decimal places`);
  }
  return `${whole}${fraction.padEnd(decimals, "0")}`.replace(/^0+(?=\d)/, "");
}

/** The buyer's payment, or undefined when the request carries none. */
function readPaymentHeader(request: Request): PaymentPayload | undefined {
  const raw = request.headers.get("X-PAYMENT") ?? request.headers.get("PAYMENT");
  if (!raw) return undefined;
  try {
    // base64 JSON per the spec; tolerate a bare JSON body from a hand-rolled client
    const text = raw.trim().startsWith("{") ? raw : new TextDecoder().decode(base64ToBytes(raw));
    return JSON.parse(text) as PaymentPayload;
  } catch {
    return undefined;
  }
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64.trim());
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export interface FacilitatorVerifier extends PaymentVerifier {
  settle(verified: VerifyResult): Promise<SettleResult>;
}

export function createFacilitatorVerifier(
  options: FacilitatorVerifierOptions,
): FacilitatorVerifier {
  const base = (options.facilitatorUrl ?? PAYAI_FACILITATOR_URL).replace(/\/+$/, "");
  const asset = options.asset ?? USDC_BASE;
  const doFetch = options.fetchImpl ?? fetch;
  const log = options.log ?? (() => undefined);
  const version = options.protocolVersion ?? 2;

  function requirementsFor(requirement: PaymentRequirement): Record<string, unknown> {
    // Without `extra` the facilitator cannot rebuild the signature and refuses every payment
    // with invalid_exact_evm_missing_eip712_domain.
    const extra = options.assetDomain ?? USDC_EIP712_DOMAIN;
    const amount = toAtomicUnits(requirement.amountUsd, options.assetDecimals);
    const maxTimeoutSeconds = requirement.maxTimeoutSeconds ?? 300;

    if (version === 2) {
      // v2 renamed maxAmountRequired to amount and carries CAIP-2 networks unchanged.
      //
      // `resource` is not in the v2 schema and the facilitator does not require it, but it is
      // the only thing that ties a settlement to a URL — a discovery catalog of resources
      // cannot list a payment that names no resource. It is accepted, so send it.
      return {
        scheme: "exact",
        network: options.network,
        amount,
        asset,
        payTo: options.payTo,
        maxTimeoutSeconds,
        resource: requirement.resource,
        description: requirement.description ?? "",
        mimeType: "application/json",
        extra,
      };
    }
    return {
      scheme: "exact",
      network: toShortNetwork(options.network),
      maxAmountRequired: amount,
      resource: requirement.resource,
      description: requirement.description ?? "",
      mimeType: "application/json",
      payTo: options.payTo,
      maxTimeoutSeconds,
      asset,
      extra,
    };
  }

  /**
   * The buyer's payload, restated in the envelope the facilitator accepts.
   *
   * v2 nests the terms the buyer agreed to as `accepted` *inside* the payload — that nesting
   * is the whole difference, and getting it wrong returns `invalid_payment_requirements:
   * ": Invalid input"`, which names no field. v1 instead flattens scheme and network next to
   * the payload.
   */
  function payloadFor(
    payment: PaymentPayload,
    accepted: Record<string, unknown>,
  ): Record<string, unknown> {
    if (version === 2) {
      return {
        x402Version: 2,
        // Not required alongside `accepted`, but the facilitator's own OpenAPI description
        // lists scheme and network as required on a payment payload, and the discovery
        // catalog records a network per resource. Sending them costs nothing.
        scheme: payment.scheme ?? "exact",
        network: options.network,
        // A payload-level `resource` OBJECT — a string here is rejected. Every catalogued
        // entry carries url, type, method, description and mimeType, which is exactly this
        // shape, so this is the most likely thing the catalog is built from.
        resource: {
          url: accepted["resource"],
          type: "http",
          method: "GET",
          description: accepted["description"],
          mimeType: accepted["mimeType"],
        },
        accepted,
        payload: payment.payload,
        // the client's echo, verbatim: the facilitator compares it against serverExtensions
        ...(payment.extensions ? { extensions: payment.extensions } : {}),
      };
    }
    return {
      x402Version: 1,
      scheme: payment.scheme ?? "exact",
      network: toShortNetwork(payment.network ?? options.network),
      payload: payment.payload,
    };
  }

  /**
   * v2 only: extensions the resource server declares.
   *
   * Sent **only when the client echoed one back**. Declaring an extension the client did not
   * echo is refused outright — `403 Extension validation failed: client must echo server
   * extensions` — so sending it unconditionally would turn every payment from an older client
   * into a refusal. Discovery is worth having; it is not worth failing a sale for.
   */
  function serverExtensions(payment: PaymentPayload, declared: unknown): Record<string, unknown> {
    const bazaar = declared ?? options.bazaar;
    if (version !== 2 || !bazaar) return {};
    if (!payment.extensions?.["bazaar"]) return {};
    return { serverExtensions: { bazaar } };
  }

  type Call<T> =
    { reached: true; body: T; bazaar?: BazaarStatus } | { reached: false; error: string };

  /** `EXTENSION-RESPONSES`: base64 JSON keyed by extension name. Absent on the v1 path. */
  function readBazaarStatus(headers: Headers): BazaarStatus | undefined {
    const raw = headers.get("extension-responses");
    if (!raw) return undefined;
    try {
      const text = new TextDecoder().decode(base64ToBytes(raw));
      return (JSON.parse(text) as Record<string, BazaarStatus>)["bazaar"];
    } catch {
      return undefined;
    }
  }

  async function call<T>(path: string, body: unknown): Promise<Call<T>> {
    try {
      const res = await doFetch(`${base}${path}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(options.apiKey ? { authorization: `Bearer ${options.apiKey}` } : {}),
        },
        body: JSON.stringify(body),
      });
      // Check the status before the body. A facilitator answering 500 or 403 can still return
      // JSON carrying `isValid` or `success`, and reading it regardless means an error page
      // decides whether we were paid. This rail must fail closed.
      if (!res.ok && res.status >= 500) {
        return { reached: false, error: `facilitator returned HTTP ${res.status}` };
      }
      const bazaar = readBazaarStatus(res.headers);
      // A rejected declaration is silent otherwise: payments keep working and the resource
      // simply never appears in the catalog, which is the failure that took longest to see.
      if (bazaar?.status === "rejected") {
        log("x402 bazaar listing rejected", { reason: bazaar.rejectedReason });
      }
      return { reached: true, body: (await res.json()) as T, ...(bazaar ? { bazaar } : {}) };
    } catch (err) {
      return { reached: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  return {
    /**
     * Checks the buyer's signature. Free, and moves nothing — call `settle` once the work
     * has actually succeeded.
     */
    async verify(request: Request, requirement: PaymentRequirement): Promise<VerifyResult> {
      const payment = readPaymentHeader(request);
      if (!payment) {
        return { ok: false, rail: "x402", reason: "no payment header present" };
      }
      const paymentRequirements = requirementsFor(requirement);
      const call1 = await call<VerifyResponse>("/verify", {
        x402Version: version,
        paymentPayload: payloadFor(payment, paymentRequirements),
        // v2 keeps this alongside the payload as well as inside it. PayAI rejects the body
        // outright without it, so it is not the redundancy it looks like.
        paymentRequirements,
        ...serverExtensions(payment, requirement.bazaar),
      });
      if (!call1.reached) {
        // Fail closed: an unreachable facilitator must never be read as a valid payment.
        log("x402 facilitator unreachable", { error: call1.error });
        return { ok: false, rail: "x402", reason: "payment facilitator unreachable" };
      }
      const verified = call1.body;
      if (!verified.isValid) {
        return {
          ok: false,
          rail: "x402",
          reason: verified.invalidReason
            ? `${verified.invalidReason}${verified.invalidMessage ? `: ${verified.invalidMessage}` : ""}`
            : "payment refused by the facilitator",
        };
      }
      return {
        ok: true,
        rail: "x402",
        // everything settle() needs, so it does not have to re-read the request
        receipt: {
          payment,
          paymentRequirements,
          payer: verified.payer,
          // settle() never sees the requirement again, so carry the declaration with it
          ...(requirement.bazaar ? { bazaar: requirement.bazaar } : {}),
        },
      };
    },

    /** Submits the transfer. Only call this once the paid work has succeeded. */
    async settle(verified: VerifyResult): Promise<SettleResult> {
      const receipt = verified.receipt as
        | {
            payment: PaymentPayload;
            paymentRequirements: Record<string, unknown>;
            bazaar?: unknown;
          }
        | undefined;
      if (!receipt?.payment) return { ok: false, reason: "nothing to settle" };
      const call2 = await call<SettleResponse>("/settle", {
        x402Version: version,
        paymentPayload: payloadFor(receipt.payment, receipt.paymentRequirements),
        paymentRequirements: receipt.paymentRequirements,
        ...serverExtensions(receipt.payment, receipt.bazaar),
      });
      if (!call2.reached) {
        log("x402 settlement failed to reach the facilitator", { error: call2.error });
        return { ok: false, reason: call2.error };
      }
      const result = call2.body;
      if (!result.success) {
        // The buyer already has the resource. Worth logging loudly: it is lost revenue,
        // not a failed request, and the caller should not turn it into an error.
        log("x402 settlement refused after the work was served", {
          reason: result.errorReason,
          message: result.errorMessage,
        });
        return {
          ok: false,
          reason: result.errorReason ?? "settlement refused",
          ...(result.payer ? { payer: result.payer } : {}),
        };
      }
      if (call2.bazaar) log("x402 bazaar listing", { ...call2.bazaar });
      // A settlement we cannot name cannot be made idempotent: the caller keys the credit on
      // this hash, and without one it would invent a fresh key per attempt and credit the same
      // authorisation again on every retry. Treat it as unsettled rather than as money.
      if (!result.transaction) {
        log("x402 settlement reported success with no transaction", { payer: result.payer });
        return {
          ok: false,
          reason:
            "the facilitator reported success but named no transaction, so the payment cannot be confirmed",
          ...(result.payer ? { payer: result.payer } : {}),
        };
      }
      return {
        ok: true,
        transaction: result.transaction,
        ...(result.payer ? { payer: result.payer } : {}),
        ...(call2.bazaar ? { bazaar: call2.bazaar } : {}),
      };
    },
  };
}

/**
 * One verifier over several rails: try each in turn, first acceptance wins.
 *
 * A caller presents whatever it has — a USDC payment header or a prepaid key — and should
 * not have to be told which rail the server prefers. Refusals are reported from the rail
 * that got furthest: "insufficient credit" is useful, "no payment header present" from a
 * rail the caller never intended to use is noise.
 *
 * `settle` dispatches on the rail that accepted, so a rail that already took its money
 * during verification is never asked to take it twice.
 */
export function createAnyVerifier(verifiers: readonly PaymentVerifier[]): PaymentVerifier {
  return {
    async verify(request: Request, requirement: PaymentRequirement): Promise<VerifyResult> {
      const refusals: VerifyResult[] = [];
      for (const verifier of verifiers) {
        const result = await verifier.verify(request, requirement);
        if (result.ok) return result;
        refusals.push(result);
      }
      const informative = refusals.find(
        (r) => r.reason && !/no payment header|no API key/i.test(r.reason),
      );
      return informative ?? refusals[0] ?? { ok: false, reason: "no payment presented" };
    },
    async settle(verified: VerifyResult) {
      const owner = verifiers.find(
        (v) => v.settle && verified.rail !== undefined && railOf(v) === verified.rail,
      );
      const settled = await owner?.settle?.(verified);
      if (settled) return settled;
      // No verifier owns this rail's settlement. That is correct for a rail which already took
      // its money during verification (prepaid credits), and a bug for anything else — so say
      // which, rather than reporting a success nobody performed.
      if (verified.rail === "prepaid_credits") return { ok: true };
      return {
        ok: false,
        reason: `nothing settles the ${verified.rail ?? "unknown"} rail on this deployment`,
      };
    },
  };
}

/** Which rail a verifier settles. Only the facilitator verifier settles anything today. */
function railOf(verifier: PaymentVerifier): PaymentRail | undefined {
  return "settle" in verifier && typeof verifier.settle === "function" ? "x402" : undefined;
}
