/**
 * @agentwares/x402 — 402 Payment Required helper + verifier interface.
 *
 * The 402 body advertises both rails. Both settle; only one of them settles without a person:
 *
 *   - **prepaid_credits (card, via Stripe)** — live. `payTo` is a self-serve endpoint that mints a
 *     prepaid key and hands back a Stripe Checkout URL, so an agent can go from a 402 to
 *     a paid call without a human. The verifier lives in `@agentwares/billing`
 *     (`createCreditsVerifier`), which is where the database and the Stripe client are.
 *   - **x402 (USDC on Base)** — live, and the only rail an unattended agent can complete.
 *     `createFacilitatorVerifier` checks the buyer's EIP-3009 signature with the PayAI
 *     facilitator and settles after the work succeeds. `StubVerifier` remains for a
 *     deployment with no receiving address, where it refuses rather than pretending.
 *
 * Nothing here holds funds.
 */

/**
 * `prepaid_credits` is deliberately not called `mpp`. MPP is the Machine Payments Protocol
 * (Stripe + Tempo, March 2026): pre-authorised spending sessions an agent settles on its own.
 * This rail is a Stripe Checkout page that funds a balance — a different thing, needing a
 * person. An agent that knows MPP and sees `mpp` will attempt MPP semantics and fail, so the
 * name stays free for a real implementation.
 */
export type PaymentRail = "x402" | "prepaid_credits";

export interface PaymentRequirement {
  rail: PaymentRail;
  /** decimal USD string, e.g. "0.05" */
  amountUsd: string;
  /** resource being paid for, usually the request URL or tool name */
  resource: string;
  description?: string;
  /** x402: network + asset; mpp: currency */
  network?: string;
  asset?: string;
  currency?: string;
  /** where to pay; absent while payments are not live */
  payTo?: string;
  /** seconds the quote is valid */
  maxTimeoutSeconds?: number;
  /**
   * True when settling this rail needs a person — today, a hosted Stripe Checkout card form.
   * An autonomous caller should pick a requirement without this flag; one that has it is
   * offered so an agent working alongside a human can hand the URL over rather than fail.
   */
  humanRequired?: boolean;
  /**
   * Discovery metadata for the x402 `bazaar` extension, when this resource declares one.
   * Carried per requirement rather than per verifier so a product with several priced routes
   * can describe each one; see BazaarExtension in ./facilitator.ts.
   */
  bazaar?: Record<string, unknown>;
}

/** Everything an agent needs to buy a key and fund it without a human. */
export interface SelfServe {
  /** POST here with no auth to get a key with a zero balance + a Checkout URL. */
  keysUrl: string;
  /** GET with the key to read the balance; POST to create another top-up. */
  creditsUrl?: string;
  /**
   * POST here with the key to fund it in USDC over x402 — the only top-up an unattended
   * agent can finish. `creditsUrl` ends at a hosted card page.
   */
  creditsX402Url?: string;
  /** credit pack sizes in USD */
  packsUsd: number[];
  /** header that makes a retried paid call charge only once */
  idempotencyHeader: "Idempotency-Key";
}

export interface PaymentRequiredBody {
  code: "PAYMENT_REQUIRED";
  cause: string;
  fix: string;
  retryable: true;
  priceUsd: number;
  accepts: PaymentRequirement[];
  /** true while neither rail can actually be settled */
  comingSoon: boolean;
  /** how to pay today: API key + prepaid credits */
  alternatives: string[];
  /** present once the card rail is live: the whole no-human purchase path */
  selfServe?: SelfServe;
  /**
   * x402 v2 extensions. `bazaar` is discovery metadata a client is expected to echo back in
   * its payment payload; without that echo the facilitator will not catalog the resource, so
   * a resource that omits this is payable but permanently unlistable.
   */
  extensions?: Record<string, unknown>;
}

export interface PaymentRequiredResponse {
  status: 402;
  headers: Record<string, string>;
  body: PaymentRequiredBody;
}

export interface BuildPaymentRequiredOptions {
  resource: string;
  priceUsd: number;
  description?: string;
  /** set once a rail can actually be settled (drops `comingSoon`) */
  live?: boolean;
  /** x402 rail: the USDC address payment is sent to. Unset = the rail is not advertised. */
  payTo?: string;
  /** CAIP-2 chain for the x402 rail; Base mainnet unless the receive address lives elsewhere. */
  network?: string;
  /** prepaid_credits rail: the URL that takes a card and funds a balance. */
  creditsPayTo?: string;
  signupUrl?: string;
  /** the no-human purchase path; included in the body when the card rail is live */
  selfServe?: SelfServe;
  /**
   * Discovery metadata for the x402 `bazaar` extension. Advertised in the 402 so a client
   * can echo it; see BazaarExtension in ./facilitator.ts for why that echo is the whole
   * mechanism.
   */
  bazaar?: Record<string, unknown>;
  /**
   * True when this resource really does answer `sample=true` free and keyless.
   *
   * The 402's `fix` prose used to promise one unconditionally, which was a lie on every
   * product without sample mode and absurd on a credit top-up. An agent that believes it
   * spends a call finding out.
   */
  sampleMode?: boolean;
}

/** Base mainnet. The CDP facilitator also settles Polygon, Arbitrum, World and Solana. */
export const DEFAULT_X402_NETWORK = "eip155:8453";

export const X402_HEADER = "X-Payment-Requirements";
export const X402_REQUIRED_HEADER = "PAYMENT-REQUIRED";

function toAmount(priceUsd: number): string {
  if (!Number.isFinite(priceUsd) || priceUsd < 0)
    throw new Error("priceUsd must be a non-negative number");
  return priceUsd.toFixed(6).replace(/0+$/, "").replace(/\.$/, ".0");
}

/** Build the 402 response (status, headers, JSON body) for a paid resource. */
export function buildPaymentRequired(opts: BuildPaymentRequiredOptions): PaymentRequiredResponse {
  const amountUsd = toAmount(opts.priceUsd);
  // `accepts` is a promise that the rail can be settled, so a rail with nowhere to send the
  // money is left out entirely. The x402 entry used to be advertised with `payTo: undefined`
  // while no CDP account existed: an agent that picked it had no address to pay and burned a
  // retry on a method we could never have honoured.
  const creditsPayTo = opts.creditsPayTo ?? opts.selfServe?.keysUrl;
  const accepts: PaymentRequirement[] = [];
  if (opts.payTo) {
    accepts.push({
      rail: "x402",
      amountUsd,
      resource: opts.resource,
      description: opts.description,
      network: opts.network ?? DEFAULT_X402_NETWORK,
      asset: "USDC",
      payTo: opts.payTo,
      maxTimeoutSeconds: 300,
      ...(opts.bazaar ? { bazaar: opts.bazaar } : {}),
    });
  }
  if (creditsPayTo) {
    accepts.push({
      rail: "prepaid_credits",
      amountUsd,
      resource: opts.resource,
      description: opts.description,
      currency: "usd",
      payTo: creditsPayTo,
      maxTimeoutSeconds: 300,
      // funding a balance ends at a hosted Stripe Checkout page, which an agent cannot fill in
      humanRequired: true,
    });
  }
  const live = opts.live === true;
  const selfServe = opts.selfServe;
  // Say plainly which step a machine can do and which one it cannot. An agent that reads
  // "pay the card form" as an instruction to itself will loop: the Checkout URL is a hosted
  // web page.
  //
  // Order matters more than it looks. Many agents act on `fix` prose rather than parsing
  // `accepts`, so whatever is named first is what gets attempted. This text used to describe
  // only the card rail — the one that needs a person — while the USDC rail settled fine and
  // went unmentioned, which told every unattended caller to give up in front of a working
  // checkout. Lead with the rail that needs nobody.
  const x402Rail = accepts.find((a) => a.rail === "x402" && a.payTo);
  const usdcFix = x402Rail
    ? `Pay in USDC with no account and no human: take the \`accepts\` entry with ` +
      `\`rail: "x402"\`, sign an EIP-3009 transferWithAuthorization for ${x402Rail.amountUsd} ` +
      `USDC to ${x402Rail.payTo} on ${x402Rail.network}, and retry with it base64 in the ` +
      `X-PAYMENT header. The facilitator submits the transfer, so you need USDC and no gas. `
    : "";
  // Only when there is one. This was unconditional, so every 402 in the portfolio promised a
  // free sample — including products that have none, and including the credit top-up endpoint,
  // where it read as an offer of free credit.
  const sampleFix = opts.sampleMode
    ? "Free first: retry with sample=true — no key, no payment. "
    : "";
  const cardFix = selfServe
    ? `Or pay by card: POST ${selfServe.keysUrl} (no auth, no signup) returns a key and a Stripe ` +
      `Checkout URL. Funding that key needs a person at a browser; if you are running unattended, ` +
      `surface the URL to your operator rather than retrying, or use the USDC rail above. Once ` +
      `funded, send Authorization: Bearer <key>, plus Idempotency-Key so a repeated call is ` +
      `charged once.`
    : "";
  const liveFix =
    usdcFix || cardFix
      ? `${sampleFix}${usdcFix}${cardFix}`.trim()
      : "Retry with a PAYMENT header satisfying one of `accepts`, or send an API key with credit balance.";
  const body: PaymentRequiredBody = {
    code: "PAYMENT_REQUIRED",
    cause: live
      ? `This call costs $${amountUsd}. No valid payment or credit was presented.`
      : `This call costs $${amountUsd}. Pay-per-call (x402 / Stripe MPP) is coming soon; use an API key with prepaid credits.`,
    fix: live
      ? liveFix
      : `Create an API key${opts.signupUrl ? ` at ${opts.signupUrl}` : ""} and retry with Authorization: Bearer <key>. Try the free sample mode first.`,
    retryable: true,
    priceUsd: opts.priceUsd,
    accepts,
    comingSoon: !live,
    alternatives: [
      ...(creditsPayTo ? ["api_key_credits"] : []),
      ...(opts.sampleMode ? ["sample_mode"] : []),
    ],
    ...(selfServe ? { selfServe } : {}),
    ...(opts.bazaar ? { extensions: { bazaar: opts.bazaar } } : {}),
  };
  // The machine-readable header carries the extension too: a client that reads only the
  // header, which the spec allows, still sees what it has to echo.
  const encoded = JSON.stringify({
    x402Version: 2,
    accepts,
    resource: opts.resource,
    ...(opts.bazaar ? { extensions: { bazaar: opts.bazaar } } : {}),
  });
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "WWW-Authenticate": `Payment realm="agentwares", methods="x402 prepaid_credits", price="${amountUsd} USD"`,
    [X402_HEADER]: encoded,
    [X402_REQUIRED_HEADER]: btoa(encoded),
    "Cache-Control": "no-store",
  };
  return { status: 402, headers, body };
}

export interface VerifyResult {
  ok: boolean;
  rail?: PaymentRail;
  receipt?: unknown;
  reason?: string;
}

/** Given a request, decide whether it carries a valid payment. */
export interface PaymentVerifier {
  verify(request: Request, requirement: PaymentRequirement): Promise<VerifyResult>;
  /**
   * Optional second step for rails where verifying and taking the money are separate acts.
   * x402 works this way: checking a signature is free, submitting the transfer is not, so
   * settlement happens only after the paid work succeeded and a failed call is never
   * charged. Rails that debit during `verify` (prepaid credits) leave this unimplemented
   * and refund through `onPaidFailure` instead.
   */
  settle?(verified: VerifyResult): Promise<{ ok: boolean; reason?: string }>;
}

/**
 * Never accepts a payment, never touches funds. Still the verifier for the x402/USDC rail
 * (no CDP account yet); the card rail uses `createCreditsVerifier` from @agentwares/billing.
 */
export class StubVerifier implements PaymentVerifier {
  async verify(request: Request, requirement: PaymentRequirement): Promise<VerifyResult> {
    const hasHeader = request.headers.has("PAYMENT") || request.headers.has("X-PAYMENT");
    return {
      ok: false,
      rail: requirement.rail,
      reason: hasHeader
        ? "payments are not live yet (phase 2: wallet). Use an API key with credits."
        : "no payment header present",
    };
  }
}

/** Convenience: a Web-standard Response for the 402. */
export function paymentRequiredResponse(opts: BuildPaymentRequiredOptions): Response {
  const r = buildPaymentRequired(opts);
  return new Response(JSON.stringify(r.body), { status: r.status, headers: r.headers });
}

export * from "./facilitator.js";
