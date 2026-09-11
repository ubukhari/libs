export type WebBotAuthErrorCode =
  /** The caller passed something this library cannot sign or serialize. */
  | "INVALID_INPUT"
  /** A structured-field header could not be parsed per RFC 9651. */
  | "MALFORMED_FIELD"
  /** A covered component could not be resolved against the message (RFC 9421 section 2.5). */
  | "UNRESOLVABLE_COMPONENT"
  /** A JWK is not a usable Ed25519 key, or its `kid` disagrees with its thumbprint. */
  | "INVALID_KEY"
  /** Web Crypto rejected the key or the operation. */
  | "CRYPTO_ERROR";

/** The wire shape every error serialises to (`JSON.stringify(err)`). */
export interface WebBotAuthErrorShape {
  code: WebBotAuthErrorCode;
  /** What went wrong, in one sentence. */
  cause: string;
  /** What the caller can do about it. */
  fix: string;
  /** Whether the same call can reasonably be retried later. */
  retryable: boolean;
}

/** Structured error per CLAUDE.md ("Errors carry code, cause, fix, retryable"). */
export class WebBotAuthError extends Error implements WebBotAuthErrorShape {
  readonly code: WebBotAuthErrorCode;
  override readonly cause: string;
  readonly fix: string;
  readonly retryable: boolean;
  readonly source: unknown;

  constructor(shape: WebBotAuthErrorShape & { source?: unknown }) {
    super(`${shape.code}: ${shape.cause}`);
    this.name = "WebBotAuthError";
    this.code = shape.code;
    this.cause = shape.cause;
    this.fix = shape.fix;
    this.retryable = shape.retryable;
    this.source = shape.source;
  }

  toJSON(): WebBotAuthErrorShape {
    return { code: this.code, cause: this.cause, fix: this.fix, retryable: this.retryable };
  }
}

export function isWebBotAuthError(error: unknown): error is WebBotAuthError {
  return error instanceof WebBotAuthError;
}

/** Most failures here are deterministic: the same input fails the same way next time. */
export function invalid(
  code: WebBotAuthErrorCode,
  cause: string,
  fix: string,
  source?: unknown,
): WebBotAuthError {
  return new WebBotAuthError({ code, cause, fix, retryable: false, source });
}
