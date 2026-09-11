/**
 * Web Bot Auth: sign your agent's outbound HTTP requests with Ed25519 so a verifier can
 * tell who is calling, and serve the signed key directory that publishes the key.
 *
 * Implemented from draft-ietf-webbotauth-httpsig-protocol-00 (1 September 2026) and
 * RFC 9421 HTTP Message Signatures, with defaults chosen to match what Cloudflare's Web
 * Bot Auth verifier accepts today. See the README for where those two diverge.
 *
 * Web Crypto and the Fetch API only — no Node built-ins — so the signing path runs
 * unchanged on Vercel Functions, Cloudflare Workers, Deno and Node 20+.
 */
export {
  DIRECTORY_MEDIA_TYPE,
  DIRECTORY_PATH,
  DIRECTORY_TAG,
  ED25519_ALG,
  REQUEST_TAG,
  generateSigningKey,
  importSigningKey,
  importVerifyingKey,
  jwkThumbprint,
  publicJwkFrom,
  signBytes,
  verifyBytes,
  type Ed25519PrivateJwk,
  type Ed25519PublicJwk,
  type GeneratedSigningKey,
  type SigningKey,
  type VerifyingKey,
} from "./keys.js";

export {
  attachSignature,
  directoryOrigin,
  directoryUrl,
  signRequest,
  type SignatureAgentForm,
  type SignRequestOptions,
  type SignedRequestHeaders,
} from "./sign.js";

export {
  contentDigest,
  directoryBody,
  directoryHandler,
  signedDirectoryResponse,
  type DirectoryKey,
  type DirectoryOptions,
  type DirectoryProfile,
} from "./directory.js";

export {
  verifyDirectoryResponse,
  verifyRequest,
  type DirectoryVerifyOptions,
  type DirectoryVerifyResult,
  type KeyResolver,
  type VerifyFailure,
  type VerifyFailureCode,
  type VerifyOptions,
  type VerifyResult,
  type VerifySuccess,
} from "./verify.js";

export {
  buildSignatureBase,
  serializeComponentIdentifier,
  serializeSignatureParams,
  type ComponentIdentifier,
  type MessageContext,
  type RequestLike,
  type ResponseLike,
} from "./base.js";

export {
  SfToken,
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  parseDictionary,
  parseItem,
  serializeDictionary,
  serializeInnerList,
  serializeItem,
  serializeString,
  type BareItem,
  type SfInnerList,
  type SfItem,
  type SfMemberValue,
  type SfParams,
} from "./sfv.js";

export {
  WebBotAuthError,
  isWebBotAuthError,
  type WebBotAuthErrorCode,
  type WebBotAuthErrorShape,
} from "./errors.js";
