/**
 * Published test vectors, transcribed from the specs with the RFC 8792 line wrapping undone.
 *
 * - `RFC9421_ED25519_JWK` and `B_2_6` come from RFC 9421 Appendix B.1.4 and B.2.6.
 * - `E_2_1`, `E_2_2` and `E_2_3` come from Appendix E.2 of
 *   draft-ietf-webbotauth-httpsig-protocol-00 (1 September 2026), which reuses the same key.
 *
 * Ed25519 is deterministic (RFC 8032), so a correct implementation reproduces these
 * signature bytes exactly, not merely a signature that happens to verify.
 */
import type { Ed25519PrivateJwk } from "../keys.js";

/** RFC 9421 Appendix B.1.4, "Example Ed25519 Test Key" (test-key-ed25519). */
export const RFC9421_ED25519_JWK: Ed25519PrivateJwk = {
  kty: "OKP",
  crv: "Ed25519",
  d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

/** The RFC 7638 / RFC 8037 Appendix A.3 thumbprint of the key above, used as `keyid`. */
export const RFC9421_ED25519_THUMBPRINT = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

/** RFC 9421 Appendix B.2, "test-request". */
export const TEST_REQUEST = {
  method: "POST",
  url: "https://example.com/foo?param=Value&Pet=dog",
  headers: {
    Host: "example.com",
    Date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "Content-Type": "application/json",
    "Content-Digest":
      "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
    "Content-Length": "18",
  },
} as const;

/** RFC 9421 Appendix B.2.6, "Signing a Request Using ed25519". */
export const B_2_6 = {
  label: "sig-b26",
  base: [
    '"date": Tue, 20 Apr 2021 02:07:55 GMT',
    '"@method": POST',
    '"@path": /foo',
    '"@authority": example.com',
    '"content-type": application/json',
    '"content-length": 18',
    '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
  ].join("\n"),
  signature:
    "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
} as const;

/** Appendix E.2.1: dictionary `Signature-Agent`, the form the current draft mandates. */
export const E_2_1 = {
  label: "sig2",
  signatureAgentHeader: 'agent2="https://signature-agent.test"',
  nonce: "n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==",
  created: 1735689600,
  expires: 4889289600,
  base: [
    '"@authority": example.com',
    '"signature-agent";key="agent2": "https://signature-agent.test"',
    '"@signature-params": ("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"',
  ].join("\n"),
  signature:
    "RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==",
} as const;

/**
 * Appendix E.2.2: the legacy sf-string `Signature-Agent`. This is byte for byte the example
 * in Cloudflare's own Web Bot Auth documentation, and the form its verifier accepts today.
 */
export const E_2_2 = {
  label: "sig2",
  signatureAgentHeader: '"https://signature-agent.test"',
  directory: "https://signature-agent.test",
  nonce: "e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==",
  created: 1735689600,
  expires: 1735693200,
  base: [
    '"@authority": example.com',
    '"signature-agent": "https://signature-agent.test"',
    '"@signature-params": ("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"',
  ].join("\n"),
  signature:
    "jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==",
} as const;

/** Appendix E.2.3: the signed directory response (the Appendix B possession proof). */
export const E_2_3 = {
  label: "binding",
  authority: "signature-agent.test",
  url: "https://signature-agent.test/.well-known/http-message-signatures-directory",
  body: '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}',
  contentDigest: "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:",
  created: 1735689600,
  expires: 4889289600,
  base: [
    '"@authority";req: signature-agent.test',
    '"content-digest": sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:',
    '"@signature-params": ("@authority";req "content-digest");created=1735689600;expires=4889289600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";tag="http-message-signatures-directory"',
  ].join("\n"),
  signature:
    "l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==",
} as const;

/** RFC 9421 Figure 1, the non-normative example signature base in section 2.5. */
export const RFC9421_FIGURE_1 = [
  '"@method": POST',
  '"@authority": example.com',
  '"@path": /foo',
  '"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
  '"content-length": 18',
  '"content-type": application/json',
  '"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"',
].join("\n");
