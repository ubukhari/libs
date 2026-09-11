#!/usr/bin/env node
/**
 * Generate the Ed25519 key that signs this portfolio's Web Bot Auth requests.
 *
 *   pnpm --filter @agentwares/web-bot-auth build   # the script uses the built package
 *   pnpm --filter @agentwares/web-bot-auth keygen
 *
 * The private key is written straight to a 0600 file in ~/code/agentwares-secrets — the
 * same place, and the same rules, as the x402 wallet key documented in that directory's
 * README. It is never printed, never logged, and never passed as an argument.
 *
 * It does belong in the deployment's environment, as a secret: both halves of Web Bot Auth
 * run there. The prober signs its outbound requests, and the key directory signs its own
 * response — `@authority` comes from the request that fetched it, so the body cannot be
 * pre-signed. This file is the source of truth for that value; the deployment holds a copy.
 *
 * Only the thumbprint and the public JWK go to stdout. The thumbprint is the `keyid` that
 * appears in every signature, so it is public by design.
 *
 * Refuses to run if a key already exists. A key that has been registered with Cloudflare
 * cannot be silently replaced: rotation means publishing both keys and retiring the old
 * one, which the package's directory helpers support.
 */
import { chmodSync, existsSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SECRETS_DIR =
  process.env.AGENTWARES_SECRETS_DIR ?? resolve(homedir(), "code/agentwares-secrets");
const KEY_FILE = resolve(SECRETS_DIR, "web-bot-auth.key");
const JWK_FILE = resolve(SECRETS_DIR, "web-bot-auth.jwk");
const KEYID_FILE = resolve(SECRETS_DIR, "web-bot-auth.keyid");

let generateSigningKey;
try {
  ({ generateSigningKey } = await import(resolve(HERE, "../dist/index.js")));
} catch {
  console.error("refusing: the package is not built.");
  console.error("Run `pnpm --filter @agentwares/web-bot-auth build` first, so the keyid is");
  console.error("derived by the same code the test vectors cover.");
  process.exit(2);
}

if (!existsSync(SECRETS_DIR) || !statSync(SECRETS_DIR).isDirectory()) {
  console.error(`refusing: ${SECRETS_DIR} does not exist.`);
  console.error("Create it with mode 0700 first; it is deliberately outside the git repo.");
  process.exit(2);
}

if (existsSync(KEY_FILE)) {
  console.error(`refusing: ${KEY_FILE} already exists.`);
  console.error("Overwriting it orphans whatever is registered against the old key.");
  process.exit(2);
}

const key = await generateSigningKey();

// Private JWK: 0600, written once, never echoed.
writeFileSync(KEY_FILE, `${JSON.stringify(key.privateJwk)}\n`, { mode: 0o600 });
chmodSync(KEY_FILE, 0o600);

// Public material: safe to read, safe to copy into a deployment.
writeFileSync(JWK_FILE, `${JSON.stringify(key.publicJwk, null, 2)}\n`, { mode: 0o644 });
writeFileSync(KEYID_FILE, `${key.keyid}\n`, { mode: 0o644 });

console.log(key.keyid);
console.error("");
console.error(`private JWK  ${KEY_FILE} (0600) — never print, commit, or put in an env var`);
console.error(`public JWK   ${JWK_FILE}`);
console.error(`keyid        ${KEYID_FILE}`);
console.error("");
console.error("Next: back it up the way agentwares-secrets/README.md describes for the wallet");
console.error("keys (login Keychain plus the encrypted iCloud archive), serve the public JWK at");
console.error("/.well-known/http-message-signatures-directory, then register that URL with");
console.error("Cloudflare under Manage Account > Configurations > Bot Submission Form.");
