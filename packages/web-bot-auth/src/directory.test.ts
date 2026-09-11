import { describe, expect, it } from "vitest";
import {
  contentDigest,
  directoryBody,
  directoryHandler,
  signedDirectoryResponse,
} from "./directory.js";
import {
  DIRECTORY_MEDIA_TYPE,
  DIRECTORY_PATH,
  importSigningKey,
  generateSigningKey,
  signBytes,
  type SigningKey,
} from "./keys.js";
import { base64Encode, isInnerList, parseDictionary } from "./sfv.js";
import { verifyDirectoryResponse } from "./verify.js";
import {
  E_2_3,
  RFC9421_ED25519_JWK,
  RFC9421_ED25519_THUMBPRINT,
} from "./__fixtures__/test-vectors.js";

const key: SigningKey = await importSigningKey(RFC9421_ED25519_JWK);
const fetchDirectory = (authority = "signature-agent.test"): Request =>
  new Request(`https://${authority}${DIRECTORY_PATH}`, {
    headers: { accept: DIRECTORY_MEDIA_TYPE },
  });

describe("directory body and digest — Appendix E.2.3", () => {
  it("serializes the JWKS exactly as the draft shows it", () => {
    expect(directoryBody([key])).toBe(E_2_3.body);
  });

  it("computes the published Content-Digest over those bytes", async () => {
    await expect(contentDigest(E_2_3.body)).resolves.toBe(E_2_3.contentDigest);
  });

  it("signs the published directory base to the published signature", async () => {
    const signature = await signBytes(key, new TextEncoder().encode(E_2_3.base));
    expect(base64Encode(signature)).toBe(E_2_3.signature);
  });

  it("publishes nbf/exp when a key carries a validity window", () => {
    const body: unknown = JSON.parse(directoryBody([{ key, nbf: 1712793600, exp: 1715385600 }]));
    expect(body).toEqual({
      keys: [
        {
          kty: "OKP",
          crv: "Ed25519",
          kid: RFC9421_ED25519_THUMBPRINT,
          x: RFC9421_ED25519_JWK.x,
          use: "sig",
          nbf: 1712793600,
          exp: 1715385600,
        },
      ],
    });
  });

  it("never leaks the private scalar", () => {
    expect(directoryBody([key])).not.toContain(RFC9421_ED25519_JWK.d);
    expect(directoryBody([key])).not.toContain('"d"');
  });
});

describe("signedDirectoryResponse", () => {
  it("serves the required status, media type and headers", async () => {
    const response = await signedDirectoryResponse(fetchDirectory(), [key]);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(DIRECTORY_MEDIA_TYPE);
    expect(response.headers.get("cache-control")).toBe("max-age=86400");
    expect(response.headers.get("signature-input")).toContain(
      'tag="http-message-signatures-directory"',
    );
    expect(response.headers.get("signature-input")).toContain('("@authority";req)');
    expect(response.headers.get("content-digest")).toBe(
      await contentDigest(await response.clone().text()),
    );
  });

  it("carries keyid and a long-lived window, per the draft's Appendix C.8", async () => {
    const created = 1_800_000_000;
    const response = await signedDirectoryResponse(fetchDirectory(), [key], { created });
    const input = response.headers.get("signature-input") ?? "";
    expect(input).toContain(`keyid="${RFC9421_ED25519_THUMBPRINT}"`);
    expect(input).toContain(`;expires=${created + 7 * 24 * 60 * 60};`);
  });

  it("signs once per published key", async () => {
    const second = await generateSigningKey();
    const response = await signedDirectoryResponse(fetchDirectory(), [key, second]);
    const inputs = parseDictionary(response.headers.get("signature-input") ?? "");
    const signatures = parseDictionary(response.headers.get("signature") ?? "");
    expect([...inputs.keys()]).toEqual(["sig1", "sig2"]);
    expect([...signatures.keys()]).toEqual(["sig1", "sig2"]);

    const first = inputs.get("sig1");
    if (!first || !isInnerList(first)) throw new Error("expected an inner list");
    expect(first.params).toContainEqual(["keyid", key.keyid]);
  });

  it("covers content-digest under the ietf-draft profile only", async () => {
    const cloudflare = await signedDirectoryResponse(fetchDirectory(), [key]);
    expect(cloudflare.headers.get("signature-input")).not.toContain('"content-digest"');

    const ietf = await signedDirectoryResponse(fetchDirectory(), [key], {
      profile: "ietf-draft",
    });
    expect(ietf.headers.get("signature-input")).toContain('("@authority";req "content-digest")');
  });

  it("refuses to serve an empty directory", async () => {
    await expect(signedDirectoryResponse(fetchDirectory(), [])).rejects.toThrowError(
      /would be empty/,
    );
  });
});

describe("verifyDirectoryResponse", () => {
  it.each(["cloudflare", "ietf-draft"] as const)("verifies the %s profile", async (profile) => {
    const request = fetchDirectory();
    const response = await signedDirectoryResponse(request, [key], { profile });
    const result = await verifyDirectoryResponse(request, response, {
      requireContentDigest: profile === "ietf-draft",
    });
    expect(result.ok).toBe(true);
    expect(result.proven).toEqual([RFC9421_ED25519_THUMBPRINT]);
    expect(result.keys[0]?.x).toBe(RFC9421_ED25519_JWK.x);
  });

  it("proves possession of every key it publishes", async () => {
    const second = await generateSigningKey();
    const request = fetchDirectory();
    const response = await signedDirectoryResponse(request, [key, second]);
    const result = await verifyDirectoryResponse(request, response);
    expect(result.proven.sort()).toEqual([key.keyid, second.keyid].sort());
  });

  it("rejects the key set re-served under a different authority", async () => {
    const response = await signedDirectoryResponse(fetchDirectory("signature-agent.test"), [key]);
    const result = await verifyDirectoryResponse(fetchDirectory("impostor.example"), response);
    expect(result.ok).toBe(false);
    expect(result.failures[0]?.code).toBe("BAD_SIGNATURE");
  });

  it("rejects a body swapped under a captured signature", async () => {
    const request = fetchDirectory();
    const response = await signedDirectoryResponse(request, [key], { profile: "ietf-draft" });
    const other = await generateSigningKey();
    const swapped = new Response(directoryBody([other]), { headers: response.headers });
    const result = await verifyDirectoryResponse(request, swapped, {
      requireContentDigest: true,
    });
    expect(result.ok).toBe(false);
    expect(result.failures[0]?.code).toBe("DIGEST_MISMATCH");
  });

  it("reports a directory whose signature has expired", async () => {
    const request = fetchDirectory();
    const response = await signedDirectoryResponse(request, [key], {
      created: 1_700_000_000,
      expiresIn: 60,
    });
    const result = await verifyDirectoryResponse(request, response, { now: 1_700_100_000 });
    expect(result.ok).toBe(false);
    expect(result.failures[0]?.code).toBe("STALE");
  });

  it("rejects a body that is not a JWKS", async () => {
    const request = fetchDirectory();
    const result = await verifyDirectoryResponse(request, new Response("{}"));
    expect(result.ok).toBe(false);
    expect(result.failures[0]?.code).toBe("MALFORMED");
  });
});

describe("directoryHandler", () => {
  it("answers the well-known path and 404s everything else", async () => {
    const handler = directoryHandler([key]);
    const served = await handler(fetchDirectory());
    expect(served.status).toBe(200);
    expect((await handler(new Request("https://bot.example/other"))).status).toBe(404);
  });
});
