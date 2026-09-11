/**
 * RFC 9421 section 2.5, "Creating the Signature Base".
 *
 * The signature base is the only thing that is actually signed, so every byte of it
 * matters: `"@authority": example.com\n` with a different space, a different case or a
 * different parameter order is a different message. The algorithm below follows the RFC
 * step for step and errors out rather than guessing, as section 2.5 requires ("All errors
 * produced as described MUST fail the algorithm immediately").
 */
import { invalid } from "./errors.js";
import {
  parseDictionary,
  serializeInnerList,
  serializeMemberValue,
  serializeParams,
  serializeString,
  type SfInnerList,
  type SfItem,
  type SfParams,
} from "./sfv.js";

/** One entry in the covered-components list, e.g. `"signature-agent";key="sig1"`. */
export interface ComponentIdentifier {
  /** Lowercased field name, or a derived component name beginning with `@`. */
  name: string;
  /** Component parameters, in the order they are serialized. */
  params?: SfParams;
}

export interface RequestLike {
  method: string;
  url: string;
  headers: Headers;
}

export interface ResponseLike {
  status: number;
  headers: Headers;
}

/**
 * The message the base is built against. When `response` is present the target message is
 * the response and `request` is its related request, which is what `;req` resolves against.
 */
export interface MessageContext {
  request: RequestLike;
  response?: ResponseLike;
}

/** RFC 9421 section 2.1.x parameters this library deliberately does not implement. */
const UNSUPPORTED_PARAMS = new Set(["sf", "bs", "tr"]);

export function serializeComponentIdentifier(component: ComponentIdentifier): string {
  return serializeString(component.name) + serializeParams(component.params ?? []);
}

/**
 * RFC 9421 section 2.3: the `@signature-params` value is a parameterized Inner List of the
 * covered component identifiers. The same serialization is the value of `Signature-Input`.
 */
export function serializeSignatureParams(
  components: ComponentIdentifier[],
  params: SfParams,
): string {
  const list: SfInnerList = {
    items: components.map((component): SfItem => ({
      value: component.name,
      params: component.params ?? [],
    })),
    params,
  };
  return serializeInnerList(list);
}

/**
 * Build the signature base for a set of covered components and signature parameters.
 * Returns the exact ASCII string that gets signed — no trailing newline (RFC 9421
 * section 2.5: "the example signature base above does not include the final newline").
 */
export function buildSignatureBase(
  components: ComponentIdentifier[],
  params: SfParams,
  context: MessageContext,
): string {
  const lines: string[] = [];
  const seen = new Set<string>();

  for (const component of components) {
    const identifier = serializeComponentIdentifier(component);
    // Step 2.1: a repeated component identifier is an error.
    if (seen.has(identifier)) {
      throw invalid(
        "INVALID_INPUT",
        `component ${identifier} appears twice in the covered components`,
        "Each component identifier, including its parameters, may appear only once.",
      );
    }
    seen.add(identifier);
    lines.push(`${identifier}: ${resolveComponentValue(component, context)}`);
  }

  lines.push(
    `${serializeString("@signature-params")}: ${serializeSignatureParams(components, params)}`,
  );
  const base = lines.join("\n");

  // Step 4: the base is an ASCII string.
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(base)) {
    throw invalid(
      "UNRESOLVABLE_COMPONENT",
      "the signature base contains non-ASCII characters",
      "Drop the offending component; RFC 9421 forbids non-ASCII in the base and Cloudflare does not support the `bs` wrapper that would encode it.",
    );
  }
  return base;
}

function resolveComponentValue(component: ComponentIdentifier, context: MessageContext): string {
  const params = component.params ?? [];
  const paramNames = new Set(params.map(([name]) => name));

  for (const name of paramNames) {
    if (UNSUPPORTED_PARAMS.has(name)) {
      throw invalid(
        "UNRESOLVABLE_COMPONENT",
        `component parameter \`${name}\` is not supported`,
        "Cloudflare rejects `sf` and `bs` too; sign the raw field value, or leave the component out.",
      );
    }
  }

  const isRequestTarget = paramNames.has("req");
  if (isRequestTarget && !context.response) {
    // Step 2.5: `req` against a request message is an error.
    throw invalid(
      "UNRESOLVABLE_COMPONENT",
      `component ${serializeComponentIdentifier(component)} uses \`req\` but the target message is a request`,
      "Use `req` only when signing a response, where it refers to the request that produced it.",
    );
  }

  if (component.name.startsWith("@")) {
    return derivedComponentValue(component, context, isRequestTarget);
  }
  return fieldComponentValue(component, context, isRequestTarget, params);
}

function derivedComponentValue(
  component: ComponentIdentifier,
  context: MessageContext,
  isRequestTarget: boolean,
): string {
  const { request, response } = context;

  if (component.name === "@status") {
    if (isRequestTarget || !response) {
      throw invalid(
        "UNRESOLVABLE_COMPONENT",
        "@status can only be derived from a response",
        "Remove @status from a request signature; Cloudflare rejects it outright.",
      );
    }
    return String(response.status);
  }

  // Every other derived component reads the request, which is the target message for a
  // request signature and the related request for a `;req` component on a response.
  const url = parseUrl(request.url);
  switch (component.name) {
    case "@method":
      // RFC 9421 section 2.2.1: methods are case-sensitive and uppercase by convention.
      return request.method.toUpperCase();
    case "@target-uri":
      return url.toString();
    case "@authority":
      // RFC 9421 section 2.2.3 via RFC 9110 section 4.2.3: lowercase host, default port omitted.
      // `URL#host` already does both.
      return url.host;
    case "@scheme":
      return url.protocol.replace(/:$/, "").toLowerCase();
    case "@request-target":
      return `${url.pathname}${url.search}`;
    case "@path":
      return url.pathname === "" ? "/" : url.pathname;
    case "@query":
      // RFC 9421 section 2.2.7: the leading `?` is always present.
      return url.search === "" ? "?" : url.search;
    case "@query-param":
      return queryParamValue(component, url);
    default:
      throw invalid(
        "UNRESOLVABLE_COMPONENT",
        `unknown derived component ${component.name}`,
        "Use one of @method, @target-uri, @authority, @scheme, @request-target, @path, @query, @query-param or @status.",
      );
  }
}

function queryParamValue(component: ComponentIdentifier, url: URL): string {
  const nameParam = (component.params ?? []).find(([key]) => key === "name");
  if (!nameParam || typeof nameParam[1] !== "string") {
    throw invalid(
      "UNRESOLVABLE_COMPONENT",
      "@query-param requires a string `name` parameter",
      'Write it as "@query-param";name="foo".',
    );
  }
  const values = url.searchParams.getAll(nameParam[1]);
  if (values.length !== 1) {
    throw invalid(
      "UNRESOLVABLE_COMPONENT",
      `@query-param;name="${nameParam[1]}" matched ${values.length} query parameters`,
      "Sign @query instead when a parameter is absent or repeated.",
    );
  }
  // RFC 9421 section 2.2.8: the value is percent-encoded.
  return encodeURIComponent(values[0] ?? "");
}

function fieldComponentValue(
  component: ComponentIdentifier,
  context: MessageContext,
  isRequestTarget: boolean,
  params: SfParams,
): string {
  if (component.name !== component.name.toLowerCase()) {
    // RFC 9421 section 2.1: "implementations MUST use lowercased field names".
    throw invalid(
      "INVALID_INPUT",
      `field component "${component.name}" is not lowercased`,
      "Lowercase the field name; component names are matched byte for byte.",
    );
  }

  const headers =
    isRequestTarget || !context.response ? context.request.headers : context.response.headers;
  // The Fetch `Headers` getter already combines repeated fields with ", ", which is the
  // combination rule in RFC 9421 section 2.1 / RFC 9110 section 5.2.
  const raw = headers.get(component.name);
  if (raw === null) {
    throw invalid(
      "UNRESOLVABLE_COMPONENT",
      `field "${component.name}" is not present in the message`,
      "Add the header before signing, or drop it from the covered components.",
    );
  }

  const keyParam = params.find(([name]) => name === "key");
  if (!keyParam) return raw.trim();

  if (typeof keyParam[1] !== "string") {
    throw invalid(
      "INVALID_INPUT",
      "the `key` component parameter must be a string",
      'Write it as "signature-agent";key="sig1".',
    );
  }
  // RFC 9421 section 2.1.2: re-serialize the dictionary member value, not the raw text.
  const member = parseDictionary(raw).get(keyParam[1]);
  if (member === undefined) {
    throw invalid(
      "UNRESOLVABLE_COMPONENT",
      `field "${component.name}" has no dictionary member "${keyParam[1]}"`,
      "Name a member that the field actually carries, or drop the `key` parameter.",
    );
  }
  return serializeMemberValue(member);
}

function parseUrl(url: string): URL {
  try {
    return new URL(url);
  } catch (error) {
    throw invalid(
      "INVALID_INPUT",
      `"${url}" is not an absolute URL`,
      "Sign a Request built from an absolute https:// URL.",
      error,
    );
  }
}
