/**
 * The slice of RFC 9651 Structured Field Values that HTTP Message Signatures needs:
 * Dictionaries, Inner Lists, Items and Parameters over Integer / Decimal / String /
 * Token / Byte Sequence / Boolean bare items.
 *
 * RFC 9421 section 2.5 requires the "strict serialization rules defined by
 * [STRUCTURED-FIELDS], Section 4", so the serializers here are strict: they reject
 * anything they cannot round-trip rather than emitting a field a verifier will read
 * differently. Dates and Display Strings are deliberately absent — no component of
 * Web Bot Auth uses them, and silently mis-parsing one would be worse than failing.
 */
import { invalid } from "./errors.js";

/** A Token bare item, which serializes without quotes (e.g. `type=directory`). */
export class SfToken {
  constructor(readonly value: string) {}
}

export type BareItem = string | number | boolean | Uint8Array | SfToken;
/** Parameters are an ordered list: RFC 9421 section 2.3 fixes the order once chosen. */
export type SfParams = Array<[string, BareItem]>;

export interface SfItem {
  value: BareItem;
  params: SfParams;
}

export interface SfInnerList {
  items: SfItem[];
  params: SfParams;
}

export type SfMemberValue = SfItem | SfInnerList;

export function isInnerList(value: SfMemberValue): value is SfInnerList {
  return "items" in value;
}

const MAX_INTEGER = 999_999_999_999_999;
const MIN_INTEGER = -999_999_999_999_999;

// ---------------------------------------------------------------------------
// Serialization (RFC 9651 section 4.1)
// ---------------------------------------------------------------------------

/** RFC 9651 section 4.1.9: DQUOTE, backslash-escaping `\` and `"`, printable ASCII only. */
export function serializeString(value: string): string {
  let out = '"';
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code >= 0x7f) {
      throw invalid(
        "INVALID_INPUT",
        `string contains a character that is not printable ASCII (U+${code.toString(16).toUpperCase().padStart(4, "0")})`,
        "Structured-field strings are limited to %x20-%x7E; percent-encode or drop the character before signing.",
      );
    }
    if (char === "\\" || char === '"') out += "\\";
    out += char;
  }
  return `${out}"`;
}

const TOKEN_RE = /^[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*$/;

/** RFC 9651 section 4.1.7. */
export function serializeToken(value: string): string {
  if (!TOKEN_RE.test(value)) {
    throw invalid(
      "INVALID_INPUT",
      `"${value}" is not a valid structured-field token`,
      "Tokens start with ALPHA or `*` and continue with tchar / `:` / `/`; use a string instead.",
    );
  }
  return value;
}

/** RFC 9651 section 4.1.4 (Integer) and 4.1.5 (Decimal). */
export function serializeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw invalid(
      "INVALID_INPUT",
      `${value} is not a finite number`,
      "Structured fields have no representation for NaN or Infinity.",
    );
  }
  if (Number.isInteger(value)) {
    if (value > MAX_INTEGER || value < MIN_INTEGER) {
      throw invalid(
        "INVALID_INPUT",
        `integer ${value} is outside the structured-field range`,
        "Structured-field integers span -999999999999999 to 999999999999999.",
      );
    }
    return String(value);
  }
  const rounded = Math.round(value * 1000) / 1000;
  if (Math.abs(Math.trunc(rounded)) > 999_999_999_999) {
    throw invalid(
      "INVALID_INPUT",
      `decimal ${value} has more than 12 integer digits`,
      "Structured-field decimals allow at most 12 integer digits and 3 fractional digits.",
    );
  }
  const text = rounded.toFixed(3).replace(/0+$/, "");
  return text.endsWith(".") ? `${text}0` : text;
}

/** RFC 9651 section 4.1.8: `:` base64 `:`. */
export function serializeByteSequence(value: Uint8Array): string {
  return `:${base64Encode(value)}:`;
}

export function serializeBareItem(value: BareItem): string {
  if (typeof value === "string") return serializeString(value);
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "boolean") return value ? "?1" : "?0";
  if (value instanceof SfToken) return serializeToken(value.value);
  if (value instanceof Uint8Array) return serializeByteSequence(value);
  throw invalid(
    "INVALID_INPUT",
    "value is not a serializable structured-field bare item",
    "Pass a string, number, boolean, SfToken or Uint8Array.",
  );
}

const KEY_RE = /^[a-z*][a-z0-9_\-.*]*$/;

/** RFC 9651 section 4.1.1.3. */
export function serializeKey(key: string): string {
  if (!KEY_RE.test(key)) {
    throw invalid(
      "INVALID_INPUT",
      `"${key}" is not a valid structured-field key`,
      "Keys start with lowercase ALPHA or `*` and continue with lcalpha / DIGIT / `_` / `-` / `.` / `*`.",
    );
  }
  return key;
}

/** RFC 9651 section 4.1.1.2. A Boolean `true` is serialized by omitting the value. */
export function serializeParams(params: SfParams): string {
  let out = "";
  for (const [key, value] of params) {
    out += `;${serializeKey(key)}`;
    if (value !== true) out += `=${serializeBareItem(value)}`;
  }
  return out;
}

export function serializeItem(item: SfItem): string {
  return serializeBareItem(item.value) + serializeParams(item.params);
}

/** RFC 9651 section 4.1.1.1: `(` items joined by a single SP `)` then parameters. */
export function serializeInnerList(list: SfInnerList): string {
  return `(${list.items.map(serializeItem).join(" ")})${serializeParams(list.params)}`;
}

export function serializeMemberValue(value: SfMemberValue): string {
  return isInnerList(value) ? serializeInnerList(value) : serializeItem(value);
}

/** RFC 9651 section 4.1.2. */
export function serializeDictionary(dict: Iterable<[string, SfMemberValue]>): string {
  const parts: string[] = [];
  for (const [key, value] of dict) {
    if (!isInnerList(value) && value.value === true) {
      parts.push(serializeKey(key) + serializeParams(value.params));
    } else {
      parts.push(`${serializeKey(key)}=${serializeMemberValue(value)}`);
    }
  }
  return parts.join(", ");
}

// ---------------------------------------------------------------------------
// Parsing (RFC 9651 section 4.2)
// ---------------------------------------------------------------------------

class Cursor {
  index = 0;
  constructor(readonly input: string) {}

  peek(): string | undefined {
    return this.index < this.input.length ? this.input[this.index] : undefined;
  }

  next(): string | undefined {
    const char = this.peek();
    if (char !== undefined) this.index += 1;
    return char;
  }

  get done(): boolean {
    return this.index >= this.input.length;
  }

  skipSp(): void {
    while (this.peek() === " ") this.index += 1;
  }

  skipOws(): void {
    while (this.peek() === " " || this.peek() === "\t") this.index += 1;
  }

  fail(reason: string): never {
    throw invalid(
      "MALFORMED_FIELD",
      `${reason} at offset ${this.index} of "${this.input}"`,
      "Check the field against RFC 9651; a signature cannot be built from a field that will not parse.",
    );
  }
}

/** RFC 9651 section 4.2: Dictionary of Items and Inner Lists. Later members win. */
export function parseDictionary(input: string): Map<string, SfMemberValue> {
  const cursor = new Cursor(input);
  const dict = new Map<string, SfMemberValue>();
  cursor.skipSp();
  while (!cursor.done) {
    const key = parseKey(cursor);
    let value: SfMemberValue;
    if (cursor.peek() === "=") {
      cursor.next();
      value = parseItemOrInnerList(cursor);
    } else {
      value = { value: true, params: parseParams(cursor) };
    }
    dict.set(key, value);
    cursor.skipOws();
    if (cursor.done) return dict;
    if (cursor.next() !== ",") cursor.fail("expected a comma between dictionary members");
    cursor.skipOws();
    if (cursor.done) cursor.fail("trailing comma in dictionary");
  }
  return dict;
}

/** RFC 9651 section 4.2.3: a bare Item with its parameters. */
export function parseItem(input: string): SfItem {
  const cursor = new Cursor(input);
  cursor.skipSp();
  const item: SfItem = { value: parseBareItem(cursor), params: parseParams(cursor) };
  cursor.skipSp();
  if (!cursor.done) cursor.fail("unexpected trailing characters after item");
  return item;
}

function parseItemOrInnerList(cursor: Cursor): SfMemberValue {
  return cursor.peek() === "(" ? parseInnerList(cursor) : parseItemWithParams(cursor);
}

function parseItemWithParams(cursor: Cursor): SfItem {
  return { value: parseBareItem(cursor), params: parseParams(cursor) };
}

/** RFC 9651 section 4.2.1.2. */
function parseInnerList(cursor: Cursor): SfInnerList {
  if (cursor.next() !== "(") cursor.fail("expected `(` to open an inner list");
  const items: SfItem[] = [];
  for (;;) {
    cursor.skipSp();
    if (cursor.peek() === ")") {
      cursor.next();
      return { items, params: parseParams(cursor) };
    }
    if (cursor.done) cursor.fail("unterminated inner list");
    items.push(parseItemWithParams(cursor));
    const char = cursor.peek();
    if (char !== " " && char !== ")") cursor.fail("expected a space or `)` in an inner list");
  }
}

/** RFC 9651 section 4.2.3.2. */
function parseParams(cursor: Cursor): SfParams {
  const params: SfParams = [];
  while (cursor.peek() === ";") {
    cursor.next();
    cursor.skipSp();
    const key = parseKey(cursor);
    let value: BareItem = true;
    if (cursor.peek() === "=") {
      cursor.next();
      value = parseBareItem(cursor);
    }
    const existing = params.findIndex(([name]) => name === key);
    if (existing >= 0) params.splice(existing, 1);
    params.push([key, value]);
  }
  return params;
}

/** RFC 9651 section 4.2.3.3. */
function parseKey(cursor: Cursor): string {
  const char = cursor.peek();
  if (char === undefined || !/^[a-z*]$/.test(char)) cursor.fail("expected a key");
  let key = "";
  for (;;) {
    const next = cursor.peek();
    if (next === undefined || !/^[a-z0-9_\-.*]$/.test(next)) return key;
    key += next;
    cursor.next();
  }
}

/** RFC 9651 section 4.2.3.1. */
function parseBareItem(cursor: Cursor): BareItem {
  const char = cursor.peek();
  if (char === undefined) cursor.fail("expected a bare item");
  if (char === '"') return parseStringValue(cursor);
  if (char === ":") return parseByteSequence(cursor);
  if (char === "?") return parseBoolean(cursor);
  if (char === "-" || /^[0-9]$/.test(char)) return parseNumber(cursor);
  if (/^[A-Za-z*]$/.test(char)) return parseTokenValue(cursor);
  cursor.fail(`unexpected character "${char}"`);
}

function parseStringValue(cursor: Cursor): string {
  if (cursor.next() !== '"') cursor.fail("expected an opening quote");
  let out = "";
  for (;;) {
    const char = cursor.next();
    if (char === undefined) cursor.fail("unterminated string");
    if (char === "\\") {
      const escaped = cursor.next();
      if (escaped !== "\\" && escaped !== '"') cursor.fail("invalid string escape");
      out += escaped;
      continue;
    }
    if (char === '"') return out;
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code >= 0x7f) cursor.fail("string contains a non-printable character");
    out += char;
  }
}

function parseTokenValue(cursor: Cursor): SfToken {
  let out = "";
  for (;;) {
    const char = cursor.peek();
    if (char === undefined || !/^[A-Za-z0-9!#$%&'*+\-.^_`|~:/]$/.test(char)) {
      return new SfToken(out);
    }
    out += char;
    cursor.next();
  }
}

function parseByteSequence(cursor: Cursor): Uint8Array {
  if (cursor.next() !== ":") cursor.fail("expected `:` to open a byte sequence");
  let encoded = "";
  for (;;) {
    const char = cursor.next();
    if (char === undefined) cursor.fail("unterminated byte sequence");
    if (char === ":") break;
    if (!/^[A-Za-z0-9+/=]$/.test(char)) cursor.fail("invalid base64 in byte sequence");
    encoded += char;
  }
  try {
    return base64Decode(encoded);
  } catch (error) {
    cursor.fail(`byte sequence is not valid base64 (${String(error)})`);
  }
}

function parseBoolean(cursor: Cursor): boolean {
  if (cursor.next() !== "?") cursor.fail("expected `?` to open a boolean");
  const char = cursor.next();
  if (char === "1") return true;
  if (char === "0") return false;
  cursor.fail("expected `?0` or `?1`");
}

function parseNumber(cursor: Cursor): number {
  let text = "";
  if (cursor.peek() === "-") {
    text += cursor.next();
  }
  let decimal = false;
  for (;;) {
    const char = cursor.peek();
    if (char === undefined) break;
    if (/^[0-9]$/.test(char)) {
      text += char;
      cursor.next();
      continue;
    }
    if (char === "." && !decimal) {
      decimal = true;
      text += char;
      cursor.next();
      continue;
    }
    break;
  }
  if (text === "" || text === "-" || text.endsWith(".")) cursor.fail("malformed number");
  const value = Number(text);
  if (!Number.isFinite(value)) cursor.fail("malformed number");
  return value;
}

// ---------------------------------------------------------------------------
// base64 — Web-standard only, so this runs unchanged on Workers and in Node
// ---------------------------------------------------------------------------

export function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64Decode(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  return base64Decode(padded + "=".repeat((4 - (padded.length % 4)) % 4));
}
