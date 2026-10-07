/**
 * Reading every page of a cursor-paginated MCP list (`tools/list`, `resources/list`,
 * `prompts/list`, …), bounded, and never a silent partial list.
 *
 * MCP paginates these with an opaque `nextCursor`; the last page omits it. A reader that stops
 * after one page, or at a fixed page count without saying so, hides whatever comes after — a
 * proxy cannot reach those tools, and a monitor reads them as removed. A reader with no bound
 * loops forever on a server that hands back the cursor it was given.
 *
 * {@link readAllPages} follows the cursor until it is absent or empty, stops at a cursor it has
 * already followed, and stops at a ceiling with `truncated` set, so the caller decides what a
 * partial list is worth: an error, the last good list, or the partial list with a warning. It
 * takes the page fetch as a callback, so it works over the SDK client, a raw JSON-RPC POST, or
 * anything else, and uses only Web-standard JavaScript (Node, Workers, browsers).
 *
 * Same semantics as agentcheck's `McpClient.listTools()` (BUG-2).
 */

/** Pages read before a list counts as truncated (what mcpcheck and mcp-liveness follow). */
export const LIST_MAX_PAGES = 20;
/**
 * Items read before a list counts as truncated. Above the largest tool catalog in
 * mcp-liveness's October 2026 census of the MCP registry (1,408 tools; 128 of 13,235 answering
 * servers list more than 100).
 */
export const LIST_MAX_ITEMS = 2_000;

export interface ListPage<T> {
  items: readonly T[];
  /** the page's `nextCursor`, as the server sent it; anything but a non-empty string ends the list */
  nextCursor?: unknown;
}

export interface ReadAllPagesOptions {
  /** default {@link LIST_MAX_PAGES} */
  maxPages?: number;
  /** default {@link LIST_MAX_ITEMS} */
  maxItems?: number;
  /** the method, for the truncation reason (default `"tools/list"`) */
  method?: string;
}

export interface ListTruncation {
  ceiling: "pages" | "items";
  /** one sentence a log line, a status field or a cell summary can carry as it is */
  reason: string;
}

export interface ReadAllPagesResult<T> {
  /** every item read, in page order; when `truncated` is set, only the pages read */
  items: T[];
  pages: number;
  /** set when a ceiling stopped the read: `items` is then NOT the whole list */
  truncated?: ListTruncation;
  /**
   * true when the read ended at a cursor it had already followed. Not a truncation: following
   * it again could only return pages already read, so `items` is everything the server serves.
   */
  repeatedCursor?: true;
}

/**
 * Read every page. `fetchPage(cursor, page)` gets `undefined` for the first page (send no
 * cursor) and each `nextCursor` after that; `page` counts from 1. Errors from `fetchPage`
 * propagate unchanged.
 */
export async function readAllPages<T>(
  fetchPage: (cursor: string | undefined, page: number) => Promise<ListPage<T>>,
  opts: ReadAllPagesOptions = {},
): Promise<ReadAllPagesResult<T>> {
  const maxPages = opts.maxPages ?? LIST_MAX_PAGES;
  const maxItems = opts.maxItems ?? LIST_MAX_ITEMS;
  const method = opts.method ?? "tools/list";
  const items: T[] = [];
  const followed = new Set<string>();
  let cursor: string | undefined;
  for (let page = 1; ; page++) {
    const res = await fetchPage(cursor, page);
    if (Array.isArray(res.items)) items.push(...res.items);
    const next = res.nextCursor;
    const more = typeof next === "string" && next !== "";
    if (items.length > maxItems) {
      return {
        items,
        pages: page,
        truncated: {
          ceiling: "items",
          reason: `${method} listed more than ${maxItems} items in ${page} page${page === 1 ? "" : "s"}${more ? " and had more" : ""}; at most ${maxItems} are read`,
        },
      };
    }
    if (!more) return { items, pages: page };
    if (followed.has(next)) return { items, pages: page, repeatedCursor: true };
    if (page >= maxPages) {
      return {
        items,
        pages: page,
        truncated: {
          ceiling: "pages",
          reason: `${method} had more than ${maxPages} pages (${items.length} items read); at most ${maxPages} pages are read`,
        },
      };
    }
    followed.add(next);
    cursor = next;
  }
}
