import { describe, expect, it } from "vitest";
import { LIST_MAX_ITEMS, LIST_MAX_PAGES, readAllPages, type ListPage } from "./paging.js";

/** A paged list: cursor (`""` for the first page) → items on that page and the cursor it returns. */
function pages(map: Record<string, { items: string[]; next?: unknown }>) {
  const asked: (string | undefined)[] = [];
  const fetchPage = async (cursor: string | undefined): Promise<ListPage<string>> => {
    asked.push(cursor);
    const page = map[cursor ?? ""];
    if (!page) throw new Error(`unknown cursor ${String(cursor)}`);
    return { items: page.items, nextCursor: page.next };
  };
  return { fetchPage, asked };
}

/** A server whose cursor never ends: a fresh cursor and one item on every page. */
function endless(perPage = 1) {
  const asked: (string | undefined)[] = [];
  const fetchPage = async (cursor: string | undefined): Promise<ListPage<string>> => {
    asked.push(cursor);
    const n = cursor === undefined ? 0 : Number(cursor.slice(1));
    return {
      items: Array.from({ length: perPage }, (_, i) => `t${n}_${i}`),
      nextCursor: `c${n + 1}`,
    };
  };
  return { fetchPage, asked };
}

describe("readAllPages", () => {
  it("reads a three-page list to the end, passing each cursor back", async () => {
    const p = pages({
      "": { items: ["a", "b"], next: "p2" },
      p2: { items: ["c"], next: "p3" },
      p3: { items: ["d", "e"] },
    });
    expect(await readAllPages(p.fetchPage)).toEqual({ items: ["a", "b", "c", "d", "e"], pages: 3 });
    expect(p.asked).toEqual([undefined, "p2", "p3"]);
  });

  it("an absent, empty or non-string nextCursor is the last page", async () => {
    for (const next of [undefined, "", null, 7]) {
      const p = pages({ "": { items: ["a"], next } });
      expect(await readAllPages(p.fetchPage)).toEqual({ items: ["a"], pages: 1 });
      expect(p.asked).toEqual([undefined]);
    }
  });

  it("stops at an echoed cursor instead of looping, each page read once", async () => {
    const p = pages({ "": { items: ["a"], next: "p2" }, p2: { items: ["b"], next: "p2" } });
    expect(await readAllPages(p.fetchPage)).toEqual({
      items: ["a", "b"],
      pages: 2,
      repeatedCursor: true,
    });
    expect(p.asked).toEqual([undefined, "p2"]);
  });

  it("stops at a cycle back to an earlier page", async () => {
    const p = pages({
      "": { items: ["a"], next: "x" },
      x: { items: ["b"], next: "y" },
      y: { items: ["c"], next: "x" },
    });
    const r = await readAllPages(p.fetchPage);
    expect(r).toMatchObject({ items: ["a", "b", "c"], repeatedCursor: true });
    expect(r.truncated).toBeUndefined();
    expect(p.asked).toEqual([undefined, "x", "y"]);
  });

  it(`says it is truncated past ${LIST_MAX_PAGES} pages, having asked for exactly that many`, async () => {
    const e = endless();
    const r = await readAllPages(e.fetchPage);
    expect(e.asked).toHaveLength(LIST_MAX_PAGES);
    expect(r.pages).toBe(LIST_MAX_PAGES);
    expect(r.items).toHaveLength(LIST_MAX_PAGES);
    expect(r.truncated).toEqual({
      ceiling: "pages",
      reason: `tools/list had more than ${LIST_MAX_PAGES} pages (${LIST_MAX_PAGES} items read); at most ${LIST_MAX_PAGES} pages are read`,
    });
  });

  it(`says it is truncated past ${LIST_MAX_ITEMS} items, even on one page`, async () => {
    const big = Array.from({ length: LIST_MAX_ITEMS + 1 }, (_, i) => `t${i}`);
    const r = await readAllPages(pages({ "": { items: big } }).fetchPage);
    expect(r.truncated?.ceiling).toBe("items");
    expect(r.truncated?.reason).toContain(`more than ${LIST_MAX_ITEMS} items`);

    const exactly = big.slice(0, LIST_MAX_ITEMS);
    expect((await readAllPages(pages({ "": { items: exactly } }).fetchPage)).truncated).toBe(
      undefined,
    );
  });

  it("takes its own ceilings and method name", async () => {
    const r = await readAllPages(endless(3).fetchPage, {
      maxPages: 2,
      maxItems: 100,
      method: "resources/list",
    });
    expect(r).toMatchObject({ pages: 2, truncated: { ceiling: "pages" } });
    expect(r.truncated?.reason).toBe(
      "resources/list had more than 2 pages (6 items read); at most 2 pages are read",
    );
  });

  it("a page that fails fails the read", async () => {
    const p = pages({ "": { items: ["a"], next: "gone" } });
    await expect(readAllPages(p.fetchPage)).rejects.toThrow("unknown cursor gone");
  });
});
