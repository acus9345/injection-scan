/**
 * Text normalization that defeats the usual obfuscation tricks while keeping a
 * map back to the original string, so findings can point at the real text.
 */

/** Characters that render as nothing (or reorder text) and are used to hide instructions. */
export function isInvisible(cp: number): boolean {
  return (
    cp === 0x00ad || // soft hyphen
    cp === 0x034f || // combining grapheme joiner
    cp === 0x061c || // Arabic letter mark
    cp === 0x115f ||
    cp === 0x1160 ||
    cp === 0x17b4 ||
    cp === 0x17b5 ||
    cp === 0x180e || // Mongolian vowel separator
    (cp >= 0x200b && cp <= 0x200f) || // zero-width space/joiners, LRM, RLM
    (cp >= 0x202a && cp <= 0x202e) || // bidi embeddings and overrides
    (cp >= 0x2060 && cp <= 0x2064) || // word joiner, invisible operators
    (cp >= 0x2066 && cp <= 0x2069) || // bidi isolates
    cp === 0x3164 ||
    cp === 0xfeff || // zero-width no-break space / BOM
    cp === 0xffa0 ||
    (cp >= 0xfe00 && cp <= 0xfe0f) || // variation selectors
    (cp >= 0xe0000 && cp <= 0xe007f) || // Unicode tag characters
    (cp >= 0xe0100 && cp <= 0xe01ef) // variation selectors supplement
  );
}

export function isBidiControl(cp: number): boolean {
  return (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
}

export function isTagChar(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

// Latin lookalikes from Cyrillic, Greek and other scripts that NFKD leaves alone.
const HOMOGLYPHS: Record<string, string> = {
  а: "a", в: "b", е: "e", ё: "e", к: "k", м: "m", н: "h", о: "o", р: "p", с: "c", т: "t", у: "y", х: "x",
  і: "i", ї: "i", ј: "j", ѕ: "s", ԁ: "d", ԛ: "q", ԝ: "w", һ: "h", ӏ: "l", ɡ: "g", ɩ: "i", ı: "i",
  α: "a", β: "b", ε: "e", ι: "i", κ: "k", ν: "v", ο: "o", ρ: "p", τ: "t", υ: "u", χ: "x", ω: "w",
  "‘": "'", "’": "'", "‚": "'", "‛": "'", "′": "'",
  "“": '"', "”": '"', "„": '"', "″": '"',
  "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-",
};

export interface Normalized {
  /** Lowercased text with invisible characters removed, lookalikes folded and whitespace collapsed. */
  text: string;
  /** For each character of `text`, the index in the original string where its source starts. */
  starts: number[];
  /** For each character of `text`, the index in the original string just after its source. */
  ends: number[];
}

const COMBINING = /\p{M}/gu;

/**
 * Normalize text for matching:
 * - removes zero-width, bidi-control, tag and other invisible characters,
 * - applies NFKD and drops combining marks (fullwidth and math letters become ASCII, accents go away),
 * - lowercases and folds common Cyrillic/Greek lookalikes to Latin,
 * - collapses runs of spaces and tabs to one space, and runs containing a line break to one `\n`.
 */
export function normalize(input: string): Normalized {
  let text = "";
  const starts: number[] = [];
  const ends: number[] = [];
  let pendingSpace: "" | " " | "\n" = "";
  let pendingAt = 0;

  for (let i = 0; i < input.length; ) {
    const cp = input.codePointAt(i)!;
    const size = cp > 0xffff ? 2 : 1;
    const end = i + size;
    if (isInvisible(cp)) {
      i = end;
      continue;
    }
    const ch = input.slice(i, end);
    if (/\s/u.test(ch)) {
      if (pendingSpace === "") pendingAt = i;
      if (ch === "\n" || ch === "\r" || ch === " " || ch === " ") pendingSpace = "\n";
      else if (pendingSpace === "") pendingSpace = " ";
      i = end;
      continue;
    }
    if (pendingSpace !== "") {
      if (text.length > 0) {
        text += pendingSpace;
        starts.push(pendingAt);
        ends.push(i);
      }
      pendingSpace = "";
    }
    const folded = fold(ch);
    text += folded;
    // One entry per UTF-16 code unit, so astral characters (emoji) keep the map aligned.
    for (let k = 0; k < folded.length; k++) {
      starts.push(i);
      ends.push(end);
    }
    i = end;
  }
  return { text, starts, ends };
}

function fold(ch: string): string {
  const direct = HOMOGLYPHS[ch] ?? HOMOGLYPHS[ch.toLowerCase()];
  if (direct !== undefined) return direct;
  let out = ch.normalize("NFKD").replace(COMBINING, "").toLowerCase();
  if (out.length === 0) return "";
  if (out.length === 1) return HOMOGLYPHS[out] ?? out;
  out = Array.from(out, (c) => HOMOGLYPHS[c] ?? c).join("");
  // NFKD can expand characters into whitespace (e.g. U+00A0 -> " "); keep that as a space.
  return out.replace(/\s+/gu, " ");
}

/** Map a `[start, end)` range in normalized text back to the original string. */
export function toOriginal(n: Normalized, start: number, end: number): [number, number] {
  const s = n.starts[start] ?? n.starts[n.starts.length - 1] ?? 0;
  const e = n.ends[Math.max(start, end - 1)] ?? s;
  return [s, e];
}
