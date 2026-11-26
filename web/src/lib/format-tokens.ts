// Compact token counts for labels, axes and tooltips: 1.5k, 600M, 1.2B.
// Three significant digits at most, no trailing zeros, and a value never shows four digits in
// front of its unit (999 999 is "1M", not "1000k"), so a label is at most five characters long.

const UNITS: ReadonlyArray<readonly [number, string]> = [
  [1e3, "k"],
  [1e6, "M"],
  [1e9, "B"],
  [1e12, "T"],
];

export function formatTokens(n: number): string {
  if (!Number.isFinite(n)) return "0";
  if (n < 0) return `-${formatTokens(-n)}`;
  if (n < 1000) return String(Math.round(n));
  for (let i = 0; i < UNITS.length; i++) {
    const [size, suffix] = UNITS[i];
    const v = n / size;
    let digits = 2;
    if (v >= 100) digits = 0;
    else if (v >= 10) digits = 1;
    const text = v.toFixed(digits);
    // Rounding can reach 1000 of this unit: use the next one, unless this is the last.
    if (Number(text) >= 1000 && i < UNITS.length - 1) continue;
    if (v >= 1000 && i < UNITS.length - 1) continue;
    return (text.includes(".") ? text.replace(/\.?0+$/, "") : text) + suffix;
  }
  return String(Math.round(n));
}
