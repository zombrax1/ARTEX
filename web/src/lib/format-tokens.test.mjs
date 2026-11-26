import { formatTokens } from "./format-tokens.ts";
import assert from "node:assert/strict";
import test from "node:test";

test("formatTokens keeps small counts as integers", () => {
  assert.equal(formatTokens(0), "0");
  assert.equal(formatTokens(999), "999");
  assert.equal(formatTokens(999.4), "999");
});

test("formatTokens uses k, M, B and T without trailing zeros", () => {
  assert.equal(formatTokens(1000), "1k");
  assert.equal(formatTokens(1500), "1.5k");
  assert.equal(formatTokens(12345), "12.3k");
  assert.equal(formatTokens(1_000_000), "1M");
  assert.equal(formatTokens(900_000), "900k");
  assert.equal(formatTokens(600_000_000), "600M");
  assert.equal(formatTokens(1_200_000_000), "1.2B");
  assert.equal(formatTokens(2_400_000_000), "2.4B");
  assert.equal(formatTokens(3_623_300_000), "3.62B");
  assert.equal(formatTokens(15_000_000_000), "15B");
  assert.equal(formatTokens(2_500_000_000_000), "2.5T");
});

test("formatTokens never shows four digits in front of a unit", () => {
  assert.equal(formatTokens(999_499), "999k");
  assert.equal(formatTokens(999_500), "1M");
  assert.equal(formatTokens(999_999), "1M");
  assert.equal(formatTokens(999_999_999), "1B");
  assert.equal(formatTokens(999_999_999_999), "1T");
  for (const n of [1, 999, 1000, 9_999, 99_999, 999_999, 1e6, 123_456_789, 999_999_999, 1.2e9, 987_654_321_000]) {
    assert.ok(formatTokens(n).length <= 5, `${n} -> ${formatTokens(n)}`);
  }
});

test("formatTokens axis ticks from the reported chart read as an increasing scale", () => {
  assert.deepEqual([0, 6e8, 1.2e9, 1.8e9, 2.4e9].map(formatTokens), ["0", "600M", "1.2B", "1.8B", "2.4B"]);
});

test("formatTokens tolerates odd input", () => {
  assert.equal(formatTokens(NaN), "0");
  assert.equal(formatTokens(-1500), "-1.5k");
});
