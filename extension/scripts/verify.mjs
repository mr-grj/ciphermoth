// Checks that the release packages were built from this source.
//
//   git checkout vX.Y.Z && cd extension && npm ci
//   node scripts/verify.mjs path/to/SHA256SUMS
//
// Rebuilds the packages reproducibly (same toolchain from package-lock.json,
// SOURCE_DATE_EPOCH defaulting to the value the release used) and compares
// every checksum. A store package can be checked the same way: download it
// (Chrome: the .crx is a zip with a header; unzip it and compare the files with
// dist/chromium), or compare the zip from the GitHub release, which is what is
// uploaded to the stores. The signed Firefox XPI adds Mozilla's signature
// files (META-INF/); everything else must equal dist/firefox.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const expectedFile = process.argv[2];
if (!expectedFile) {
  console.error("usage: node scripts/verify.mjs path/to/SHA256SUMS");
  process.exit(2);
}

const parse = (text) =>
  new Map(
    text
      .trim()
      .split("\n")
      .filter((line) => /^[0-9a-f]{64} {2}\S+$/.test(line))
      .map((line) => [line.slice(66), line.slice(0, 64)])
  );

execFileSync("node", ["scripts/build.mjs", "--package"], { cwd: root, stdio: "inherit" });
const built = parse(readFileSync(join(root, "dist/packages/SHA256SUMS"), "utf8"));
const expected = parse(readFileSync(expectedFile, "utf8"));
let failures = 0;
for (const [name, sum] of built) {
  if (!expected.has(name)) continue;
  const ok = expected.get(name) === sum;
  if (!ok) failures += 1;
  console.log(`${ok ? "OK      " : "MISMATCH"} ${name}`);
}
const compared = [...built.keys()].filter((name) => expected.has(name)).length;
if (!compared) {
  console.error("No package in that SHA256SUMS matches this version.");
  process.exit(1);
}
process.exit(failures ? 1 : 0);
