// Builds the extension for Chromium and Firefox, reproducibly.
//
//   node scripts/build.mjs             dist/chromium, dist/firefox
//   node scripts/build.mjs --package   ... plus dist/packages/*.zip and SHA256SUMS
//   node scripts/build.mjs --test      dist-test/chromium (Playwright build, see below)
//
// Reproducible: pinned toolchain (package-lock.json), no minification, no
// source maps, no timestamps or paths in the output, zip entries sorted with a
// fixed mtime (SOURCE_DATE_EPOCH, default 2026-01-01) and fixed attributes.
// Building the same commit twice gives byte-identical packages (verify.mjs).
//
// The --test build is for automated tests only and never shipped: it adds host
// permissions for every site (Playwright cannot click the toolbar button, which
// is what grants activeTab), the clipboardRead permission, a 3 s clipboard
// timer, a popup that can be pointed at a tab (#tab=<id>) and a hook to run the
// fill command. All of it hangs off __E2E__, which is false in real builds.

import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync, gzipSync } from "node:zlib";
import { readdirSync, statSync } from "node:fs";

import * as esbuild from "esbuild";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = new Set(process.argv.slice(2));
const TEST = args.has("--test");
const PACKAGE = args.has("--package");
const targets = TEST ? ["chromium"] : ["chromium", "firefox"];
const outRoot = join(root, TEST ? "dist-test" : "dist");
const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const BUDGET_BYTES = 60 * 1024;

const readJson = (path) => JSON.parse(readFileSync(join(root, path), "utf8"));

// Arrays are concatenated (permissions), objects merged, the rest replaced.
const merge = (base, extra) => {
  const out = { ...base };
  for (const [key, value] of Object.entries(extra)) {
    if (Array.isArray(value) && Array.isArray(out[key])) out[key] = [...out[key], ...value];
    else if (value && typeof value === "object" && !Array.isArray(value) && out[key])
      out[key] = merge(out[key], value);
    else out[key] = value;
  }
  return out;
};

export const manifestFor = (target, { test = false } = {}) => {
  let manifest = merge(readJson("manifest/base.json"), readJson(`manifest/${target}.json`));
  manifest.version = version;
  if (test) {
    manifest = merge(manifest, {
      permissions: ["clipboardRead", "nativeMessaging"],
      host_permissions: ["https://*/*", "http://*/*"],
    });
    manifest.name = "CipherMoth (test build)";
  }
  return manifest;
};

// The extension must keep the app's brand: every token in base.css must equal
// frontend/src/lib/brand.js.
const checkBrand = () => {
  const brand = readFileSync(join(root, "../frontend/src/lib/brand.js"), "utf8");
  const css = readFileSync(join(root, "src/ui/base.css"), "utf8");
  for (const [name, css_var] of [
    ["INK", "--ink"],
    ["PAPER_DARK", "--paper-dark"],
    ["SURFACE", "--surface"],
    ["GLOW", "--glow"],
    ["GLOW_SOFT", "--glow-soft"],
    ["WARN", "--warn"],
    ["WEAK", "--weak"],
    ["TOTP", "--totp"],
  ]) {
    const want = new RegExp(`export const ${name} = "(#[0-9a-f]{6})"`).exec(brand)?.[1];
    const have = new RegExp(`${css_var}: (#[0-9a-f]{6});`).exec(css)?.[1];
    if (!want || want !== have) throw new Error(`brand token ${name}: ${have} != ${want}`);
  }
};

const FONTS = {
  "space-grotesk.woff2":
    "node_modules/@fontsource-variable/space-grotesk/files/space-grotesk-latin-wght-normal.woff2",
  "space-mono.woff2": "node_modules/@fontsource/space-mono/files/space-mono-latin-400-normal.woff2",
};

const buildTarget = async (target) => {
  const out = join(outRoot, target);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(join(out, "fonts"), { recursive: true });
  const entries = {
    background: "src/background/index.ts",
    popup: "src/popup/main.tsx",
    options: "src/options/main.tsx",
    bridge: "src/bridge/vault-bridge.ts",
    ...(target === "chromium" ? { offscreen: "src/offscreen/offscreen.ts" } : {}),
  };
  await esbuild.build({
    absWorkingDir: root,
    entryPoints: entries,
    outdir: out,
    bundle: true,
    format: "iife",
    platform: "browser",
    target: target === "chromium" ? ["chrome120"] : ["firefox128"],
    // Syntax only (constant folding, dead code removal), so the test-build
    // branches vanish from real builds; names and layout stay readable.
    minifySyntax: true,
    sourcemap: false,
    legalComments: "none",
    charset: "utf8",
    jsx: "automatic",
    jsxImportSource: "preact",
    define: {
      __E2E__: JSON.stringify(TEST),
      __TARGET__: JSON.stringify(target),
      __VERSION__: JSON.stringify(version),
    },
    logLevel: "warning",
  });
  await esbuild.build({
    absWorkingDir: root,
    entryPoints: { popup: "src/popup/popup.css", options: "src/options/options.css" },
    outdir: out,
    bundle: true,
    external: ["*.woff2"],
    minify: false,
    legalComments: "none",
    charset: "utf8",
    logLevel: "warning",
  });
  for (const page of ["popup/popup.html", "options/options.html"]) {
    cpSync(join(root, "src", page), join(out, page.split("/")[1]));
  }
  if (target === "chromium")
    cpSync(join(root, "src/offscreen/offscreen.html"), join(out, "offscreen.html"));
  cpSync(join(root, "src/icons"), join(out, "icons"), { recursive: true });
  for (const [name, source] of Object.entries(FONTS))
    cpSync(join(root, source), join(out, "fonts", name));
  writeFileSync(
    join(out, "manifest.json"),
    `${JSON.stringify(manifestFor(target, { test: TEST }), null, 2)}\n`
  );
  return out;
};

const popupWeight = (out) =>
  ["popup.js", "popup.css", "popup.html", "fonts/space-grotesk.woff2", "fonts/space-mono.woff2"]
    .map((file) => gzipSync(readFileSync(join(out, file)), { level: 9 }).length)
    .reduce((a, b) => a + b, 0);

// --- reproducible zip (store method for nothing, deflate for everything) ---------

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (data) => {
  let crc = 0xffffffff;
  for (const byte of data) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
};

const files = (dir) =>
  readdirSync(dir)
    .flatMap((name) => {
      const path = join(dir, name);
      return statSync(path).isDirectory() ? files(path) : [path];
    })
    .sort();

const dosTime = (epochSeconds) => {
  const d = new Date(epochSeconds * 1000);
  const time = (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | (d.getUTCSeconds() >> 1);
  const date = ((d.getUTCFullYear() - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate();
  return { time, date };
};

export const zipDirectory = (dir, epochSeconds) => {
  const { time, date } = dosTime(epochSeconds);
  const locals = [];
  const centrals = [];
  let offset = 0;
  const names = files(dir)
    .map((path) => relative(dir, path).split("\\").join("/"))
    .sort();
  for (const name of names) {
    const data = readFileSync(join(dir, name));
    const packed = deflateRawSync(data, { level: 9 });
    const nameBytes = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(0x0800, 6);
    header.writeUInt16LE(8, 8);
    header.writeUInt16LE(time, 10);
    header.writeUInt16LE(date, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(packed.length, 18);
    header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(nameBytes.length, 26);
    header.writeUInt16LE(0, 28);
    locals.push(header, nameBytes, packed);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBytes);
    offset += header.length + nameBytes.length + packed.length;
  }
  const centralSize = centrals.reduce((n, b) => n + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(names.length, 8);
  end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...centrals, end]);
};

export const packageName = (target) => `ciphermoth-extension-${target}-${version}.zip`;

const main = async () => {
  checkBrand();
  for (const target of targets) {
    const out = await buildTarget(target);
    const weight = popupWeight(out);
    console.log(`${target}: ${relative(root, out)} (popup ${(weight / 1024).toFixed(1)} KiB gzip)`);
    if (weight > BUDGET_BYTES) throw new Error(`popup over the ${BUDGET_BYTES / 1024} KiB budget`);
  }
  if (!PACKAGE) return;
  const epoch = Number(process.env.SOURCE_DATE_EPOCH ?? Date.UTC(2026, 0, 1) / 1000);
  const packages = join(outRoot, "packages");
  rmSync(packages, { recursive: true, force: true });
  mkdirSync(packages, { recursive: true });
  const sums = [];
  for (const target of targets) {
    const zip = zipDirectory(join(outRoot, target), epoch);
    const name = packageName(target);
    writeFileSync(join(packages, name), zip);
    sums.push(`${createHash("sha256").update(zip).digest("hex")}  ${name}`);
  }
  writeFileSync(join(packages, "SHA256SUMS"), `${sums.join("\n")}\n`);
  console.log(readFileSync(join(packages, "SHA256SUMS"), "utf8").trim());
};

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await main();
} else if (!existsSync(root)) {
  throw new Error("unreachable");
}
