// Build ciphermoth-native-host for this machine and put it where Tauri's
// bundle.externalBin expects it (src-tauri/binaries/<name>-<target triple>), so
// every package ships it next to the app executable. Run by beforeBuildCommand
// (release; debug for `tauri build --debug`), tauri.qa.json (--qa: the QA
// identity) and beforeDevCommand (--debug: the development identity).
//
//   node build-native-host.mjs [--qa] [--debug]

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const args = new Set(process.argv.slice(2));
for (const arg of args) {
  if (!["--qa", "--debug"].includes(arg)) throw new Error(`unknown option ${arg}`);
}
const here = dirname(fileURLToPath(import.meta.url));
const crate = join(here, "src-tauri");
const triple = /^host: (\S+)$/m.exec(execFileSync("rustc", ["-vV"], { cwd: crate }).toString())[1];
// `tauri build --debug` runs beforeBuildCommand with TAURI_ENV_DEBUG=true: a
// debug app (development identity) needs a debug host, or the host it ships
// (release = production identity) talks to the real app's socket instead.
const debug = args.has("--debug") || process.env.TAURI_ENV_DEBUG === "true";
const profile = debug ? "debug" : "release";
const cargo = ["build", "-p", "ciphermoth-native-host", "--locked"];
if (profile === "release") cargo.push("--release");
if (args.has("--qa")) cargo.push("--features", "qa");
execFileSync("cargo", cargo, { cwd: crate, stdio: "inherit" });

const exe = triple.includes("windows") ? ".exe" : "";
const built = join(crate, "target", profile, `native-host${exe}`);
const target = join(crate, "binaries", `ciphermoth-native-host-${triple}${exe}`);
mkdirSync(dirname(target), { recursive: true });
copyFileSync(built, `${target}.partial`);
renameSync(`${target}.partial`, target);
console.log(`native host (${profile}${args.has("--qa") ? ", QA" : ""}): ${target}`);
