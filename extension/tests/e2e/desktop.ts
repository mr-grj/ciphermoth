// Desktop mode in the e2e tests: the real native host (QA identity) and a
// stand-in desktop app (desktop/src-tauri/extension-link/examples/app_stub.rs)
// that runs the app's real link server against the live test backend. The
// browser finds the host through a manifest in its profile folder.

import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

import { MASTER_PASSWORD, type Stack } from "./harness";
import { E2E_DIR, EXTENSION_ROOT } from "./paths";

const CRATE = join(EXTENSION_ROOT, "../desktop/src-tauri");
const TARGET = join(E2E_DIR, "cargo");
const exe = process.platform === "win32" ? ".exe" : "";
export const HOST_BIN = join(TARGET, "debug", `native-host${exe}`);
export const STUB_BIN = join(TARGET, "debug", "examples", `app_stub${exe}`);
export const HOST_NAME = "com.ciphermoth.desktop.qa";
export const CHROMIUM_ID = "emeejhcdcdnlhejcpeohdafdnkmbaddn";

export const buildDesktopBinaries = (): void => {
  const options = {
    cwd: CRATE,
    stdio: "inherit" as const,
    env: { ...process.env, CARGO_TARGET_DIR: TARGET },
  };
  execFileSync("cargo", ["build", "-p", "ciphermoth-native-host", "--features", "qa"], options);
  execFileSync(
    "cargo",
    ["build", "-p", "ciphermoth-extension-link", "--example", "app_stub"],
    options
  );
};

export const newQaRoot = (): string => mkdtempSync(join(tmpdir(), "cm-qa-"));

// What the desktop app's switch writes (Chromium reads it from the profile).
export const hostManifestPath = (profile: string): string =>
  join(profile, "NativeMessagingHosts", `${HOST_NAME}.json`);

export const installHost = (profile: string): void => {
  mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
  writeFileSync(
    hostManifestPath(profile),
    JSON.stringify({
      name: HOST_NAME,
      description: "CipherMoth desktop app (e2e)",
      path: HOST_BIN,
      type: "stdio",
      allowed_origins: [`chrome-extension://${CHROMIUM_ID}/`],
    })
  );
};

export const uninstallHost = (profile: string): void =>
  rmSync(hostManifestPath(profile), { force: true });

export class AppStub {
  private readonly lines: string[] = [];
  private waiters: { prefix: string; resolve: (line: string) => void }[] = [];
  private constructor(private readonly child: ChildProcess) {
    createInterface({ input: child.stdout! }).on("line", (line) => {
      const waiter = this.waiters.find((w) => line.startsWith(w.prefix));
      if (waiter) {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        waiter.resolve(line);
      } else {
        this.lines.push(line);
      }
    });
  }

  static async start(qaRoot: string, stack: Stack): Promise<AppStub> {
    const child = spawn(STUB_BIN, ["--api", stack.backend, "--password", MASTER_PASSWORD], {
      env: { ...process.env, CIPHERMOTH_QA_ROOT: qaRoot },
      stdio: ["pipe", "pipe", "inherit"],
    });
    const stub = new AppStub(child);
    await stub.next("listening");
    return stub;
  }

  // The next line starting with `prefix` (already printed, or still to come).
  next(prefix: string, timeoutMs = 20_000): Promise<string> {
    const index = this.lines.findIndex((line) => line.startsWith(prefix));
    if (index >= 0) return Promise.resolve(this.lines.splice(index, 1)[0]!);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`app stub: no "${prefix}"`)), timeoutMs);
      this.waiters.push({
        prefix,
        resolve: (line) => {
          clearTimeout(timer);
          resolve(line);
        },
      });
    });
  }

  send(command: "allow" | "deny" | "lock" | "unlock" | "unpair"): void {
    this.child.stdin!.write(`${command}\n`);
  }

  async stop(): Promise<void> {
    if (this.child.exitCode !== null) return;
    const exited = new Promise((resolve) => this.child.once("exit", resolve));
    this.child.stdin!.write("quit\n");
    const timer = setTimeout(() => this.child.kill("SIGKILL"), 5000);
    await exited;
    clearTimeout(timer);
  }
}
