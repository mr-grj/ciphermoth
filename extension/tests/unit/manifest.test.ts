import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

// @ts-expect-error -- plain ESM build script without types
import { manifestFor, zipDirectory } from "../../scripts/build.mjs";

const ROOT = join(import.meta.dirname, "../..");

describe("real builds", () => {
  it("contain none of the test build's hooks or permissions", () => {
    execFileSync("node", ["scripts/build.mjs"], { cwd: ROOT, stdio: "ignore" });
    for (const target of ["chromium", "firefox"]) {
      for (const file of ["background.js", "popup.js", "options.js", "bridge.js"]) {
        const code = readFileSync(join(ROOT, "dist", target, file), "utf8");
        expect(code, `${target}/${file}`).not.toContain("__ciphermothE2E");
        expect(code, `${target}/${file}`).not.toContain("location.hash");
      }
      const manifest = JSON.parse(
        readFileSync(join(ROOT, "dist", target, "manifest.json"), "utf8")
      );
      expect(manifest.host_permissions).toBeUndefined();
      expect(manifest.name).toBe("CipherMoth");
    }
  }, 60_000);
});

const CSP =
  "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

describe("the shipped manifests", () => {
  it.each(["chromium", "firefox"])("%s asks for the least it can", (target) => {
    const manifest = manifestFor(target);
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions).toEqual(
      target === "chromium"
        ? ["activeTab", "scripting", "storage", "alarms", "clipboardWrite", "offscreen"]
        : ["activeTab", "scripting", "storage", "alarms", "clipboardWrite"]
    );
    expect(manifest.optional_permissions).toEqual(["clipboardRead"]);
    expect(manifest.optional_host_permissions).toEqual([
      "https://*/*",
      "http://localhost/*",
      "http://127.0.0.1/*",
      "http://[::1]/*",
    ]);
    expect(manifest.host_permissions).toBeUndefined();
    expect(manifest.content_scripts).toBeUndefined();
    expect(manifest.web_accessible_resources).toBeUndefined();
    expect(manifest.content_security_policy).toEqual({ extension_pages: CSP });
    for (const banned of [
      "tabs",
      "<all_urls>",
      "webRequest",
      "cookies",
      "history",
      "nativeMessaging",
    ]) {
      expect(JSON.stringify(manifest.permissions)).not.toContain(banned);
    }
    expect(Object.keys(manifest.commands)).toEqual(["_execute_action", "fill-login"]);
    expect(manifest.commands["fill-login"].suggested_key).toEqual({
      default: "Ctrl+Shift+L",
      mac: "Command+Shift+L",
    });
    expect(manifest.commands._execute_action.suggested_key).toEqual({ default: "Alt+Shift+M" });
  });

  it("chromium accepts no message from other extensions or pages", () => {
    const manifest = manifestFor("chromium");
    expect(manifest.externally_connectable).toEqual({ ids: [], matches: [] });
    expect(manifest.background).toEqual({ service_worker: "background.js" });
    expect(manifest.minimum_chrome_version).toBe("120");
  });

  it("firefox has a fixed id and declares it collects nothing", () => {
    const manifest = manifestFor("firefox");
    expect(manifest.browser_specific_settings.gecko).toEqual({
      id: "ciphermoth@mr-grj.github.io",
      strict_min_version: "128.0",
      data_collection_permissions: { required: ["none"] },
    });
    expect(manifest.background).toEqual({ scripts: ["background.js"] });
  });

  it("only the test build has host permissions", () => {
    const test = manifestFor("chromium", { test: true });
    expect(test.host_permissions).toEqual(["https://*/*", "http://*/*"]);
    expect(test.name).toContain("test build");
  });

  it("matches the version in package.json", () => {
    const { version } = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
    expect(manifestFor("chromium").version).toBe(version);
    expect(manifestFor("firefox").version).toBe(version);
  });
});

describe("reproducible packages", () => {
  it("zips the same tree to the same bytes, entries sorted", () => {
    const dir = mkdtempSync(join(tmpdir(), "cm-zip-"));
    mkdirSync(join(dir, "b"));
    writeFileSync(join(dir, "b", "two.txt"), "two");
    writeFileSync(join(dir, "a.txt"), "one");
    const first = zipDirectory(dir, 1_767_225_600);
    const second = zipDirectory(dir, 1_767_225_600);
    expect(Buffer.compare(first, second)).toBe(0);
    const text = first.toString("latin1");
    expect(text.indexOf("a.txt")).toBeLessThan(text.indexOf("b/two.txt"));
    expect(first.readUInt32LE(0)).toBe(0x04034b50);
  });
});
