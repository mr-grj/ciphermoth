// Only imported by a dedicated QA frontend build. Runs inside the native webview.
import { invoke } from "@tauri-apps/api/core";
import api from "../api/client";
import { coreStatus, coreRequest } from "./core";
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(fn) {
  for (let n = 0; n < 200; n++) {
    const result = fn();
    if (result) return result;
    await pause(100);
  }
  throw new Error("UI condition timed out");
}
function input(label, value) {
  const node = [...document.querySelectorAll("label")].find(
    (x) => x.textContent.replace(/\s*\*$/, "") === label
  );
  const field = node && document.getElementById(node.htmlFor);
  if (!field) throw new Error(`Missing field: ${label}`);
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(field, value);
  field.dispatchEvent(new Event("input", { bubbles: true }));
}
const button = (label) =>
  [...document.querySelectorAll("button")].find((x) => x.textContent === label && !x.disabled);
const checks = [];
try {
  await until(
    () =>
      button("Create Vault") ||
      button("Unlock Vault") ||
      document.querySelector('input[type="checkbox"]')
  );
  const interactiveMs = Math.round(performance.now());
  if (!sessionStorage.getItem("qa-interactive-ms")) {
    sessionStorage.setItem("qa-interactive-ms", String(interactiveMs));
    await invoke("qa_report", {
      result: { stage: "interactive", interactive_ms: interactiveMs, core: await coreStatus() },
    });
  }
  const fresh = !!document.querySelector('input[type="checkbox"]');
  input("Master Password", sessionStorage.getItem("qa-password") || "Desktop-GUI-Canary-2026!");
  if (fresh) {
    input("Confirm Master Password", "Desktop-GUI-Canary-2026!");
    document.querySelector('input[type="checkbox"]').click();
  }
  await pause(100);
  (await until(() => button(fresh ? "Create Vault" : "Unlock Vault"))).click();
  await until(() => button("Log out"));
  checks.push(fresh ? "create vault through UI" : "unlock persisted vault through UI");
  if (fresh) {
    (await until(() => button("Add First Password"))).click();
    await until(() =>
      [...document.querySelectorAll("label")].some((x) => x.textContent.startsWith("Name"))
    );
    input("Name", "Native GUI entry");
    input("Password", "Native-GUI-password-canary!");
    await pause(100);
    (await until(() => button("Create"))).click();
    // A disabled submit button means the request is in flight, not completed.
    await until(
      () => ![...document.querySelectorAll("button")].some((x) => x.textContent === "Create")
    );
    checks.push("create password through UI");
  }
  const { data } = await api.get("/passwords");
  if (
    !data.some(
      (row) =>
        row.password_name === "Native GUI entry" &&
        row.password_value === "Native-GUI-password-canary!"
    )
  )
    throw new Error("saved entry not found");
  checks.push("retrieve password through native IPC");
  const search = await until(() => document.querySelector('input[placeholder^="Search name"]'));
  const setSearch = (value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(search, value);
    search.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const hasEntryRow = () =>
    [...document.querySelectorAll('[role="row"]')].some((row) =>
      row.textContent.includes("Native GUI entry")
    );
  setSearch("no-match-synthetic-qa");
  await until(() => !hasEntryRow());
  setSearch("Native GUI entry");
  await until(hasEntryRow);
  setSearch("");
  checks.push("search filters and restores the native vault rows");
  if (fresh) {
    const { workflows } = await import("./qaWorkflows");
    await workflows(checks);
    const { extensionWorkflow } = await import("./qaExtension");
    await extensionWorkflow(checks);
  }
  if (import.meta.env.VITE_DESKTOP_DIALOG_QA === "1" && !sessionStorage.getItem("qa-files")) {
    const { getSessionToken } = await import("../utils");
    const session = getSessionToken();
    await invoke("qa_report", { result: { stage: "backup_save" } });
    const saved = await invoke("backup_export", {
      session,
      password: "Desktop-GUI-Canary-2026!",
    });
    if (!saved.saved) throw new Error("native backup not saved");
    await invoke("qa_report", { result: { stage: "backup_open" } });
    const selected = await invoke("choose_backup");
    if (!selected?.ticket || selected.path) throw new Error("invalid native file grant");
    const restored = await invoke("backup_import", {
      session,
      password: "Desktop-GUI-Canary-2026!",
      ticket: selected.ticket,
      onConflict: "skip",
    });
    if (restored.skipped < 1) throw new Error("native backup did not restore");
    sessionStorage.setItem("qa-files", "done");
    checks.push("native backup save/open dialogs and restore");
  }
  const denied = [
    "plugin:shell|execute",
    "plugin:fs|read_file",
    "plugin:window|close",
    "plugin:updater|check",
    "plugin:updater|download_and_install",
  ];
  for (const command of denied) {
    let refused = false;
    try {
      await invoke(command, {});
    } catch {
      refused = true;
    }
    if (!refused) throw new Error("capability accepted");
  }
  checks.push("ungranted capabilities refused");
  let timeout = false;
  try {
    await coreRequest({
      method: "POST",
      path: "/api/master_password/unlock",
      headers: [["content-type", "application/json"]],
      body: new TextEncoder().encode(
        JSON.stringify({ master_password: "Desktop-GUI-Canary-2026!" })
      ),
      timeoutMs: 1,
    });
  } catch (error) {
    timeout = error.code === "timeout";
  }
  if (!timeout) throw new Error("native timeout not enforced");
  checks.push("native timeout cancels real KDF request");
  await invoke("clipboard_write", { value: "Native-clipboard-canary", timeoutMs: 1000 });
  await invoke("qa_report", { result: { stage: "clipboard_timeout" } });
  await pause(1800);
  await invoke("clipboard_write", { value: "Native-clipboard-canary", timeoutMs: 1000 });
  await invoke("qa_report", { result: { stage: "clipboard_replaced" } });
  await pause(1800);
  checks.push("native clipboard command");
  await pause(1200);
  const stage = sessionStorage.getItem("qa-lock-stage");
  if (!stage) {
    sessionStorage.setItem("qa-checks", JSON.stringify(checks));
    sessionStorage.setItem("qa-fresh", JSON.stringify(fresh));
    sessionStorage.setItem("qa-lock-stage", "manual");
    button("Log out").click();
  } else if (stage === "manual") {
    sessionStorage.setItem("qa-lock-stage", "idle");
    await api.patch("/settings", {
      inactivity_ms: 30000,
      warn_before_ms: 5000,
      hidden_ms: 60000,
      debounce_ms: 1000,
      clipboard_clear_ms: 30000,
      update_check_enabled: false,
    });
    await invoke("qa_report", { result: { stage: "native_idle", core: await coreStatus() } });
    // Deliberately starve this real WebView's event loop. The host must observe
    // core termination before JS timers or this script can run again.
    const blockedUntil = performance.now() + 35000;
    while (performance.now() < blockedUntil) {
      /* QA only */
    }
  } else if (stage === "idle") {
    await api.patch("/settings", {
      inactivity_ms: 120000,
      warn_before_ms: 60000,
      hidden_ms: 60000,
      debounce_ms: 1000,
      clipboard_clear_ms: 30000,
      update_check_enabled: false,
    });
    sessionStorage.setItem("qa-lock-stage", "native");
    await invoke("qa_lock");
  } else if (stage === "native") {
    sessionStorage.setItem("qa-lock-stage", "rotation");
    sessionStorage.setItem("qa-password", "Desktop-Rotated-Canary-2027!");
    await api.patch("/master_password/update", {
      master_password: "Desktop-GUI-Canary-2026!",
      new_master_password: "Desktop-Rotated-Canary-2027!",
    });
  } else if (stage === "rotation") {
    const old = await api.post("/master_password/unlock", {
      master_password: "Desktop-GUI-Canary-2026!",
    });
    if (old.data.valid) throw new Error("old password survived rotation");
    sessionStorage.setItem("qa-lock-stage", "rotation-back");
    sessionStorage.removeItem("qa-password");
    await api.patch("/master_password/update", {
      master_password: "Desktop-Rotated-Canary-2027!",
      new_master_password: "Desktop-GUI-Canary-2026!",
    });
  } else if (stage === "rotation-back") {
    sessionStorage.setItem("qa-lock-stage", "shortcut");
    document.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: "L",
        code: "KeyL",
        metaKey: true,
        ctrlKey: true,
        shiftKey: true,
        bubbles: true,
      })
    );
  } else {
    await invoke("clipboard_write", { value: "Native-quit-clipboard-canary", timeoutMs: 300000 });
    await invoke("qa_report", {
      result: {
        ok: true,
        fresh: JSON.parse(sessionStorage.getItem("qa-fresh")),
        checks: [
          ...JSON.parse(sessionStorage.getItem("qa-checks")),
          "manual lock then UI unlock",
          "native idle lock while WebView timers cannot execute",
          "native lock callback then UI unlock",
          "master password rotated through Tauri; old password rejected; UI unlock with new password",
          "lock keyboard shortcut then UI unlock",
        ],
        core: await coreStatus(),
        backup: JSON.parse(sessionStorage.getItem("qa-backup-metrics") || "null"),
        interactive_ms: Number(sessionStorage.getItem("qa-interactive-ms")),
      },
    });
  }
} catch (error) {
  await invoke("qa_report", {
    result: {
      ok: false,
      checks,
      error: error.message,
      text: document.body.innerText.slice(0, 1500),
    },
  });
}
