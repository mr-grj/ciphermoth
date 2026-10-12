import { invoke } from "@tauri-apps/api/core";
import { coreAxios } from "./axiosAdapter";
import { CoreError, coreCancel, coreJson, coreRequest, coreStatus } from "./core";

const MASTER = "Canary-Master-7Qx-ciphermoth";
const ATTACHMENT_CANARY = "CANARY-ATTACHMENT-91c4";
const MIB = 1024 * 1024;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const randomBytes = (size) => {
  const out = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65536) {
    crypto.getRandomValues(out.subarray(offset, Math.min(size, offset + 65536)));
  }
  return out;
};

const sameBytes = (a, b) => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
};

const sha256 = async (bytes) =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const percentile = (values, p) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
};

const round = (value) => Math.round(value * 100) / 100;

export async function waitForReady(timeoutMs = 30000, accept = () => true) {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    const status = await coreStatus();
    if (status.state === "ready" && accept(status)) return status;
    if (status.state === "failed") throw new Error(`core failed: ${status.reason}`);
    await sleep(25);
  }
  throw new Error("core not ready in time");
}

const expectError = async (promise, code) => {
  try {
    await promise;
  } catch (error) {
    if (error instanceof CoreError && error.code === code) return true;
    throw new Error(`expected ${code}, got ${error.code || error.message}`);
  }
  throw new Error(`expected ${code}, got success`);
};

export async function runSuite(onProgress = () => {}) {
  const checks = [];
  const metrics = {};
  const check = async (name, fn) => {
    const started = performance.now();
    onProgress({ name, state: "running" });
    await invoke("selftest_mark", { name: `running: ${name}`, ms: started }).catch(() => {});
    try {
      const detail = await fn();
      const entry = {
        name,
        ok: true,
        ms: round(performance.now() - started),
        detail: detail ?? null,
      };
      checks.push(entry);
      onProgress({ ...entry, state: "ok" });
    } catch (error) {
      const entry = {
        name,
        ok: false,
        ms: round(performance.now() - started),
        error: String(error.message || error),
      };
      checks.push(entry);
      onProgress({ ...entry, state: "failed" });
    }
  };

  await check("core ready", async () => {
    const status = await waitForReady();
    metrics.core_ready = status;
    return status.info?.protocol;
  });

  await check("real CipherMoth route through axios adapter", async () => {
    const response = await coreAxios.get("/meta");
    if (response.status !== 200 || response.data.version !== "1.4.7") throw new Error("bad meta");
    if (response.headers["x-content-type-options"] !== "nosniff") throw new Error("headers");
    return response.data;
  });

  await check("create vault in core, key stays in core", async () => {
    const created = await coreJson("POST", "/spike/vault/create", { master_password: MASTER });
    if (created.status !== 200) throw new Error(`status ${created.status}`);
    const text = JSON.stringify(created.data);
    if (/[A-Za-z0-9_-]{43}=/.test(text)) throw new Error("key-shaped value reached the renderer");
    return created.data;
  });

  await check("small request latency (500 x health)", async () => {
    const samples = [];
    for (let i = 0; i < 500; i += 1) {
      const started = performance.now();
      const reply = await coreRequest({ path: "/spike/health" });
      samples.push(performance.now() - started);
      if (reply.status !== 200) throw new Error("status");
    }
    metrics.small_latency_ms = {
      p50: round(percentile(samples, 50)),
      p95: round(percentile(samples, 95)),
      p99: round(percentile(samples, 99)),
      mean: round(samples.reduce((a, b) => a + b, 0) / samples.length),
    };
    return metrics.small_latency_ms;
  });

  await check("binary echo is byte-identical", async () => {
    const allBytes = new Uint8Array(256 * 64).map((_, i) => i % 256);
    for (const payload of [new Uint8Array(0), allBytes, randomBytes(MIB)]) {
      const reply = await coreRequest({
        method: "POST",
        path: "/spike/echo",
        headers: [["content-type", "application/octet-stream"]],
        body: payload,
      });
      if (!sameBytes(reply.body, payload)) throw new Error(`mismatch at ${payload.length}`);
    }
  });

  await check("5 MiB attachment round trip (FormData -> pipe -> Fernet -> SQLite)", async () => {
    const data = randomBytes(5 * MIB);
    data.set(new TextEncoder().encode(ATTACHMENT_CANARY), 0);
    const form = new FormData();
    form.append("file", new Blob([data]), "synthetic.bin");
    const encodeStarted = performance.now();
    const encoded = new Response(form);
    const body = new Uint8Array(await encoded.arrayBuffer());
    const encodeMs = performance.now() - encodeStarted;
    const uploadStarted = performance.now();
    const upload = await coreRequest({
      method: "POST",
      path: "/spike/attachments",
      headers: [["content-type", encoded.headers.get("content-type")]],
      body,
    });
    const uploadMs = performance.now() - uploadStarted;
    const meta = JSON.parse(new TextDecoder().decode(upload.body));
    if (upload.status !== 200) throw new Error(`upload ${upload.status} ${JSON.stringify(meta)}`);
    const expected = await sha256(data);
    if (meta.sha256 !== expected) throw new Error("upload hash");
    const downloadStarted = performance.now();
    const download = await coreRequest({ path: `/spike/attachments/${meta.id}` });
    const downloadMs = performance.now() - downloadStarted;
    if (!sameBytes(download.body, data)) throw new Error("download bytes differ");
    metrics.attachment_5mib = {
      formdata_encode_ms: round(encodeMs),
      upload_ms: round(uploadMs),
      download_ms: round(downloadMs),
      upload_mb_s: round(5 / (uploadMs / 1000)),
      download_mb_s: round(5 / (downloadMs / 1000)),
    };
    return metrics.attachment_5mib;
  });

  await check("FormData through the axios adapter", async () => {
    const data = randomBytes(256 * 1024);
    const form = new FormData();
    form.append("file", new Blob([data]), "axios.bin");
    const response = await coreAxios.post("/spike/attachments", form, { baseURL: "/" });
    if (response.data.sha256 !== (await sha256(data))) throw new Error("hash");
  });

  await check("1000-entry decrypted listing end to end", async () => {
    await coreJson("POST", "/spike/entries/seed", undefined, "count=1000");
    const samples = [];
    for (let i = 0; i < 5; i += 1) {
      const started = performance.now();
      const reply = await coreRequest({ path: "/spike/entries" });
      const rows = JSON.parse(new TextDecoder().decode(reply.body));
      samples.push(performance.now() - started);
      if (rows.length !== 1000) throw new Error("rows");
    }
    metrics.listing_1000_ms = {
      min: round(Math.min(...samples)),
      max: round(Math.max(...samples)),
    };
    if (metrics.listing_1000_ms.max > 500) throw new Error("listing over 500 ms");
    return metrics.listing_1000_ms;
  });

  await check("listing not blocked behind a 5 MiB upload", async () => {
    const form = new FormData();
    form.append("file", new Blob([randomBytes(5 * MIB)]), "big.bin");
    const encoded = new Response(form);
    const body = new Uint8Array(await encoded.arrayBuffer());
    const started = performance.now();
    const upload = coreRequest({
      method: "POST",
      path: "/spike/attachments",
      headers: [["content-type", encoded.headers.get("content-type")]],
      body,
    }).then(() => performance.now() - started);
    const listing = coreRequest({ path: "/spike/health" }).then(() => performance.now() - started);
    const [uploadMs, healthMs] = await Promise.all([upload, listing]);
    return { upload_ms: round(uploadMs), concurrent_small_ms: round(healthMs) };
  });

  await check("concurrent requests resolve by id", async () => {
    const started = performance.now();
    const slow = Array.from({ length: 10 }, () =>
      coreRequest({ path: "/spike/sleep", query: "ms=300" })
    );
    const fastMs = await coreRequest({ path: "/spike/health" }).then(
      () => performance.now() - started
    );
    const results = await Promise.all(slow);
    const totalMs = performance.now() - started;
    if (results.some((r) => r.status !== 200)) throw new Error("status");
    if (fastMs > 250) throw new Error(`fast request waited ${fastMs} ms`);
    if (totalMs > 2000) throw new Error(`total ${totalMs} ms`);
    return { fast_ms: round(fastMs), total_ms: round(totalMs) };
  });

  await check("timeout cancels the core task", async () => {
    await expectError(
      coreRequest({ path: "/spike/sleep", query: "ms=5000", timeoutMs: 300 }),
      "timeout"
    );
    await sleep(100);
    const stats = await coreJson("GET", "/spike/stats");
    if (stats.data.cancelled < 1) throw new Error("core task not cancelled");
    return stats.data.cancelled;
  });

  await check("explicit cancellation", async () => {
    const pending = coreRequest({ path: "/spike/sleep", query: "ms=30000", clientId: "cancel-me" });
    await sleep(150);
    await coreCancel("cancel-me");
    await expectError(pending, "cancelled");
  });

  await check("python exception maps to a generic 500", async () => {
    const reply = await coreRequest({ path: "/spike/raise" });
    const text = new TextDecoder().decode(reply.body);
    if (reply.status !== 500 || text.includes("CANARY")) throw new Error(text);
  });

  await check("renderer cannot reach paths outside the allowlist", async () => {
    await expectError(coreRequest({ path: "/docs" }), "forbidden_path");
    await expectError(coreRequest({ path: "/openapi.json" }), "forbidden_path");
    await expectError(coreRequest({ path: "/spike/../api/meta" }), "forbidden_path");
  });

  await check("renderer cannot set arbitrary headers", async () => {
    await expectError(
      coreRequest({ path: "/api/meta", headers: [["x-ciphermoth-key-derivation", "x"]] }),
      "forbidden_header"
    );
  });

  await check("renderer cannot call Tauri APIs outside its capability", async () => {
    const refused = [];
    for (const command of [
      "plugin:window|close",
      "plugin:window|set_title",
      "plugin:event|emit",
      "plugin:path|resolve_directory",
      "plugin:webview|internal_toggle_devtools",
      "plugin:shell|execute",
      "plugin:fs|read_file",
    ]) {
      try {
        await invoke(command, { title: "x", event: "x", directory: 1, path: "/etc/hosts" });
      } catch (error) {
        refused.push(command);
        continue;
      }
      throw new Error(`${command} was allowed`);
    }
    return refused.length;
  });

  await check("core environment is scrubbed", async () => {
    const stats = await coreJson("GET", "/spike/stats");
    const names = stats.data.env_names;
    const leaked = names.filter(
      (n) => /^(PYTHON|LD_|DYLD_)/.test(n) || n === "CIPHERMOTH_CANARY_ENV"
    );
    if (leaked.length) throw new Error(`leaked: ${leaked.join(",")}`);
    return names;
  });

  await check("oversized request refused in Rust before the pipe", async () => {
    await expectError(
      coreRequest({ method: "POST", path: "/spike/echo", body: new Uint8Array(24 * MIB + 1) }),
      "too_large"
    );
  });

  await check("core crash fails in-flight requests, restarts locked", async () => {
    const before = await coreStatus();
    const inflight = coreRequest({ path: "/spike/sleep", query: "ms=10000" }).catch(
      (error) => error
    );
    await sleep(100);
    await expectError(
      coreRequest({ method: "POST", path: "/spike/crash", query: "mode=abort" }),
      "core_exited"
    );
    const inflightError = await inflight;
    if (inflightError.code !== "core_exited") throw new Error(`in-flight: ${inflightError.code}`);
    const started = performance.now();
    const after = await waitForReady(30000, (s) => s.info.pid !== before.info.pid);
    const restartMs = performance.now() - started;
    if (after.info.pid === before.info.pid) throw new Error("same pid");
    const status = await coreJson("GET", "/spike/vault/status");
    if (status.data.unlocked !== false) throw new Error("vault still unlocked after crash");
    metrics.restart_after_crash_ms = round(restartMs);
    return {
      old_pid: before.info.pid,
      new_pid: after.info.pid,
      restart_ms: round(restartMs),
      restarts: after.restarts,
    };
  });

  await check("memory during Argon2id", async () => {
    const reply = await coreJson("POST", "/spike/kdf");
    metrics.kdf = reply.data;
    return reply.data;
  });

  const stats = await coreJson("GET", "/spike/stats").catch(() => ({ data: null }));
  return {
    ok: checks.every((c) => c.ok),
    checks,
    metrics,
    core_stats: stats.data,
    user_agent: navigator.userAgent,
  };
}

let selftestStarted = false;

export async function maybeRunSelftest(onProgress) {
  if (selftestStarted) return null;
  selftestStarted = true;
  let scenario = null;
  try {
    scenario = await invoke("selftest_scenario");
  } catch {
    return null;
  }
  await invoke("selftest_mark", { name: "ui_ready", ms: performance.now() });
  window.addEventListener("error", (event) => {
    invoke("selftest_mark", {
      name: `js_error: ${event.message}`.slice(0, 500),
      ms: performance.now(),
    });
  });
  window.addEventListener("unhandledrejection", (event) => {
    invoke("selftest_mark", {
      name: `js_rejection: ${String(event.reason)}`.slice(0, 500),
      ms: performance.now(),
    });
  });
  if (scenario !== "ipc") return scenario;
  const report = await runSuite(onProgress);
  await invoke("selftest_finish", { report: JSON.stringify(report) });
  return scenario;
}
