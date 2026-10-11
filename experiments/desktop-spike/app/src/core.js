import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const asciiJson = (value) =>
  JSON.stringify(value).replace(
    /[\u007f-￿]/g,
    (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0")
  );

export class CoreError extends Error {
  constructor(code, message) {
    super(message || code);
    this.code = code;
  }
}

const parseError = (raw) => {
  try {
    const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
    return new CoreError(parsed.code, parsed.message);
  } catch {
    return new CoreError("unknown", String(raw));
  }
};

export async function coreRequest({
  method = "GET",
  path,
  query = "",
  headers = [],
  body,
  timeoutMs = 30000,
  clientId,
}) {
  const payload =
    body instanceof Uint8Array ? body : body ? new Uint8Array(body) : new Uint8Array(0);
  const meta = asciiJson({
    method,
    path,
    query,
    headers,
    timeout_ms: timeoutMs,
    client_id: clientId ?? null,
  });
  let buffer;
  try {
    buffer = await invoke("core_request", payload, { headers: { "x-core-meta": meta } });
  } catch (raw) {
    throw parseError(raw);
  }
  const bytes = new Uint8Array(buffer);
  const metaLength = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0);
  const head = JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + metaLength)));
  return { status: head.status, headers: head.headers, body: bytes.subarray(4 + metaLength) };
}

export const coreJson = async (method, path, payload, query = "") => {
  const reply = await coreRequest({
    method,
    path,
    query,
    headers: payload === undefined ? [] : [["content-type", "application/json"]],
    body: payload === undefined ? undefined : new TextEncoder().encode(JSON.stringify(payload)),
  });
  const text = new TextDecoder().decode(reply.body);
  return { status: reply.status, data: text ? JSON.parse(text) : null };
};

export const coreCancel = (clientId) => invoke("core_cancel", { clientId });
export const coreStatus = () => invoke("core_status");
export const coreRestart = () => invoke("core_restart");
export const onCoreStatus = (handler) => listen("core-status", (event) => handler(event.payload));
