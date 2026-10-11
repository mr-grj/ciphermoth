import axios from "axios";
import { coreRequest } from "./core";

const toBytes = async (data, headers) => {
  if (data === undefined || data === null) return { body: undefined };
  if (data instanceof FormData) {
    const encoded = new Response(data);
    return {
      body: new Uint8Array(await encoded.arrayBuffer()),
      contentType: encoded.headers.get("content-type"),
    };
  }
  if (data instanceof Uint8Array) return { body: data };
  if (data instanceof ArrayBuffer) return { body: new Uint8Array(data) };
  if (typeof data === "string") return { body: new TextEncoder().encode(data) };
  return {
    body: new TextEncoder().encode(JSON.stringify(data)),
    contentType: headers["Content-Type"] || "application/json",
  };
};

export async function ipcAdapter(config) {
  const url = new URL(axios.getUri(config), "http://core.invalid");
  const headers = config.headers?.toJSON ? config.headers.toJSON() : { ...config.headers };
  const { body, contentType } = await toBytes(config.data, headers);
  const forwarded = [];
  if (contentType) forwarded.push(["content-type", contentType]);
  else if (headers["Content-Type"]) forwarded.push(["content-type", headers["Content-Type"]]);
  if (headers["x-ciphermoth-entry"])
    forwarded.push(["x-ciphermoth-entry", headers["x-ciphermoth-entry"]]);
  const reply = await coreRequest({
    method: config.method.toUpperCase(),
    path: url.pathname,
    query: url.search.replace(/^\?/, ""),
    headers: forwarded,
    body,
    timeoutMs: config.timeout || 30000,
  });
  const responseHeaders = Object.fromEntries(reply.headers);
  let data = reply.body;
  if (config.responseType !== "arraybuffer" && config.responseType !== "blob") {
    const text = new TextDecoder().decode(reply.body);
    try {
      data = text ? JSON.parse(text) : "";
    } catch {
      data = text;
    }
  }
  const response = {
    data,
    status: reply.status,
    statusText: "",
    headers: responseHeaders,
    config,
    request: null,
  };
  if (config.validateStatus && !config.validateStatus(reply.status)) {
    throw new axios.AxiosError(
      `Request failed with status code ${reply.status}`,
      axios.AxiosError.ERR_BAD_RESPONSE,
      config,
      null,
      response
    );
  }
  return response;
}

export const coreAxios = axios.create({ baseURL: "/api", adapter: ipcAdapter });
