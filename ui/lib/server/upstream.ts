/**
 * Server-only client for the control plane. Over https it presents the
 * UI's own X.509-SVID (OMEGA_API_CLIENT_CERT / OMEGA_API_CLIENT_KEY)
 * and verifies the server against OMEGA_API_CA. The files are re-read
 * when they change, so a rotated SVID is picked up without a restart.
 */

import { readFileSync, statSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { Readable } from "node:stream";
import { upstreamConfig } from "./config";

export type UpstreamResponse = {
  status: number;
  headers: Headers;
  body: ReadableStream<Uint8Array> | null;
};

let cached: { stamp: string; agent: https.Agent } | undefined;

function agentFor(files: { ca?: string; cert?: string; key?: string }): https.Agent {
  const paths = [files.ca, files.cert, files.key];
  const stamp = paths.map((p) => (p ? `${p}:${statSync(p).mtimeMs}` : "")).join("|");
  if (cached?.stamp === stamp) return cached.agent;
  cached?.agent.destroy();
  const agent = new https.Agent({
    keepAlive: true,
    ca: files.ca ? readFileSync(files.ca) : undefined,
    cert: files.cert ? readFileSync(files.cert) : undefined,
    key: files.key ? readFileSync(files.key) : undefined,
  });
  cached = { stamp, agent };
  return agent;
}

/** omegaRequest sends one request to the control plane. path includes the query. */
export function omegaRequest(
  method: string,
  path: string,
  headers: Headers,
  body?: Uint8Array,
): Promise<UpstreamResponse> {
  const cfg = upstreamConfig();
  const url = new URL(path, cfg.url);
  const secure = url.protocol === "https:";
  const outHeaders: Record<string, string> = {};
  headers.forEach((v, k) => {
    outHeaders[k] = v;
  });
  if (body) outHeaders["content-length"] = String(body.byteLength);

  return new Promise((resolve, reject) => {
    const options: https.RequestOptions = { method, headers: outHeaders };
    let req: http.ClientRequest;
    const onResponse = (res: http.IncomingMessage) => {
      const h = new Headers();
      for (const [k, v] of Object.entries(res.headers)) {
        if (v === undefined) continue;
        for (const value of Array.isArray(v) ? v : [v]) h.append(k, value);
      }
      const empty = method === "HEAD" || res.statusCode === 204 || res.statusCode === 304;
      if (empty) res.resume();
      resolve({
        status: res.statusCode ?? 502,
        headers: h,
        body: empty ? null : (Readable.toWeb(res) as ReadableStream<Uint8Array>),
      });
    };
    try {
      req = secure
        ? https.request(url, { ...options, agent: agentFor(cfg) }, onResponse)
        : http.request(url, options, onResponse);
    } catch (err) {
      reject(err);
      return;
    }
    req.setTimeout(30_000, () => req.destroy(new Error("timed out")));
    req.on("error", reject);
    req.end(body);
  });
}

/** omegaJSON posts a JSON body and parses the JSON answer. */
export async function omegaJSON(
  path: string,
  payload: unknown,
): Promise<{ status: number; json: unknown }> {
  const res = await omegaRequest(
    "POST",
    path,
    new Headers({ "content-type": "application/json", accept: "application/json" }),
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  const text = res.body ? await new Response(res.body).text() : "";
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = { error: text.trim() };
  }
  return { status: res.status, json };
}
