const BASE = import.meta.env.VITE_API_BASE || "";

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const j = await res.json();
      if (j.detail) msg = typeof j.detail === "string" ? j.detail : j.detail.map((d) => d.msg).join(", ");
    } catch {
      /* non-JSON error */
    }
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

const post = (path, body) => req(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });

export const api = {
  config: () => req("/api/config"),
  dashboard: () => req("/api/dashboard"),
  targets: () => req("/api/targets"),
  createTarget: (body) => post("/api/targets", body),
  deleteTarget: (id) => req(`/api/targets/${id}`, { method: "DELETE" }),
  verifyTarget: (id) => post(`/api/targets/${id}/verify`),
  startScan: (target_id) => post("/api/scans", { target_id }),
  scans: (params = {}) => {
    const clean = Object.fromEntries(Object.entries(params).filter(([, v]) => v !== "" && v != null));
    return req("/api/scans?" + new URLSearchParams(clean));
  },
  scan: (id) => req(`/api/scans/${id}`),
  diff: (id) => req(`/api/scans/${id}/diff`),
  deleteScan: (id) => req(`/api/scans/${id}`, { method: "DELETE" }),
  reportUrl: (id) => `${BASE}/api/scans/${id}/report.pdf`,
};

// Backend may return naive UTC timestamps (SQLite); treat them as UTC.
export function parseDate(s) {
  if (!s) return null;
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : s + "Z");
}

export function fmtDate(s, withTime = true) {
  const d = parseDate(s);
  if (!d) return "—";
  return d.toLocaleString(undefined, withTime
    ? { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }
    : { year: "numeric", month: "short", day: "numeric" });
}

export function timeAgo(s) {
  const d = parseDate(s);
  if (!d) return "never";
  const sec = Math.round((Date.now() - d.getTime()) / 1000);
  if (sec < 60) return "just now";
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const SEV_COLOR = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#facc15",
  low: "#60a5fa",
  info: "#94a3b8",
};
export const GRADE_COLOR = { "A+": "#22c55e", A: "#4ade80", B: "#a3e635", C: "#facc15", D: "#fb923c", F: "#f43f5e" };
