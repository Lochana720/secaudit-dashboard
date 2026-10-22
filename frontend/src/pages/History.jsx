import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, fmtDate } from "../api";
import { Empty, ErrorBox, GradeChip, StatusBadge } from "../components/ui";

const PAGE_SIZE = 15;

export default function History() {
  const [params, setParams] = useSearchParams();
  const target = params.get("target") || "";
  const status = params.get("status") || "";
  const page = Number(params.get("page") || 1);
  const [targets, setTargets] = useState([]);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const set = (k, v) => {
    const p = new URLSearchParams(params);
    v ? p.set(k, v) : p.delete(k);
    if (k !== "page") p.delete("page");
    setParams(p);
  };

  const load = () =>
    api.scans({ target_id: target, status, page, page_size: PAGE_SIZE }).then(setData).catch(setError);

  useEffect(() => { api.targets().then(setTargets).catch(() => {}); }, []);
  useEffect(() => { load(); }, [target, status, page]);

  const remove = async (s) => {
    if (!confirm(`Delete scan #${s.id}?`)) return;
    await api.deleteScan(s.id).catch((e) => alert(e.message));
    load();
  };

  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Scan history</h1>
          <p className="muted">{data ? `${data.total} scan${data.total === 1 ? "" : "s"}` : "…"}</p>
        </div>
      </header>

      <div className="filters">
        <select value={target} onChange={(e) => set("target", e.target.value)}>
          <option value="">All targets</option>
          {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
        <select value={status} onChange={(e) => set("status", e.target.value)}>
          <option value="">Any status</option>
          {["completed", "failed", "running", "pending"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>

      <ErrorBox error={error} />
      {!data ? <div className="loading">Loading…</div> : data.items.length === 0 ? (
        <Empty title="No scans found">Run a scan from the Targets page.</Empty>
      ) : (
        <section className="card">
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>Scan</th><th>Target</th><th>Status</th><th>Grade</th><th>Score</th><th>Issues (C/H/M/L)</th><th>Date</th><th /></tr>
              </thead>
              <tbody>
                {data.items.map((s) => {
                  const c = s.summary?.severity_counts || {};
                  return (
                    <tr key={s.id}>
                      <td><Link className="mono" to={`/scans/${s.id}`}>#{s.id}</Link></td>
                      <td>{s.target_name}<div className="muted small mono">{s.target_url}</div></td>
                      <td><StatusBadge status={s.status} /></td>
                      <td><GradeChip grade={s.grade} /></td>
                      <td className="mono">{s.score ?? "—"}</td>
                      <td className="mono">
                        {s.summary ? (
                          <>
                            <span className="sev-c">{c.critical}</span>/<span className="sev-h">{c.high}</span>/
                            <span className="sev-m">{c.medium}</span>/<span className="sev-l">{c.low}</span>
                          </>
                        ) : "—"}
                      </td>
                      <td className="muted">{fmtDate(s.created_at)}</td>
                      <td className="row-actions">
                        {s.status === "completed" && <a href={api.reportUrl(s.id)} title="PDF">PDF</a>}
                        <button className="link-btn" onClick={() => remove(s)}>Delete</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {pages > 1 && (
            <div className="pager">
              <button className="btn btn-ghost" disabled={page <= 1} onClick={() => set("page", page - 1)}>← Prev</button>
              <span className="muted">Page {page} of {pages}</span>
              <button className="btn btn-ghost" disabled={page >= pages} onClick={() => set("page", page + 1)}>Next →</button>
            </div>
          )}
        </section>
      )}
    </>
  );
}
