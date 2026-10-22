import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, fmtDate, SEV_COLOR, SEVERITIES } from "../api";
import { ErrorBox, ScoreRing, SeverityBadge, StatusBadge } from "../components/ui";

const CATEGORY_LABEL = {
  tls: "TLS / Certificate", headers: "Security headers", cookies: "Cookies", transport: "Transport",
  cors: "CORS", disclosure: "Info disclosure", content: "Page content", dns: "DNS / Email", policy: "Policy",
};

function FindingCard({ f }) {
  const [open, setOpen] = useState(!f.passed && (f.severity === "critical" || f.severity === "high"));
  return (
    <div className={`finding ${f.passed ? "is-pass" : ""}`} style={{ "--c": f.passed ? "var(--ok)" : SEV_COLOR[f.severity] }}>
      <button className="finding-head" onClick={() => setOpen(!open)}>
        <SeverityBadge severity={f.severity} passed={f.passed} />
        <span className="finding-title">{f.title}</span>
        <span className="muted small">{CATEGORY_LABEL[f.category] || f.category}</span>
        <span className="chev">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="finding-body">
          {f.description && <p>{f.description}</p>}
          {f.recommendation && <p className="fix"><strong>How to fix:</strong> {f.recommendation}</p>}
          {f.evidence && <pre className="evidence">{f.evidence}</pre>}
          {f.reference && <a href={f.reference} target="_blank" rel="noreferrer">Learn more ↗</a>}
        </div>
      )}
    </div>
  );
}

function Running({ scan }) {
  return (
    <div className="card running">
      <div className="spinner" />
      <div>
        <h2>Scan #{scan.id} is {scan.status}…</h2>
        <p className="muted">Checking TLS, headers, cookies, CORS, DNS and more on {scan.target_url}. This usually takes 5–20 seconds.</p>
      </div>
    </div>
  );
}

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [diff, setDiff] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("findings");
  const [sev, setSev] = useState("all");
  const [cat, setCat] = useState("all");
  const [showPassed, setShowPassed] = useState(false);
  const [rescanning, setRescanning] = useState(false);

  useEffect(() => {
    let timer;
    let alive = true;
    setScan(null);
    setDiff(null);
    const load = async () => {
      try {
        const s = await api.scan(id);
        if (!alive) return;
        setScan(s);
        if (s.status === "pending" || s.status === "running") timer = setTimeout(load, 2000);
        else if (s.status === "completed") api.diff(id).then((d) => alive && setDiff(d)).catch(() => {});
      } catch (e) {
        if (alive) setError(e);
      }
    };
    load();
    return () => { alive = false; clearTimeout(timer); };
  }, [id]);

  const failed = useMemo(() => (scan?.findings || []).filter((f) => !f.passed), [scan]);
  const categories = useMemo(() => [...new Set((scan?.findings || []).map((f) => f.category))], [scan]);
  const visible = useMemo(() => {
    const list = (scan?.findings || []).filter((f) =>
      (showPassed || !f.passed) && (sev === "all" || (!f.passed && f.severity === sev)) && (cat === "all" || f.category === cat));
    return list.sort((a, b) => (a.passed - b.passed) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  }, [scan, sev, cat, showPassed]);

  const rescan = async () => {
    setRescanning(true);
    try {
      const s = await api.startScan(scan.target_id);
      navigate(`/scans/${s.id}`);
    } catch (e) {
      alert(e.message);
    } finally {
      setRescanning(false);
    }
  };

  if (error) return <ErrorBox error={error} />;
  if (!scan) return <div className="loading">Loading scan…</div>;

  const head = (
    <header className="page-head">
      <div>
        <Link to="/history" className="back">← Scan history</Link>
        <h1>{scan.target_name}</h1>
        <p className="muted mono">{scan.target_url}</p>
      </div>
      <div className="row">
        <StatusBadge status={scan.status} />
        {scan.status === "completed" && <a className="btn btn-ghost" href={api.reportUrl(scan.id)}>⤓ Export PDF</a>}
        {!["pending", "running"].includes(scan.status) && (
          <button className="btn btn-primary" onClick={rescan} disabled={rescanning}>{rescanning ? "Starting…" : "Re-scan"}</button>
        )}
      </div>
    </header>
  );

  if (scan.status === "pending" || scan.status === "running") return <>{head}<Running scan={scan} /></>;
  if (scan.status === "failed") {
    return (
      <>
        {head}
        <div className="alert alert-error"><strong>Scan failed.</strong> {scan.error}</div>
      </>
    );
  }

  const counts = scan.summary?.severity_counts || {};
  const tls = scan.meta?.tls || {};
  const headers = scan.meta?.response_headers || {};

  return (
    <>
      {head}
      <section className="card summary">
        <ScoreRing score={scan.score} grade={scan.grade} />
        <div className="summary-body">
          <div className="sev-row">
            {SEVERITIES.map((s) => (
              <button key={s} className={`sev-count ${sev === s ? "active" : ""}`} style={{ "--c": SEV_COLOR[s] }}
                onClick={() => { setTab("findings"); setSev(sev === s ? "all" : s); }}>
                <span className="n">{counts[s] || 0}</span>
                <span className="l">{s}</span>
              </button>
            ))}
          </div>
          <p className="muted small">
            {scan.summary?.passed}/{scan.summary?.total_checks} checks passed · scanned {fmtDate(scan.finished_at)} ·{" "}
            {(scan.duration_ms / 1000).toFixed(1)}s
          </p>
          {diff?.previous_scan_id && (
            <div className="diff">
              <span className={diff.score_delta > 0 ? "up" : diff.score_delta < 0 ? "down" : ""}>
                {diff.score_delta > 0 ? "▲" : diff.score_delta < 0 ? "▼" : "●"} {diff.score_delta > 0 ? "+" : ""}{diff.score_delta} pts
              </span>
              <span>vs <Link to={`/scans/${diff.previous_scan_id}`}>scan #{diff.previous_scan_id}</Link></span>
              <span className="ok-text">{diff.resolved_issues.length} resolved</span>
              <span className="err-text">{diff.new_issues.length} new</span>
              <span className="muted">{diff.unchanged_count} unchanged</span>
            </div>
          )}
        </div>
      </section>

      {diff && (diff.new_issues.length > 0 || diff.resolved_issues.length > 0) && (
        <section className="card diff-detail">
          {diff.resolved_issues.length > 0 && (
            <div><h3 className="ok-text">Resolved since last scan</h3>
              <ul>{diff.resolved_issues.map((i) => <li key={i.check_id + i.title}>✓ {i.title}</li>)}</ul></div>
          )}
          {diff.new_issues.length > 0 && (
            <div><h3 className="err-text">New issues</h3>
              <ul>{diff.new_issues.map((i) => <li key={i.check_id + i.title}><SeverityBadge severity={i.severity} /> {i.title}</li>)}</ul></div>
          )}
        </section>
      )}

      <div className="tabs">
        {[["findings", `Findings (${failed.length})`], ["tls", "TLS & certificate"], ["headers", "Response headers"]].map(([k, l]) => (
          <button key={k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>{l}</button>
        ))}
      </div>

      {tab === "findings" && (
        <section>
          <div className="filters">
            <select value={sev} onChange={(e) => setSev(e.target.value)}>
              <option value="all">All severities</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <select value={cat} onChange={(e) => setCat(e.target.value)}>
              <option value="all">All categories</option>
              {categories.map((c) => <option key={c} value={c}>{CATEGORY_LABEL[c] || c}</option>)}
            </select>
            <label className="toggle">
              <input type="checkbox" checked={showPassed} onChange={(e) => setShowPassed(e.target.checked)} />
              Show passed checks
            </label>
          </div>
          {visible.length === 0 ? <p className="muted card">No findings match these filters.</p>
            : visible.map((f) => <FindingCard key={f.id} f={f} />)}
        </section>
      )}

      {tab === "tls" && (
        <section className="card">
          {!tls.available ? <p className="err-text">HTTPS unavailable: {tls.error}</p> : (
            <dl className="kv">
              {[
                ["Protocol", tls.protocol], ["Cipher", `${tls.cipher} (${tls.cipher_bits} bits)`],
                ["Subject", tls.subject], ["Issuer", tls.issuer], ["Trusted", tls.trusted ? "Yes" : `No — ${tls.verify_error}`],
                ["Valid from", fmtDate(tls.not_before)], ["Valid until", `${fmtDate(tls.not_after)} (${tls.days_left} days left)`],
                ["Key", `${tls.key_type} ${tls.key_bits ?? ""}`], ["Signature", tls.signature_hash],
                ["TLS 1.0 / 1.1", Object.entries(tls.legacy_protocols || {}).map(([k, v]) => `${k}: ${v.replace("_", " ")}`).join(" · ")],
                ["SANs", (tls.sans || []).join(", ") || "—"], ["Serial", tls.serial],
              ].map(([k, v]) => <div key={k}><dt>{k}</dt><dd className="mono">{v}</dd></div>)}
            </dl>
          )}
        </section>
      )}

      {tab === "headers" && (
        <section className="card">
          <p className="muted small">
            Final URL <span className="mono">{scan.meta?.final_url}</span> · HTTP {scan.meta?.status_code} · {scan.meta?.http_version}
            {scan.meta?.redirect_chain?.length > 0 && <> · redirects: {scan.meta.redirect_chain.join(" → ")}</>}
          </p>
          <table className="table headers-table">
            <tbody>
              {Object.entries(headers).map(([k, v]) => (
                <tr key={k}><td className="mono hk">{k}</td><td className="mono">{v}</td></tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}
