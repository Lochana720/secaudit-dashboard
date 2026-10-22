import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, timeAgo } from "../api";
import { Empty, ErrorBox, GradeChip } from "../components/ui";

function Copy({ text }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-ghost btn-xs"
      onClick={() => navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); })}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

function Verification({ target, onVerified }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const v = target.verification;

  const run = async () => {
    setBusy(true);
    setResult(null);
    try {
      const r = await api.verifyTarget(target.id);
      setResult(r);
      if (r.verified) onVerified();
    } catch (e) {
      setResult({ verified: false, detail: e.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="verify">
      <p>Prove you control <strong>{target.hostname}</strong> using <em>one</em> of these methods, then click Verify.</p>
      <div className="verify-grid">
        <div className="verify-opt">
          <h4>Option A · DNS TXT record</h4>
          <label>Name</label>
          <div className="code-row"><code>{v.dns_record_name}</code><Copy text={v.dns_record_name} /></div>
          <label>Value</label>
          <div className="code-row"><code>{v.dns_record_value}</code><Copy text={v.dns_record_value} /></div>
        </div>
        <div className="verify-opt">
          <h4>Option B · Upload a file</h4>
          <label>URL</label>
          <div className="code-row"><code>{v.file_url}</code><Copy text={v.file_url} /></div>
          <label>File content</label>
          <div className="code-row"><code>{v.file_content}</code><Copy text={v.file_content} /></div>
        </div>
      </div>
      <div className="row">
        <button className="btn btn-primary" onClick={run} disabled={busy}>{busy ? "Checking…" : "Verify ownership"}</button>
        {result && (
          <span className={result.verified ? "ok-text" : "err-text"}>
            {result.verified ? "✓ Verified — you can scan now." : result.detail}
          </span>
        )}
      </div>
    </div>
  );
}

export default function Targets({ config }) {
  const [targets, setTargets] = useState(null);
  const [error, setError] = useState(null);
  const [form, setForm] = useState({ name: "", url: "" });
  const [formErr, setFormErr] = useState(null);
  const [saving, setSaving] = useState(false);
  const [open, setOpen] = useState(null);
  const [consent, setConsent] = useState(false);
  const [scanning, setScanning] = useState(null);
  const navigate = useNavigate();

  const load = () => api.targets().then(setTargets).catch(setError);
  useEffect(() => { load(); }, []);

  const add = async (e) => {
    e.preventDefault();
    setFormErr(null);
    setSaving(true);
    try {
      const t = await api.createTarget(form);
      setForm({ name: "", url: "" });
      setConsent(false);
      await load();
      if (!t.verified) setOpen(t.id);
    } catch (err) {
      setFormErr(err.message);
    } finally {
      setSaving(false);
    }
  };

  const scan = async (t) => {
    setScanning(t.id);
    try {
      const s = await api.startScan(t.id);
      navigate(`/scans/${s.id}`);
    } catch (err) {
      alert(err.message);
      setScanning(null);
    }
  };

  const remove = async (t) => {
    if (!confirm(`Delete ${t.name} and all of its scans?`)) return;
    await api.deleteTarget(t.id).catch((e) => alert(e.message));
    load();
  };

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Targets</h1>
          <p className="muted">Websites you are authorised to audit.</p>
        </div>
      </header>

      <form className="card add-form" onSubmit={add}>
        <h2>Add a website</h2>
        <div className="form-row">
          <input placeholder="Display name (e.g. Company site)" value={form.name} required maxLength={120}
            onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input placeholder="https://example.com" value={form.url} required
            onChange={(e) => setForm({ ...form, url: e.target.value })} />
          <button className="btn btn-primary" disabled={saving || !consent}>{saving ? "Adding…" : "Add target"}</button>
        </div>
        <label className="consent">
          <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
          I own this website or have written permission from its owner to perform security testing.
        </label>
        {config?.skip_verification && <p className="dev-note">Dev mode: new targets are auto-verified.</p>}
        {formErr && <div className="alert alert-error">{formErr}</div>}
      </form>

      <ErrorBox error={error} />
      {!targets ? <div className="loading">Loading…</div> : targets.length === 0 ? (
        <Empty title="No websites added">Add a site above to get started.</Empty>
      ) : (
        <div className="target-list">
          {targets.map((t) => (
            <div key={t.id} className="card target">
              <div className="target-main">
                <GradeChip grade={t.last_grade} size="md" />
                <div className="target-info">
                  <div className="target-title">
                    <strong>{t.name}</strong>
                    {t.verified
                      ? <span className="pill pill-ok">✓ verified{t.verification_method ? ` · ${t.verification_method}` : ""}</span>
                      : <span className="pill pill-warn">unverified</span>}
                  </div>
                  <span className="mono muted">{t.url}</span>
                  <span className="muted small">
                    {t.scan_count} scan{t.scan_count === 1 ? "" : "s"} · last {timeAgo(t.last_scan_at)}
                    {t.last_scan_id && <> · <Link to={`/scans/${t.last_scan_id}`}>latest report</Link></>}
                    {t.scan_count > 0 && <> · <Link to={`/history?target=${t.id}`}>history</Link></>}
                  </span>
                </div>
                <div className="target-actions">
                  {!t.verified && (
                    <button className="btn btn-ghost" onClick={() => setOpen(open === t.id ? null : t.id)}>
                      {open === t.id ? "Hide" : "Verify"}
                    </button>
                  )}
                  <button className="btn btn-primary" disabled={!t.verified || scanning === t.id} onClick={() => scan(t)}>
                    {scanning === t.id ? "Starting…" : "Scan now"}
                  </button>
                  <button className="btn btn-danger-ghost" onClick={() => remove(t)} title="Delete">✕</button>
                </div>
              </div>
              {open === t.id && !t.verified && <Verification target={t} onVerified={load} />}
            </div>
          ))}
        </div>
      )}
    </>
  );
}
