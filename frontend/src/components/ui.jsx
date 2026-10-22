import { Link } from "react-router-dom";
import { GRADE_COLOR, SEV_COLOR } from "../api";

export function SeverityBadge({ severity, passed }) {
  if (passed) return <span className="badge badge-pass">PASS</span>;
  return (
    <span className="badge" style={{ "--c": SEV_COLOR[severity] }}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }) {
  return <span className={`status status-${status}`}>{status}</span>;
}

export function GradeChip({ grade, size = "sm" }) {
  if (!grade) return <span className="muted">—</span>;
  return (
    <span className={`grade grade-${size}`} style={{ "--c": GRADE_COLOR[grade] }}>
      {grade}
    </span>
  );
}

export function ScoreRing({ score = 0, grade, size = 150 }) {
  const r = 58;
  const c = 2 * Math.PI * r;
  const color = GRADE_COLOR[grade] || "#64748b";
  return (
    <div className="ring" style={{ width: size, height: size }}>
      <svg viewBox="0 0 140 140" width={size} height={size}>
        <circle cx="70" cy="70" r={r} fill="none" stroke="var(--line)" strokeWidth="10" />
        <circle
          cx="70" cy="70" r={r} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - (score ?? 0) / 100)}
          transform="rotate(-90 70 70)" style={{ transition: "stroke-dashoffset .8s ease" }}
        />
      </svg>
      <div className="ring-label">
        <span className="ring-grade" style={{ color }}>{grade ?? "…"}</span>
        <span className="ring-score">{score ?? "--"}/100</span>
      </div>
    </div>
  );
}

export function Stat({ label, value, hint, accent }) {
  return (
    <div className="card stat">
      <span className="stat-label">{label}</span>
      <span className="stat-value" style={accent ? { color: accent } : undefined}>{value ?? "—"}</span>
      {hint && <span className="stat-hint">{hint}</span>}
    </div>
  );
}

export function Empty({ title, children, action }) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <svg viewBox="0 0 24 24" width="28" height="28"><path fill="currentColor" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5zm0 2.2 6 2.25V11c0 4-2.6 7.8-6 8.9-3.4-1.1-6-4.9-6-8.9V6.45z" /></svg>
      </div>
      <h3>{title}</h3>
      {children && <p className="muted">{children}</p>}
      {action}
    </div>
  );
}

export function ScanLink({ scan }) {
  return <Link to={`/scans/${scan.id}`} className="mono">#{scan.id}</Link>;
}

export function ErrorBox({ error }) {
  if (!error) return null;
  return <div className="alert alert-error">{String(error.message || error)}</div>;
}
