import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { api, fmtDate, GRADE_COLOR, SEV_COLOR, timeAgo } from "../api";
import { Empty, ErrorBox, GradeChip, SeverityBadge, Stat, StatusBadge } from "../components/ui";

const tooltipStyle = {
  contentStyle: { background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: 8, fontSize: 12 },
  labelStyle: { color: "var(--muted)" },
};

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const load = () => api.dashboard().then(setData).catch(setError);
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  if (error) return <ErrorBox error={error} />;
  if (!data) return <div className="loading">Loading dashboard…</div>;

  const t = data.totals;
  if (t.targets === 0) {
    return (
      <>
        <PageHead />
        <Empty title="No targets yet" action={<Link className="btn btn-primary" to="/targets">Add your first website</Link>}>
          Add a website you own, verify ownership, then run your first security audit.
        </Empty>
      </>
    );
  }

  const avgGrade = t.average_score == null ? null
    : t.average_score >= 95 ? "A+" : t.average_score >= 85 ? "A" : t.average_score >= 70 ? "B"
    : t.average_score >= 55 ? "C" : t.average_score >= 40 ? "D" : "F";
  const trend = data.score_trend.map((s) => ({ ...s, label: fmtDate(s.date, false) }));

  return (
    <>
      <PageHead />
      <div className="grid stats">
        <Stat label="Targets" value={t.targets} hint={`${t.verified_targets} verified`} />
        <Stat label="Scans run" value={t.scans} hint={`${t.completed_scans} completed`} />
        <Stat label="Average score" value={t.average_score ?? "—"} hint="latest scan per target" accent={GRADE_COLOR[avgGrade]} />
        <Stat label="Critical + High open" value={t.open_critical_high} hint="across latest scans"
          accent={t.open_critical_high ? SEV_COLOR.critical : GRADE_COLOR.A} />
      </div>

      <div className="grid two">
        <section className="card">
          <h2>Open issues by severity</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={data.severity_distribution} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid vertical={false} stroke="var(--line)" />
              <XAxis dataKey="severity" tick={{ fill: "var(--muted)", fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip {...tooltipStyle} cursor={{ fill: "var(--hover)" }} />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {data.severity_distribution.map((d) => <Cell key={d.severity} fill={SEV_COLOR[d.severity]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section className="card">
          <h2>Score trend</h2>
          {trend.length < 2 ? (
            <p className="muted chart-empty">Run at least two scans to see a trend.</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trend} margin={{ top: 8, right: 12, left: -20, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--line)" />
                <XAxis dataKey="label" tick={{ fill: "var(--muted)", fontSize: 11 }} axisLine={false} tickLine={false} minTickGap={24} />
                <YAxis domain={[0, 100]} tick={{ fill: "var(--muted)", fontSize: 12 }} axisLine={false} tickLine={false} />
                <Tooltip {...tooltipStyle} formatter={(v, _n, p) => [`${v}/100`, p.payload.target]} />
                <Line type="monotone" dataKey="score" stroke="var(--accent)" strokeWidth={2.5} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </section>
      </div>

      <div className="grid two">
        <section className="card">
          <h2>Targets ranked by risk</h2>
          {data.target_scores.length === 0 ? <p className="muted">No completed scans yet.</p> : (
            <ul className="rank">
              {data.target_scores.map((s) => (
                <li key={s.target_id}>
                  <GradeChip grade={s.grade} />
                  <Link to={`/scans/${s.scan_id}`}>{s.target}</Link>
                  <div className="bar"><span style={{ width: `${s.score}%`, background: GRADE_COLOR[s.grade] }} /></div>
                  <span className="mono">{s.score}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card">
          <h2>Most common issues</h2>
          {data.top_issues.length === 0 ? <p className="muted">Nothing open. Nice!</p> : (
            <ul className="issues">
              {data.top_issues.map((i) => (
                <li key={i.title}>
                  <SeverityBadge severity={i.severity} />
                  <span>{i.title}</span>
                  <span className="muted">{i.targets} site{i.targets > 1 ? "s" : ""}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="card">
        <div className="card-head">
          <h2>Recent scans</h2>
          <Link to="/history" className="btn btn-ghost">View all</Link>
        </div>
        <table className="table">
          <thead><tr><th>Scan</th><th>Target</th><th>Status</th><th>Grade</th><th>Score</th><th>When</th></tr></thead>
          <tbody>
            {data.recent_scans.map((s) => (
              <tr key={s.id}>
                <td><Link className="mono" to={`/scans/${s.id}`}>#{s.id}</Link></td>
                <td>{s.target_name}</td>
                <td><StatusBadge status={s.status} /></td>
                <td><GradeChip grade={s.grade} /></td>
                <td className="mono">{s.score ?? "—"}</td>
                <td className="muted">{timeAgo(s.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}

function PageHead() {
  return (
    <header className="page-head">
      <div>
        <h1>Security overview</h1>
        <p className="muted">Configuration health across all your verified websites.</p>
      </div>
      <Link to="/targets" className="btn btn-primary">+ New scan</Link>
    </header>
  );
}
