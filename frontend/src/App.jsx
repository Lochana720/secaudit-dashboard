import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { api } from "./api";
import Dashboard from "./pages/Dashboard.jsx";
import History from "./pages/History.jsx";
import ScanDetail from "./pages/ScanDetail.jsx";
import Targets from "./pages/Targets.jsx";

const NAV = [
  { to: "/", label: "Dashboard", icon: "M3 13h8V3H3zm0 8h8v-6H3zm10 0h8V11h-8zm0-18v6h8V3z" },
  { to: "/targets", label: "Targets", icon: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20m0 4a6 6 0 1 1 0 12 6 6 0 0 1 0-12m0 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6" },
  { to: "/history", label: "Scan history", icon: "M13 3a9 9 0 0 0-9 9H1l4 4 4-4H6a7 7 0 1 1 2.05 4.95l-1.42 1.42A9 9 0 1 0 13 3m-1 5v5l4.25 2.52.77-1.28-3.52-2.09V8z" },
];

export default function App() {
  const [config, setConfig] = useState(null);
  useEffect(() => {
    api.config().then(setConfig).catch(() => setConfig(null));
  }, []);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <svg viewBox="0 0 24 24" width="26" height="26"><path fill="var(--accent)" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5z" /><path fill="var(--bg)" d="m10.5 14.6-2.6-2.6-1.1 1.1 3.7 3.7 7-7-1.1-1.1z" /></svg>
          <div>
            <strong>SecAudit</strong>
            <span>Security dashboard</span>
          </div>
        </div>
        <nav>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"} className="nav-link">
              <svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d={n.icon} /></svg>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          {config?.skip_verification && <div className="dev-flag">DEV MODE · verification skipped</div>}
          <p>Only scan websites you own or have written permission to test.</p>
        </div>
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/targets" element={<Targets config={config} />} />
          <Route path="/history" element={<History />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="*" element={<div className="card">Page not found.</div>} />
        </Routes>
      </main>
    </div>
  );
}
