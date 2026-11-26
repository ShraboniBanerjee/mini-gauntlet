import { Link, Route, Routes } from "react-router-dom";

import { NotFoundPage } from "./pages/NotFoundPage";
import { ScanPage } from "./pages/ScanPage";
import { ScansPage } from "./pages/ScansPage";

function BrandMark() {
  // The same four marks as a scan's findings strip: critical, high, medium, pass.
  return (
    <svg className="brand-mark" viewBox="0 0 22 16" aria-hidden="true">
      <rect x="0" width="4" height="16" className="sev-critical" />
      <rect x="6" width="4" height="16" className="sev-high" />
      <rect x="12" width="4" height="16" className="sev-medium" />
      <rect x="18" width="4" height="16" className="pass" />
    </svg>
  );
}

/** Routes without the router, so tests can wrap them in a MemoryRouter. */
export function App() {
  return (
    <div className="app">
      <header className="topbar">
        <Link to="/" className="brand">
          <BrandMark />
          Mini Gauntlet
        </Link>
        <span className="topbar-note">Cloud posture scanner</span>
      </header>
      <main className="page">
        <Routes>
          <Route path="/" element={<ScansPage />} />
          <Route path="/scans/:scanId" element={<ScanPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>
    </div>
  );
}
