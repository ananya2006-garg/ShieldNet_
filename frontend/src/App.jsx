import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout           from "./components/Layout";
import Dashboard        from "./pages/Dashboard";
import Simulation       from "./pages/Simulation";
import ThreatIntel      from "./pages/ThreatIntel";
import AICopilot        from "./pages/AICopilot";
import Reports          from "./pages/Reports";
import Settings         from "./pages/Settings";
import Honeypot         from "./pages/Honeypot";
import RedBlueTeam      from "./pages/RedBlueTeam";
import IncidentsLogs    from "./pages/IncidentsLogs";
import RiskAssessment   from "./pages/RiskAssessment";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index                   element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard"        element={<Dashboard />} />
          <Route path="intel"            element={<ThreatIntel />} />
          <Route path="copilot"          element={<AICopilot />} />
          <Route path="incidents-logs"   element={<IncidentsLogs />} />
          <Route path="risk-assessment"  element={<RiskAssessment />} />
          <Route path="honeypot"         element={<Honeypot />} />
          <Route path="reports"          element={<Reports />} />
          <Route path="settings"         element={<Settings />} />
          <Route path="simulation"       element={<Simulation />} />
          <Route path="redblue"          element={<RedBlueTeam />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
