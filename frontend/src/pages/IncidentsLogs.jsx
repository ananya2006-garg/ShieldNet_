import { useState } from "react";
import Incidents from "./Incidents";
import ThreatHistory from "./ThreatHistory";

export default function IncidentsLogs() {
  const [activeTab, setActiveTab] = useState("incidents");

  return (
    <div className="min-h-full flex flex-col">
      <div className="px-6 pt-4 border-b border-cyber-border bg-cyber-bg/50 backdrop-blur sticky top-0 z-10">
        <div className="flex gap-6">
          <button 
            onClick={() => setActiveTab("incidents")}
            className={`pb-3 text-sm font-semibold transition-all border-b-2 ${activeTab === "incidents" ? "border-cyber-accent text-white" : "border-transparent text-cyber-muted hover:text-gray-300"}`}
          >
            Incident Response
          </button>
          <button 
            onClick={() => setActiveTab("logs")}
            className={`pb-3 text-sm font-semibold transition-all border-b-2 ${activeTab === "logs" ? "border-cyber-accent text-white" : "border-transparent text-cyber-muted hover:text-gray-300"}`}
          >
            Threat Logs & History
          </button>
        </div>
      </div>
      <div className="flex-1">
        {activeTab === "incidents" ? <Incidents /> : <ThreatHistory />}
      </div>
    </div>
  );
}
