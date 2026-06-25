import { useState } from "react";
import Vulnerabilities from "./Vulnerabilities";
import UserRisk from "./UserRisk";

export default function RiskAssessment() {
  const [activeTab, setActiveTab] = useState("vulnerabilities");

  return (
    <div className="min-h-full flex flex-col">
      <div className="px-6 pt-4 border-b border-cyber-border bg-cyber-bg/50 backdrop-blur sticky top-0 z-10">
        <div className="flex gap-6">
          <button 
            onClick={() => setActiveTab("vulnerabilities")}
            className={`pb-3 text-sm font-semibold transition-all border-b-2 ${activeTab === "vulnerabilities" ? "border-cyber-accent text-white" : "border-transparent text-cyber-muted hover:text-gray-300"}`}
          >
            Vulnerability Scanner
          </button>
          <button 
            onClick={() => setActiveTab("user-risk")}
            className={`pb-3 text-sm font-semibold transition-all border-b-2 ${activeTab === "user-risk" ? "border-cyber-accent text-white" : "border-transparent text-cyber-muted hover:text-gray-300"}`}
          >
            User & Device Risk
          </button>
        </div>
      </div>
      <div className="flex-1">
        {activeTab === "vulnerabilities" ? <Vulnerabilities /> : <UserRisk />}
      </div>
    </div>
  );
}
