import { useState } from "react";
import CopilotChat from "./CopilotChat";
import XAIDashboard from "./XAIDashboard";

export default function AICopilot() {
  const [activeTab, setActiveTab] = useState("copilot");

  return (
    <div className="min-h-full flex flex-col">
      <div className="px-6 pt-4 border-b border-cyber-border bg-cyber-bg/50 backdrop-blur sticky top-0 z-10">
        <div className="flex gap-6">
          <button 
            onClick={() => setActiveTab("copilot")}
            className={`pb-3 text-sm font-semibold transition-all border-b-2 ${activeTab === "copilot" ? "border-cyber-accent text-white" : "border-transparent text-cyber-muted hover:text-gray-300"}`}
          >
            AI Copilot Chat
          </button>
          <button 
            onClick={() => setActiveTab("xai")}
            className={`pb-3 text-sm font-semibold transition-all border-b-2 ${activeTab === "xai" ? "border-cyber-accent text-white" : "border-transparent text-cyber-muted hover:text-gray-300"}`}
          >
            XAI Dashboard
          </button>
        </div>
      </div>
      <div className="flex-1">
        {activeTab === "copilot" ? <CopilotChat /> : <XAIDashboard />}
      </div>
    </div>
  );
}
