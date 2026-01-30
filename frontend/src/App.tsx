import { useState } from "react";
import { PasswordStrength } from "./components/PasswordStrength";
import { PasswordGenerator } from "./components/PasswordGenerator";
import { InputValidator } from "./components/InputValidator";
import { Shield, Zap, ScanEye, PanelLeftClose, PanelLeftOpen } from "lucide-react";

export default function App() {
  const [activeTab, setActiveTab] = useState<"strength" | "generator" | "validator">("strength");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const tools = [
    { id: "strength" as const, icon: ScanEye, title: "Analyze", subtitle: "Password strength", color: "cyan" },
    { id: "generator" as const, icon: Zap, title: "Generate", subtitle: "Secure password", color: "emerald" },
    { id: "validator" as const, icon: Shield, title: "Validate", subtitle: "Form inputs", color: "amber" },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      <div className="container mx-auto px-2 py-2 max-w-full h-screen flex flex-col">
        {/* Header */}
        <div className="mb-2">
          <div className="px-4 py-4">
            <h1 className="text-slate-800 text-3xl font-bold leading-tight text-center">SecureKit</h1>
            <p className="text-slate-600 text-base font-medium text-center mt-1">Web Security Tool</p>
            <p className="text-slate-500 text-sm text-center mt-0.5">Client-side • Zero data collection</p>
          </div>
        </div>

        {/* Main Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-[auto_1fr] gap-2 flex-1 overflow-hidden">
          {/* Sidebar */}
          <div className={`transition-all duration-300 ${sidebarCollapsed ? "lg:w-[60px]" : "lg:w-[200px]"}`}>
            <div className="space-y-1.5 h-full flex flex-col bg-white/80 backdrop-blur-sm rounded-lg p-2 border border-slate-200 shadow-lg">
              {sidebarCollapsed && (
                <div
                  className="bg-gradient-to-br from-blue-500 to-indigo-600 rounded-lg p-2 border border-blue-400 shadow-lg shadow-blue-500/20 mb-1 flex items-center justify-center"
                  title="SecureKit"
                >
                  <div className="bg-white/20 p-1 rounded-lg backdrop-blur-sm">
                    <Shield className="w-4 h-4 text-white" />
                  </div>
                </div>
              )}

              {tools.map((tool) => {
                const Icon = tool.icon;
                const isActive = activeTab === tool.id;
                return (
                  <button
                    key={tool.id}
                    onClick={() => setActiveTab(tool.id)}
                    className={`w-full group relative p-2 rounded-lg transition-all duration-300 ${
                      isActive
                        ? "bg-gradient-to-r from-blue-50 to-indigo-50 shadow-lg border border-blue-300 shadow-blue-500/10"
                        : "bg-slate-50 hover:bg-slate-100 border border-slate-200 hover:border-slate-300"
                    }`}
                    title={sidebarCollapsed ? tool.title : ""}
                  >
                    <div className="flex items-center gap-2 text-left">
                      <div
                        className={`p-1.5 rounded-lg transition-all flex-shrink-0 ${
                          isActive
                            ? tool.color === "cyan"
                              ? "bg-cyan-100 shadow-md shadow-cyan-500/20"
                              : tool.color === "emerald"
                              ? "bg-emerald-100 shadow-md shadow-emerald-500/20"
                              : "bg-amber-100 shadow-md shadow-amber-500/20"
                            : "bg-slate-200 group-hover:bg-slate-300"
                        }`}
                      >
                        <Icon
                          className={`w-4 h-4 ${
                            isActive
                              ? tool.color === "cyan"
                                ? "text-cyan-600"
                                : tool.color === "emerald"
                                ? "text-emerald-600"
                                : "text-amber-600"
                              : "text-slate-500"
                          }`}
                        />
                      </div>

                      {!sidebarCollapsed && (
                        <div className="flex-1">
                          <h3 className={`text-xs font-bold mb-0 ${isActive ? "text-slate-800" : "text-slate-600"}`}>
                            {tool.title}
                          </h3>
                          <p className="text-slate-500 text-[10px] leading-tight font-mono">{tool.subtitle}</p>
                        </div>
                      )}
                    </div>

                    {isActive && (
                      <div
                        className={`absolute left-0 top-0 bottom-0 w-1 rounded-l-lg shadow-lg ${
                          tool.color === "cyan"
                            ? "bg-cyan-500 shadow-cyan-400/50"
                            : tool.color === "emerald"
                            ? "bg-emerald-500 shadow-emerald-400/50"
                            : "bg-amber-500 shadow-amber-400/50"
                        }`}
                      />
                    )}
                  </button>
                );
              })}

              {/* Collapse button */}
              <button
                onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                className="w-full p-2 rounded-lg bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 border border-blue-400 transition-all duration-300 group hidden lg:flex items-center justify-center gap-2 mt-auto shadow-lg shadow-blue-500/20"
                title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
              >
                {sidebarCollapsed ? <PanelLeftOpen className="w-4 h-4 text-white" /> : <PanelLeftClose className="w-4 h-4 text-white" />}
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="bg-white/80 backdrop-blur-sm rounded-lg p-2 shadow-xl border border-slate-200 overflow-auto">
            {activeTab === "strength" && <PasswordStrength />}
            {activeTab === "generator" && <PasswordGenerator />}
            {activeTab === "validator" && <InputValidator />}
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-2 py-1">
          <p className="text-slate-500 text-sm leading-tight font-mono">Group 4 • MO-IT142 - Security Script Programming</p>
        </div>
      </div>
    </div>
  );
}
