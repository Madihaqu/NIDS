import React from 'react';
import { ShieldCheck, Activity, Sliders, UploadCloud, Cpu, BookOpen, Sun, Moon } from 'lucide-react';

export type NavTab = 'dashboard' | 'stream' | 'sandbox' | 'csv' | 'models' | 'deploy';

interface SOCNavbarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  isStreaming: boolean;
  onToggleStreaming: () => void;
  isDark: boolean;
  onToggleTheme: () => void;
}

export const SOCNavbar: React.FC<SOCNavbarProps> = ({
  activeTab,
  onSelectTab,
  isStreaming,
  onToggleStreaming,
  isDark,
  onToggleTheme,
}) => {
  return (
    <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-slate-800 bg-slate-950/90 backdrop-blur sticky top-0 z-30">
      {/* Zone 1: Single text wordmark with subtle security emblem */}
      <div className="flex items-center gap-2.5 shrink-0">
        <div className="w-8 h-8 rounded bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center text-cyan-400">
          <ShieldCheck className="w-4 h-4" />
        </div>
        <span className="text-base font-bold tracking-tight text-slate-100 whitespace-nowrap">
          Hybrid NIDS
        </span>
        <span className="text-[11px] font-mono text-cyan-400/90 border border-cyan-800/60 rounded px-1.5 py-0.5 whitespace-nowrap hidden sm:inline-block">
          Dual-Engine ML
        </span>
      </div>

      {/* Zone 2: Navigation Links (single line, whitespace-nowrap) */}
      <nav className="hidden md:flex items-center gap-1 text-xs font-medium text-slate-400">
        <button
          onClick={() => onSelectTab('dashboard')}
          className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
            activeTab === 'dashboard'
              ? 'bg-slate-800 text-cyan-300 font-semibold'
              : 'hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          SOC Overview
        </button>
        <button
          onClick={() => onSelectTab('stream')}
          className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
            activeTab === 'stream'
              ? 'bg-slate-800 text-cyan-300 font-semibold'
              : 'hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          Live Traffic Stream
        </button>
        <button
          onClick={() => onSelectTab('sandbox')}
          className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
            activeTab === 'sandbox'
              ? 'bg-slate-800 text-cyan-300 font-semibold'
              : 'hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          Flow Sandbox
        </button>
        <button
          onClick={() => onSelectTab('csv')}
          className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
            activeTab === 'csv'
              ? 'bg-slate-800 text-cyan-300 font-semibold'
              : 'hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <UploadCloud className="w-3.5 h-3.5" />
          CSV Benchmark
        </button>
        <button
          onClick={() => onSelectTab('models')}
          className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
            activeTab === 'models'
              ? 'bg-slate-800 text-cyan-300 font-semibold'
              : 'hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          Model Calibration
        </button>
        <button
          onClick={() => onSelectTab('deploy')}
          className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
            activeTab === 'deploy'
              ? 'bg-slate-800 text-cyan-300 font-semibold'
              : 'hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <BookOpen className="w-3.5 h-3.5" />
          Deployment Guide
        </button>
      </nav>

      {/* Zone 3: 1 primary action + theme toggle */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onToggleTheme}
          aria-label="Toggle visual theme"
          className="p-1.5 text-slate-400 hover:text-slate-200 rounded border border-slate-800 hover:border-slate-700 transition-colors"
        >
          {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4" />}
        </button>

        <button
          onClick={onToggleStreaming}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded transition-colors whitespace-nowrap shrink-0 font-mono ${
            isStreaming
              ? 'bg-red-950/60 text-red-300 border border-red-800 hover:bg-red-900/60'
              : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950'
          }`}
        >
          {isStreaming ? 'Stop Stream' : 'Start Live Telemetry'}
        </button>
      </div>
    </header>
  );
};
