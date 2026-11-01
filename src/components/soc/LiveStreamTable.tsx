import React, { useState } from 'react';
import {
  Play,
  Pause,
  Trash2,
  Zap,
  Filter,
  ShieldAlert,
  ShieldCheck,
  Info,
  X,
  Copy,
  Check,
} from 'lucide-react';
import { AttackCategory, HybridDetectionResult } from '../../types/nids';

interface LiveStreamTableProps {
  flows: HybridDetectionResult[];
  isStreaming: boolean;
  onToggleStreaming: () => void;
  streamRate: number;
  onRateChange: (rate: number) => void;
  onInjectAttack: (type: AttackCategory) => void;
  onClearFlows: () => void;
}

export const LiveStreamTable: React.FC<LiveStreamTableProps> = ({
  flows,
  isStreaming,
  onToggleStreaming,
  streamRate,
  onRateChange,
  onInjectAttack,
  onClearFlows,
}) => {
  const [filterVerdict, setFilterVerdict] = useState<string>('all');
  const [selectedFlow, setSelectedFlow] = useState<HybridDetectionResult | null>(null);
  const [copiedRule, setCopiedRule] = useState<boolean>(false);

  // Filter flows
  const filteredFlows = flows.filter((f) => {
    if (filterVerdict === 'threats') return f.isThreat;
    if (filterVerdict === 'zeroday') return f.finalVerdict === 'ZeroDay';
    if (filterVerdict === 'benign') return !f.isThreat;
    return true;
  });

  const getVerdictBadge = (res: HybridDetectionResult) => {
    if (res.finalVerdict === 'ZeroDay') {
      return (
        <span className="text-xs font-mono font-medium text-cyan-400">
          Zero-Day Outlier
        </span>
      );
    }
    if (res.isThreat) {
      return (
        <span className="text-xs font-mono font-medium text-red-400">
          {res.finalVerdict}
        </span>
      );
    }
    return (
      <span className="text-xs font-mono font-medium text-emerald-400">
        Benign
      </span>
    );
  };

  const generateFirewallRule = (res: HybridDetectionResult) => {
    return `iptables -A INPUT -s ${res.flow.sourceIp} -p ${res.flow.protocol.toLowerCase()} --dport ${res.flow.destinationPort} -j DROP`;
  };

  const copyFirewallRule = (rule: string) => {
    navigator.clipboard.writeText(rule);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2000);
  };

  return (
    <div className="w-full bg-slate-900/80 border border-slate-800 rounded-lg flex flex-col">
      {/* Stream Control Toolbar */}
      <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
        {/* Left: Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={onToggleStreaming}
            className={`px-3 py-1.5 text-xs font-medium rounded flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
              isStreaming
                ? 'bg-amber-600/20 text-amber-300 border border-amber-600/40 hover:bg-amber-600/30'
                : 'bg-emerald-600/20 text-emerald-300 border border-emerald-600/40 hover:bg-emerald-600/30'
            }`}
          >
            {isStreaming ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Pause Stream</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Resume Stream</span>
              </>
            )}
          </button>

          {/* Rate slider */}
          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
            <span>Rate:</span>
            <input
              type="range"
              min="5"
              max="50"
              step="5"
              value={streamRate}
              onChange={(e) => onRateChange(Number(e.target.value))}
              className="w-20 accent-cyan-500 cursor-pointer h-1.5 bg-slate-700 rounded-lg"
            />
            <span className="w-8 tabular-nums">{streamRate}/s</span>
          </div>

          <button
            onClick={onClearFlows}
            title="Clear buffer"
            className="p-1.5 text-slate-400 hover:text-slate-200 border border-slate-800 hover:border-slate-700 rounded transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Threat Injectors (Quick Simulation) */}
        <div className="flex items-center gap-1.5 text-xs">
          <span className="text-slate-500 font-mono flex items-center gap-1 text-[11px] mr-1">
            <Zap className="w-3 h-3 text-cyan-400" /> Inject:
          </span>
          <button
            onClick={() => onInjectAttack('DDoS')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-red-950/60 text-slate-300 hover:text-red-300 border border-slate-700 hover:border-red-800 transition-colors whitespace-nowrap text-[11px] font-mono"
          >
            DDoS Flood
          </button>
          <button
            onClick={() => onInjectAttack('PortScan')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-amber-950/60 text-slate-300 hover:text-amber-300 border border-slate-700 hover:border-amber-800 transition-colors whitespace-nowrap text-[11px] font-mono"
          >
            Port Scan
          </button>
          <button
            onClick={() => onInjectAttack('BruteForce')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-orange-950/60 text-slate-300 hover:text-orange-300 border border-slate-700 hover:border-orange-800 transition-colors whitespace-nowrap text-[11px] font-mono"
          >
            Brute Force
          </button>
          <button
            onClick={() => onInjectAttack('ZeroDay')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 hover:border-cyan-600 transition-colors whitespace-nowrap text-[11px] font-mono font-medium"
          >
            Zero-Day Anomaly
          </button>
        </div>

        {/* Filter Segmented Control */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800 text-xs">
          <button
            onClick={() => setFilterVerdict('all')}
            className={`px-2.5 py-1 rounded transition-colors whitespace-nowrap ${
              filterVerdict === 'all'
                ? 'bg-slate-800 text-slate-100'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({flows.length})
          </button>
          <button
            onClick={() => setFilterVerdict('threats')}
            className={`px-2.5 py-1 rounded transition-colors whitespace-nowrap ${
              filterVerdict === 'threats'
                ? 'bg-red-900/40 text-red-300 border border-red-800/60'
                : 'text-slate-400 hover:text-red-300'
            }`}
          >
            Threats
          </button>
          <button
            onClick={() => setFilterVerdict('zeroday')}
            className={`px-2.5 py-1 rounded transition-colors whitespace-nowrap ${
              filterVerdict === 'zeroday'
                ? 'bg-cyan-900/40 text-cyan-300 border border-cyan-800/60'
                : 'text-slate-400 hover:text-cyan-300'
            }`}
          >
            Zero-Day
          </button>
          <button
            onClick={() => setFilterVerdict('benign')}
            className={`px-2.5 py-1 rounded transition-colors whitespace-nowrap ${
              filterVerdict === 'benign'
                ? 'bg-emerald-900/40 text-emerald-300 border border-emerald-800/60'
                : 'text-slate-400 hover:text-emerald-300'
            }`}
          >
            Benign
          </button>
        </div>
      </div>

      {/* High-Density Stream Table */}
      <div className="overflow-x-auto flex-1 max-h-[460px]">
        <table className="w-full text-left text-xs font-mono border-collapse">
          <thead>
            <tr className="bg-slate-950/80 text-slate-400 border-b border-slate-800 sticky top-0 z-10 text-[11px] tracking-wider uppercase">
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Source → Destination</th>
              <th className="py-2.5 px-2">Proto</th>
              <th className="py-2.5 px-3 text-right">Packets/s</th>
              <th className="py-2.5 px-3 text-right">Throughput</th>
              <th className="py-2.5 px-3 text-right">RF Conf</th>
              <th className="py-2.5 px-3 text-right">Outlier Score</th>
              <th className="py-2.5 px-3">Verdict</th>
              <th className="py-2.5 px-2 text-center">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredFlows.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-slate-500 italic">
                  No flows matching filter criteria. Start or inject traffic above.
                </td>
              </tr>
            ) : (
              filteredFlows.slice(0, 80).map((res) => {
                const isSelected = selectedFlow?.flow.id === res.flow.id;
                const timeStr = new Date(res.flow.timestamp).toLocaleTimeString([], {
                  hour12: false,
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                });

                return (
                  <tr
                    key={res.flow.id}
                    onClick={() => setSelectedFlow(res)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-950/40'
                        : res.finalVerdict === 'ZeroDay'
                        ? 'bg-cyan-950/15 hover:bg-cyan-950/30'
                        : res.isThreat
                        ? 'bg-red-950/15 hover:bg-red-950/30'
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <td className="py-2 px-3 text-slate-400 whitespace-nowrap tabular-nums">
                      {timeStr}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className="text-slate-300">{res.flow.sourceIp}:{res.flow.sourcePort}</span>
                      <span className="text-slate-600 mx-1.5">→</span>
                      <span className="text-slate-200">{res.flow.destinationIp}:{res.flow.destinationPort}</span>
                    </td>
                    <td className="py-2 px-2 text-slate-400">
                      {res.flow.protocol}
                    </td>
                    <td className="py-2 px-3 text-right text-slate-300 tabular-nums">
                      {Math.round(res.flow.flowPacketsPerSec).toLocaleString()}
                    </td>
                    <td className="py-2 px-3 text-right text-slate-400 tabular-nums">
                      {(res.flow.flowBytesPerSec / 1024).toFixed(1)} KB/s
                    </td>
                    <td className="py-2 px-3 text-right text-slate-300 tabular-nums">
                      {(res.supervised.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="py-2 px-3 text-right tabular-nums">
                      <span
                        className={
                          res.outlier.anomalyScore > 0.65
                            ? 'text-cyan-400 font-semibold'
                            : 'text-slate-400'
                        }
                      >
                        {res.outlier.anomalyScore.toFixed(3)}
                      </span>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      {getVerdictBadge(res)}
                    </td>
                    <td className="py-2 px-2 text-center">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFlow(res);
                        }}
                        className="text-slate-400 hover:text-cyan-300 p-1 rounded"
                        title="Deep Flow Inspection"
                      >
                        <Info className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Slide-over Inspection Modal / Drawer */}
      {selectedFlow && (
        <div className="border-t border-slate-800 bg-slate-950 p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {selectedFlow.isThreat ? (
                <ShieldAlert className="w-5 h-5 text-red-400" />
              ) : (
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              )}
              <h4 className="text-sm font-semibold text-slate-100">
                Flow Inspection: {selectedFlow.flow.id}
              </h4>
              <span className="text-xs font-mono text-slate-400 ml-2">
                Verdict: <span className="text-slate-200 font-bold">{selectedFlow.finalVerdict}</span>
              </span>
            </div>
            <button
              onClick={() => setSelectedFlow(null)}
              className="p-1 text-slate-400 hover:text-slate-200"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            {/* Supervised Engine Details */}
            <div className="bg-slate-900 border border-slate-800 rounded p-3">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Engine 1: Random Forest
              </span>
              <div className="space-y-1 text-slate-300">
                <div>Predicted: <span className="text-slate-100 font-semibold">{selectedFlow.supervised.predictedClass}</span></div>
                <div>Confidence: <span className="text-cyan-400 tabular-nums">{(selectedFlow.supervised.confidence * 100).toFixed(1)}%</span></div>
                <div>Rule Matched: <span className="text-slate-400">{selectedFlow.supervised.ruleMatched}</span></div>
              </div>
              <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/80 pt-1.5">
                {selectedFlow.supervised.decisionPath.map((step, idx) => (
                  <div key={idx} className="truncate">• {step}</div>
                ))}
              </div>
            </div>

            {/* Isolation Forest Details */}
            <div className="bg-slate-900 border border-slate-800 rounded p-3">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Engine 2: Isolation Forest
              </span>
              <div className="space-y-1 text-slate-300">
                <div>Anomaly Score: <span className="text-cyan-400 font-bold tabular-nums">{selectedFlow.outlier.anomalyScore}</span></div>
                <div>Is Outlier: <span className={selectedFlow.outlier.isOutlier ? 'text-cyan-300 font-semibold' : 'text-slate-400'}>{selectedFlow.outlier.isOutlier ? 'YES' : 'NO'}</span></div>
                <div>Top Contributing Deviations:</div>
              </div>
              <div className="mt-1 space-y-1 text-[11px] text-slate-400">
                {selectedFlow.outlier.contributingFeatures.length === 0 ? (
                  <div className="italic text-slate-500">Within nominal standard deviations</div>
                ) : (
                  selectedFlow.outlier.contributingFeatures.slice(0, 3).map((f, i) => (
                    <div key={i} className="flex justify-between">
                      <span className="truncate">{f.featureName}</span>
                      <span className="text-amber-400 tabular-nums">z={f.deviationZScore}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Flow Telemetry Metrics */}
            <div className="bg-slate-900 border border-slate-800 rounded p-3">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Raw Flow Properties
              </span>
              <div className="space-y-1 text-slate-300 text-[11px]">
                <div>Duration: <span className="text-slate-100 tabular-nums">{selectedFlow.flow.flowDurationMs.toFixed(1)} ms</span></div>
                <div>Packets: <span className="tabular-nums">Fwd: {selectedFlow.flow.totalFwdPackets} | Bwd: {selectedFlow.flow.totalBwdPackets}</span></div>
                <div>TCP Flags: <span className="text-slate-200">SYN:{selectedFlow.flow.flagSyn} ACK:{selectedFlow.flow.flagAck} FIN:{selectedFlow.flow.flagFin} PSH:{selectedFlow.flow.flagPsh}</span></div>
                <div>Mean IAT: <span className="tabular-nums">{selectedFlow.flow.flowIATMeanMs.toFixed(1)} ms</span></div>
                <div>Latency: <span className="text-emerald-400 tabular-nums">{selectedFlow.processedAt} ms (client-side)</span></div>
              </div>
            </div>
          </div>

          {/* Remediation & Firewall Action */}
          {selectedFlow.isThreat && (
            <div className="bg-red-950/30 border border-red-900/50 rounded p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="space-y-0.5">
                <span className="text-red-300 font-semibold block">Suggested Remediation Policy:</span>
                <code className="text-slate-300 font-mono text-[11px] select-all">
                  {generateFirewallRule(selectedFlow)}
                </code>
              </div>
              <button
                onClick={() => copyFirewallRule(generateFirewallRule(selectedFlow))}
                className="px-3 py-1.5 bg-red-900/60 hover:bg-red-800 text-red-200 rounded flex items-center gap-1.5 transition-colors font-mono text-xs"
              >
                {copiedRule ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedRule ? 'Copied' : 'Copy iptables Rule'}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
