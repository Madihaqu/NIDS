import React, { useState } from 'react';
import {
  Play,
  RotateCcw,
  Sliders,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Zap,
} from 'lucide-react';
import { NetworkFlow, HybridDetectionResult, ProtocolType } from '../../types/nids';
import { analyzeFlow } from '../../engine/hybridEngine';

export const FlowInspector: React.FC = () => {
  // Flow parameter states
  const [protocol, setProtocol] = useState<ProtocolType>('TCP');
  const [destinationPort, setDestinationPort] = useState<number>(443);
  const [flowDurationMs, setFlowDurationMs] = useState<number>(320);
  const [totalFwdPackets, setTotalFwdPackets] = useState<number>(6);
  const [totalBwdPackets, setTotalBwdPackets] = useState<number>(8);
  const [flowBytesPerSec, setFlowBytesPerSec] = useState<number>(24500);
  const [flowPacketsPerSec, setFlowPacketsPerSec] = useState<number>(42);
  const [fwdPacketLengthMean, setFwdPacketLengthMean] = useState<number>(340);
  const [bwdPacketLengthMean, setBwdPacketLengthMean] = useState<number>(680);
  const [flowIATMeanMs, setFlowIATMeanMs] = useState<number>(45);

  // TCP Flags
  const [flagSyn, setFlagSyn] = useState<number>(1);
  const [flagAck, setFlagAck] = useState<number>(1);
  const [flagFin, setFlagFin] = useState<number>(0);
  const [flagRst, setFlagRst] = useState<number>(0);
  const [flagPsh, setFlagPsh] = useState<number>(0);

  // Analysis result
  const [result, setResult] = useState<HybridDetectionResult | null>(() => {
    // Initial analysis
    const initialFlow: NetworkFlow = {
      id: 'inspect_sandbox_init',
      timestamp: Date.now(),
      sourceIp: '192.168.1.105',
      sourcePort: 54120,
      destinationIp: '142.250.190.46',
      destinationPort: 443,
      protocol: 'TCP',
      flowDurationMs: 320,
      totalFwdPackets: 6,
      totalBwdPackets: 8,
      flowBytesPerSec: 24500,
      flowPacketsPerSec: 42,
      fwdPacketLengthMean: 340,
      bwdPacketLengthMean: 680,
      flowIATMeanMs: 45,
      flagSyn: 1,
      flagAck: 1,
      flagFin: 0,
      flagRst: 0,
      flagPsh: 0,
    };
    return analyzeFlow(initialFlow);
  });

  const handleAnalyze = () => {
    const flow: NetworkFlow = {
      id: `inspect_${Date.now()}`,
      timestamp: Date.now(),
      sourceIp: '192.168.1.105',
      sourcePort: 52194,
      destinationIp: '10.0.4.15',
      destinationPort,
      protocol,
      flowDurationMs,
      totalFwdPackets,
      totalBwdPackets,
      flowBytesPerSec,
      flowPacketsPerSec,
      fwdPacketLengthMean,
      bwdPacketLengthMean,
      flowIATMeanMs,
      flagSyn,
      flagAck,
      flagFin,
      flagRst,
      flagPsh,
    };
    const res = analyzeFlow(flow);
    setResult(res);
  };

  const applyPreset = (presetName: string) => {
    switch (presetName) {
      case 'https':
        setProtocol('TCP');
        setDestinationPort(443);
        setFlowDurationMs(280);
        setTotalFwdPackets(7);
        setTotalBwdPackets(10);
        setFlowBytesPerSec(35000);
        setFlowPacketsPerSec(45);
        setFwdPacketLengthMean(310);
        setBwdPacketLengthMean(750);
        setFlowIATMeanMs(40);
        setFlagSyn(1);
        setFlagAck(1);
        setFlagFin(0);
        setFlagRst(0);
        setFlagPsh(0);
        break;
      case 'ddos':
        setProtocol('TCP');
        setDestinationPort(80);
        setFlowDurationMs(12);
        setTotalFwdPackets(50);
        setTotalBwdPackets(0);
        setFlowBytesPerSec(8500000);
        setFlowPacketsPerSec(4800);
        setFwdPacketLengthMean(64);
        setBwdPacketLengthMean(0);
        setFlowIATMeanMs(0.2);
        setFlagSyn(1);
        setFlagAck(0);
        setFlagFin(0);
        setFlagRst(0);
        setFlagPsh(0);
        break;
      case 'portscan':
        setProtocol('TCP');
        setDestinationPort(22);
        setFlowDurationMs(5);
        setTotalFwdPackets(1);
        setTotalBwdPackets(0);
        setFlowBytesPerSec(180);
        setFlowPacketsPerSec(200);
        setFwdPacketLengthMean(40);
        setBwdPacketLengthMean(0);
        setFlowIATMeanMs(5);
        setFlagSyn(1);
        setFlagAck(0);
        setFlagFin(0);
        setFlagRst(0);
        setFlagPsh(0);
        break;
      case 'zeroday':
        setProtocol('TCP');
        setDestinationPort(49152);
        setFlowDurationMs(4500);
        setTotalFwdPackets(95);
        setTotalBwdPackets(2);
        setFlowBytesPerSec(450000);
        setFlowPacketsPerSec(650);
        setFwdPacketLengthMean(2850); // Anomalous jumbo MTU breach
        setBwdPacketLengthMean(40);
        setFlowIATMeanMs(1.5);
        setFlagSyn(1);
        setFlagFin(1); // Invalid RFC collision
        setFlagAck(0);
        setFlagRst(0);
        setFlagPsh(1);
        break;
      case 'bruteforce':
        setProtocol('TCP');
        setDestinationPort(22);
        setFlowDurationMs(850);
        setTotalFwdPackets(14);
        setTotalBwdPackets(12);
        setFlowBytesPerSec(4200);
        setFlowPacketsPerSec(30);
        setFwdPacketLengthMean(170);
        setBwdPacketLengthMean(210);
        setFlowIATMeanMs(25);
        setFlagSyn(1);
        setFlagAck(1);
        setFlagFin(0);
        setFlagRst(0);
        setFlagPsh(1);
        break;
    }
  };

  return (
    <div className="w-full space-y-6">
      {/* Header and presets */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Live Flow Inspector & Parameter Sandbox
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Adjust low-level network flow features in real-time to observe dual-engine inference decisions.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleAnalyze}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              Analyze Flow
            </button>
          </div>
        </div>

        {/* Quick Presets */}
        <div className="flex flex-wrap items-center gap-2 text-xs border-t border-slate-800/80 pt-3">
          <span className="text-slate-400 font-mono text-[11px] mr-1">Load Preset:</span>
          <button
            onClick={() => {
              applyPreset('https');
              setTimeout(handleAnalyze, 10);
            }}
            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 font-mono text-[11px] transition-colors"
          >
            Normal HTTPS Traffic
          </button>
          <button
            onClick={() => {
              applyPreset('ddos');
              setTimeout(handleAnalyze, 10);
            }}
            className="px-2.5 py-1 bg-slate-800 hover:bg-red-950/60 text-slate-300 hover:text-red-300 rounded border border-slate-700 hover:border-red-800 font-mono text-[11px] transition-colors"
          >
            DDoS SYN Flood
          </button>
          <button
            onClick={() => {
              applyPreset('portscan');
              setTimeout(handleAnalyze, 10);
            }}
            className="px-2.5 py-1 bg-slate-800 hover:bg-amber-950/60 text-slate-300 hover:text-amber-300 rounded border border-slate-700 hover:border-amber-800 font-mono text-[11px] transition-colors"
          >
            Stealth Port Scan
          </button>
          <button
            onClick={() => {
              applyPreset('bruteforce');
              setTimeout(handleAnalyze, 10);
            }}
            className="px-2.5 py-1 bg-slate-800 hover:bg-orange-950/60 text-slate-300 hover:text-orange-300 rounded border border-slate-700 hover:border-orange-800 font-mono text-[11px] transition-colors"
          >
            SSH Brute Force
          </button>
          <button
            onClick={() => {
              applyPreset('zeroday');
              setTimeout(handleAnalyze, 10);
            }}
            className="px-2.5 py-1 bg-slate-800 hover:bg-cyan-950/60 text-cyan-300 rounded border border-cyan-800/60 hover:border-cyan-600 font-mono text-[11px] font-medium transition-colors"
          >
            Zero-Day Anomaly (Unknown Attack)
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Interactive Input Matrix (7 cols) */}
        <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-lg p-5 space-y-5">
          <h4 className="text-xs uppercase tracking-wider text-slate-400 font-mono">
            Flow Properties & TCP Dimensions
          </h4>

          {/* Protocol & Port */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-slate-300 font-medium block mb-1.5">
                Protocol
              </label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value as ProtocolType)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-300 font-medium block mb-1.5">
                Destination Port
              </label>
              <input
                type="number"
                value={destinationPort}
                onChange={(e) => setDestinationPort(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Flow Duration Slider */}
          <div>
            <div className="flex justify-between text-xs mb-1 font-mono">
              <span className="text-slate-300">Flow Duration:</span>
              <span className="text-cyan-400 tabular-nums">{flowDurationMs} ms</span>
            </div>
            <input
              type="range"
              min="1"
              max="10000"
              step="5"
              value={flowDurationMs}
              onChange={(e) => setFlowDurationMs(Number(e.target.value))}
              className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-slate-800 rounded"
            />
          </div>

          {/* Packets Per Sec Slider */}
          <div>
            <div className="flex justify-between text-xs mb-1 font-mono">
              <span className="text-slate-300">Flow Packets/sec:</span>
              <span className="text-cyan-400 tabular-nums">{flowPacketsPerSec.toLocaleString()} pkts/s</span>
            </div>
            <input
              type="range"
              min="1"
              max="8000"
              step="10"
              value={flowPacketsPerSec}
              onChange={(e) => setFlowPacketsPerSec(Number(e.target.value))}
              className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-slate-800 rounded"
            />
          </div>

          {/* Bytes Per Sec Slider */}
          <div>
            <div className="flex justify-between text-xs mb-1 font-mono">
              <span className="text-slate-300">Flow Bytes/sec:</span>
              <span className="text-cyan-400 tabular-nums">{(flowBytesPerSec / 1024).toFixed(1)} KB/s</span>
            </div>
            <input
              type="range"
              min="100"
              max="12000000"
              step="5000"
              value={flowBytesPerSec}
              onChange={(e) => setFlowBytesPerSec(Number(e.target.value))}
              className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-slate-800 rounded"
            />
          </div>

          {/* Total Packets (Fwd & Bwd) */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-slate-300 block mb-1 font-mono">
                Total Fwd Packets: <span className="text-slate-100">{totalFwdPackets}</span>
              </label>
              <input
                type="range"
                min="1"
                max="150"
                value={totalFwdPackets}
                onChange={(e) => setTotalFwdPackets(Number(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-slate-800 rounded"
              />
            </div>
            <div>
              <label className="text-xs text-slate-300 block mb-1 font-mono">
                Total Bwd Packets: <span className="text-slate-100">{totalBwdPackets}</span>
              </label>
              <input
                type="range"
                min="0"
                max="150"
                value={totalBwdPackets}
                onChange={(e) => setTotalBwdPackets(Number(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-slate-800 rounded"
              />
            </div>
          </div>

          {/* Packet Length Mean */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-slate-300 block mb-1 font-mono">
                Fwd Length Mean: <span className="text-slate-100">{fwdPacketLengthMean} B</span>
              </label>
              <input
                type="range"
                min="20"
                max="3500"
                value={fwdPacketLengthMean}
                onChange={(e) => setFwdPacketLengthMean(Number(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-slate-800 rounded"
              />
            </div>
            <div>
              <label className="text-xs text-slate-300 block mb-1 font-mono">
                Inter-Arrival Mean (IAT): <span className="text-slate-100">{flowIATMeanMs} ms</span>
              </label>
              <input
                type="range"
                min="0.1"
                max="600"
                step="1"
                value={flowIATMeanMs}
                onChange={(e) => setFlowIATMeanMs(Number(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-slate-800 rounded"
              />
            </div>
          </div>

          {/* TCP Flags Checkboxes */}
          <div>
            <label className="text-xs text-slate-300 font-medium block mb-2">
              TCP Flags State
            </label>
            <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
              <label className="flex items-center gap-1.5 cursor-pointer text-slate-300">
                <input
                  type="checkbox"
                  checked={flagSyn === 1}
                  onChange={(e) => setFlagSyn(e.target.checked ? 1 : 0)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0"
                />
                SYN
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer text-slate-300">
                <input
                  type="checkbox"
                  checked={flagAck === 1}
                  onChange={(e) => setFlagAck(e.target.checked ? 1 : 0)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0"
                />
                ACK
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer text-slate-300">
                <input
                  type="checkbox"
                  checked={flagFin === 1}
                  onChange={(e) => setFlagFin(e.target.checked ? 1 : 0)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0"
                />
                FIN
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer text-slate-300">
                <input
                  type="checkbox"
                  checked={flagRst === 1}
                  onChange={(e) => setFlagRst(e.target.checked ? 1 : 0)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0"
                />
                RST
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer text-slate-300">
                <input
                  type="checkbox"
                  checked={flagPsh === 1}
                  onChange={(e) => setFlagPsh(e.target.checked ? 1 : 0)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0"
                />
                PSH
              </label>
            </div>
          </div>
        </div>

        {/* Right: Instant Classification Output & Explainability (5 cols) */}
        <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-lg p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <span className="text-xs uppercase tracking-wider text-slate-400 font-mono">
                Detection Verdict
              </span>
              <span className="text-xs text-slate-500 font-mono tabular-nums">
                Latency: {result?.processedAt ?? 0.02} ms
              </span>
            </div>

            {/* Big Verdict Banner */}
            <div className="mt-4 p-4 rounded-lg bg-slate-950 border border-slate-800 flex items-center gap-3.5">
              {result?.finalVerdict === 'ZeroDay' ? (
                <AlertTriangle className="w-8 h-8 text-cyan-400 shrink-0" />
              ) : result?.isThreat ? (
                <ShieldAlert className="w-8 h-8 text-red-400 shrink-0" />
              ) : (
                <ShieldCheck className="w-8 h-8 text-emerald-400 shrink-0" />
              )}
              <div>
                <div className="text-xs font-mono uppercase tracking-wide text-slate-400">
                  Classification Status
                </div>
                <div
                  className={`text-xl font-bold font-mono tracking-tight ${
                    result?.finalVerdict === 'ZeroDay'
                      ? 'text-cyan-400'
                      : result?.isThreat
                      ? 'text-red-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {result?.finalVerdict === 'ZeroDay'
                    ? 'ZERO-DAY NOVEL ANOMALY'
                    : result?.isThreat
                    ? `KNOWN ATTACK: ${result?.finalVerdict}`
                    : 'BENIGN / NORMAL FLOW'}
                </div>
              </div>
            </div>

            {/* Score Breakdown Gauges */}
            <div className="mt-4 space-y-3">
              {/* Random Forest Score */}
              <div>
                <div className="flex justify-between text-xs font-mono mb-1">
                  <span className="text-slate-400">Random Forest Confidence</span>
                  <span className="text-slate-200 tabular-nums">
                    {result ? (result.supervised.confidence * 100).toFixed(1) : 0}%
                  </span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className="bg-cyan-500 h-full rounded-full transition-all duration-300"
                    style={{
                      width: `${result ? result.supervised.confidence * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>

              {/* Isolation Forest Anomaly Score */}
              <div>
                <div className="flex justify-between text-xs font-mono mb-1">
                  <span className="text-slate-400">Isolation Forest Outlier Score</span>
                  <span
                    className={`tabular-nums font-semibold ${
                      result && result.outlier.anomalyScore > 0.62
                        ? 'text-cyan-400'
                        : 'text-slate-200'
                    }`}
                  >
                    {result ? result.outlier.anomalyScore.toFixed(3) : 0} (Threshold: 0.62)
                  </span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-300 ${
                      result && result.outlier.anomalyScore > 0.62
                        ? 'bg-cyan-400'
                        : 'bg-emerald-500'
                    }`}
                    style={{
                      width: `${result ? result.outlier.anomalyScore * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>
            </div>

            {/* Explainable Decision Path */}
            <div className="mt-5 space-y-2">
              <span className="text-xs font-medium text-slate-300 block">
                Dual-Engine Inference Summary:
              </span>
              <p className="text-xs text-slate-400 leading-relaxed bg-slate-950 p-3 rounded border border-slate-800/80">
                {result?.explanation}
              </p>
            </div>

            {/* Contributing Outlier Features */}
            {result && result.outlier.contributingFeatures.length > 0 && (
              <div className="mt-4 space-y-1.5">
                <span className="text-xs text-slate-400 font-mono">
                  Multivariate Outlier Dimensions:
                </span>
                <div className="space-y-1">
                  {result.outlier.contributingFeatures.map((f, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between text-xs font-mono bg-slate-950 px-2.5 py-1 rounded text-slate-300"
                    >
                      <span className="truncate">{f.featureName}</span>
                      <span className="text-amber-400 tabular-nums">z-score: {f.deviationZScore}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800 text-[11px] font-mono text-slate-500 flex justify-between items-center">
            <span>Client-side zero-backend execution</span>
            <button
              onClick={handleAnalyze}
              className="text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              Re-run Model
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
