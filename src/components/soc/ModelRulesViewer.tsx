import React from 'react';
import { Cpu, Sliders, Shield, GitBranch, Layers } from 'lucide-react';
import { EngineConfig } from '../../engine/hybridEngine';

interface ModelRulesViewerProps {
  config: EngineConfig;
  onUpdateConfig: (newConfig: EngineConfig) => void;
}

export const ModelRulesViewer: React.FC<ModelRulesViewerProps> = ({
  config,
  onUpdateConfig,
}) => {
  return (
    <div className="w-full space-y-6">
      {/* Hyperparameter Tuning Section */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
        <div className="flex items-center gap-2 mb-2">
          <Sliders className="w-4 h-4 text-cyan-400" />
          <h3 className="text-base font-semibold text-slate-100">
            Runtime Hyperparameter Calibration
          </h3>
        </div>
        <p className="text-xs text-slate-400 mb-6">
          Calibrate the trade-off between detection sensitivity and false positive minimization directly in browser memory.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Isolation Forest Threshold */}
          <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3">
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-200 font-semibold">
                Isolation Forest Outlier Cutoff
              </span>
              <span className="text-cyan-400 font-bold tabular-nums">
                {config.isolationThreshold.toFixed(2)}
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Flows with isolation anomaly scores exceeding this cutoff are flagged as novel Zero-Day attacks. Lower values increase recall; higher values prevent false alarms.
            </p>
            <input
              type="range"
              min="0.45"
              max="0.85"
              step="0.01"
              value={config.isolationThreshold}
              onChange={(e) =>
                onUpdateConfig({
                  ...config,
                  isolationThreshold: Number(e.target.value),
                })
              }
              className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-slate-800 rounded"
            />
            <div className="flex justify-between text-[10px] text-slate-500 font-mono">
              <span>0.45 (Aggressive / High Recall)</span>
              <span>0.62 (Balanced)</span>
              <span>0.85 (Strict Zero-Day)</span>
            </div>
          </div>

          {/* Random Forest Confidence Cutoff */}
          <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3">
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-200 font-semibold">
                Random Forest Signature Confidence
              </span>
              <span className="text-cyan-400 font-bold tabular-nums">
                {(config.rfConfidenceCutoff * 100).toFixed(0)}%
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Minimum tree ensemble voting agreement required before accepting a known attack signature classification (e.g. DDoS, PortScan, BruteForce).
            </p>
            <input
              type="range"
              min="0.50"
              max="0.95"
              step="0.05"
              value={config.rfConfidenceCutoff}
              onChange={(e) =>
                onUpdateConfig({
                  ...config,
                  rfConfidenceCutoff: Number(e.target.value),
                })
              }
              className="w-full accent-cyan-500 cursor-pointer h-1.5 bg-slate-800 rounded"
            />
            <div className="flex justify-between text-[10px] text-slate-500 font-mono">
              <span>50% (Permissive)</span>
              <span>65% (Recommended)</span>
              <span>95% (Strict)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Model Architectures & Feature Importance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Supervised Random Forest Rules */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-emerald-400" />
            <h4 className="text-sm font-semibold text-slate-200">
              Engine 1: Supervised Random Forest Ensemble
            </h4>
          </div>
          <p className="text-xs text-slate-400">
            Formulated on decision boundaries from CIC-IDS2017 multi-class threat traces:
          </p>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="bg-slate-950 p-3 rounded border border-slate-800">
              <span className="text-red-400 font-semibold block">Tree 1: Volumetric Floods (DDoS)</span>
              <span className="text-slate-400 text-[11px]">
                Condition: <code className="text-slate-300">Packets/s &gt; 2500 || (Bytes/s &gt; 5MB/s && Duration &lt; 1s)</code>
              </span>
            </div>

            <div className="bg-slate-950 p-3 rounded border border-slate-800">
              <span className="text-amber-400 font-semibold block">Tree 2: Reconnaissance Probes (PortScan)</span>
              <span className="text-slate-400 text-[11px]">
                Condition: <code className="text-slate-300">FwdPkts &le; 3 && SYN=1 && ACK=0 && Duration &lt; 80ms</code>
              </span>
            </div>

            <div className="bg-slate-950 p-3 rounded border border-slate-800">
              <span className="text-orange-400 font-semibold block">Tree 3: Credential Exhaustion (BruteForce)</span>
              <span className="text-slate-400 text-[11px]">
                Condition: <code className="text-slate-300">Port &isin; [21, 22, 3389] && Pkts &ge; 8 && IATMean &lt; 50ms</code>
              </span>
            </div>

            <div className="bg-slate-950 p-3 rounded border border-slate-800">
              <span className="text-pink-400 font-semibold block">Tree 4: Application Exploits (WebAttack)</span>
              <span className="text-slate-400 text-[11px]">
                Condition: <code className="text-slate-300">Port &isin; [80, 443, 8080] && FwdPacketLength &gt; 1200 && PSH=1</code>
              </span>
            </div>

            <div className="bg-slate-950 p-3 rounded border border-slate-800">
              <span className="text-purple-400 font-semibold block">Tree 5: Command & Control (Botnet)</span>
              <span className="text-slate-400 text-[11px]">
                Condition: <code className="text-slate-300">IATMean &isin; [300ms, 2000ms] && Pkts/s &lt; 5 && Jitter &lt; 5ms</code>
              </span>
            </div>
          </div>
        </div>

        {/* Unsupervised Isolation Forest Baseline Distributions */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h4 className="text-sm font-semibold text-slate-200">
              Engine 2: Isolation Forest Feature Baselines
            </h4>
          </div>
          <p className="text-xs text-slate-400">
            Empirical normal distribution parameters calibrated against standard enterprise network flows:
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px] uppercase tracking-wider">
                  <th className="py-2 px-2.5">Feature</th>
                  <th className="py-2 px-2.5 text-right">Benign Mean (&mu;)</th>
                  <th className="py-2 px-2.5 text-right">Std Dev (&sigma;)</th>
                  <th className="py-2 px-2.5 text-right">Weight</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                <tr>
                  <td className="py-2 px-2.5">flowPacketsPerSec</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">45.2 pkts/s</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">&plusmn;110.5</td>
                  <td className="py-2 px-2.5 text-right tabular-nums text-cyan-400">1.5x</td>
                </tr>
                <tr>
                  <td className="py-2 px-2.5">flowBytesPerSec</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">12.5 KB/s</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">&plusmn;45.0 KB/s</td>
                  <td className="py-2 px-2.5 text-right tabular-nums text-cyan-400">1.2x</td>
                </tr>
                <tr>
                  <td className="py-2 px-2.5">flowDurationMs</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">350.0 ms</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">&plusmn;800.0</td>
                  <td className="py-2 px-2.5 text-right tabular-nums text-cyan-400">1.0x</td>
                </tr>
                <tr>
                  <td className="py-2 px-2.5">fwdPacketLengthMean</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">280.0 B</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">&plusmn;320.0</td>
                  <td className="py-2 px-2.5 text-right tabular-nums text-cyan-400">1.1x</td>
                </tr>
                <tr>
                  <td className="py-2 px-2.5">flowIATMeanMs</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">48.0 ms</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">&plusmn;95.0</td>
                  <td className="py-2 px-2.5 text-right tabular-nums text-cyan-400">1.2x</td>
                </tr>
                <tr>
                  <td className="py-2 px-2.5">TCP Flag Conflict (SYN+FIN)</td>
                  <td className="py-2 px-2.5 text-right tabular-nums text-red-400">RFC Invariant</td>
                  <td className="py-2 px-2.5 text-right tabular-nums">Outlier</td>
                  <td className="py-2 px-2.5 text-right tabular-nums text-cyan-400">2.0x</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
