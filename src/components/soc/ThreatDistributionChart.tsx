import React from 'react';
import { AttackCategory } from '../../types/nids';

interface ThreatDistributionChartProps {
  distribution: Record<AttackCategory, number>;
  totalFlows: number;
}

const CATEGORY_COLORS: Record<AttackCategory, { color: string; label: string }> = {
  Benign: { color: '#10b981', label: 'Benign' },
  DDoS: { color: '#ef4444', label: 'DDoS' },
  PortScan: { color: '#f59e0b', label: 'Port Scan' },
  BruteForce: { color: '#f97316', label: 'Brute Force' },
  WebAttack: { color: '#ec4899', label: 'Web Exploit' },
  Botnet: { color: '#a855f7', label: 'Botnet C2' },
  Infiltration: { color: '#6366f1', label: 'Infiltration' },
  ZeroDay: { color: '#06b6d4', label: 'Zero-Day' },
};

export const ThreatDistributionChart: React.FC<ThreatDistributionChartProps> = ({
  distribution,
  totalFlows,
}) => {
  const categories = (Object.keys(distribution) as AttackCategory[]).filter(
    (cat) => distribution[cat] > 0
  );

  // Calculate cumulative percentages for SVG donut chart
  let cumulative = 0;
  const radius = 38;
  const circumference = 2 * Math.PI * radius;

  const slices = categories.map((cat) => {
    const count = distribution[cat];
    const fraction = totalFlows > 0 ? count / totalFlows : 0;
    const strokeDasharray = `${fraction * circumference} ${circumference}`;
    const strokeDashoffset = -cumulative * circumference;
    cumulative += fraction;

    return {
      category: cat,
      count,
      percentage: (fraction * 100).toFixed(1),
      color: CATEGORY_COLORS[cat].color,
      label: CATEGORY_COLORS[cat].label,
      strokeDasharray,
      strokeDashoffset,
    };
  });

  const totalThreats = totalFlows - (distribution.Benign || 0);

  return (
    <div className="w-full bg-slate-900/70 border border-slate-800 rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h4 className="text-sm font-semibold text-slate-200">Attack Classification Distribution</h4>
          <p className="text-xs text-slate-500 mt-0.5">Supervised and unsupervised detection breakdown</p>
        </div>
        <div className="text-right font-mono text-xs text-slate-400">
          <span className="text-red-400 font-semibold tabular-nums">{totalThreats}</span> / {totalFlows} threats
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        {/* Donut Visual */}
        <div className="md:col-span-5 flex justify-center items-center relative py-2">
          <svg className="w-36 h-36 transform -rotate-90" viewBox="0 0 100 100">
            {/* Background ring */}
            <circle
              cx="50"
              cy="50"
              r={radius}
              fill="transparent"
              stroke="#1e293b"
              strokeWidth="14"
            />
            {/* Slices */}
            {slices.map((s) => (
              <circle
                key={s.category}
                cx="50"
                cy="50"
                r={radius}
                fill="transparent"
                stroke={s.color}
                strokeWidth="14"
                strokeDasharray={s.strokeDasharray}
                strokeDashoffset={s.strokeDashoffset}
                strokeLinecap="butt"
                className="transition-all duration-300 hover:opacity-90 cursor-pointer"
              />
            ))}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
            <span className="text-lg font-bold font-mono text-slate-100 tabular-nums">
              {totalFlows > 0 ? `${(((totalFlows - (distribution.Benign || 0)) / totalFlows) * 100).toFixed(0)}%` : '0%'}
            </span>
            <span className="text-[10px] text-slate-500 tracking-wider uppercase font-medium">Threat Ratio</span>
          </div>
        </div>

        {/* Breakdown List */}
        <div className="md:col-span-7 space-y-2">
          {slices.length === 0 ? (
            <div className="text-xs text-slate-500 italic py-4 text-center">No classified flows captured yet</div>
          ) : (
            slices.map((s) => (
              <div key={s.category} className="flex items-center justify-between text-xs py-0.5">
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className="w-2.5 h-2.5 rounded-sm shrink-0"
                    style={{ backgroundColor: s.color }}
                  />
                  <span className="text-slate-300 font-medium truncate">{s.label}</span>
                </div>
                <div className="flex items-center gap-3 font-mono text-slate-400 shrink-0 tabular-nums">
                  <span className="text-slate-200">{s.count.toLocaleString()}</span>
                  <span className="text-slate-500 w-12 text-right">{s.percentage}%</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
