import React, { useEffect, useRef, useState } from 'react';
import { HybridDetectionResult } from '../../types/nids';

interface OutlierScatterCanvasProps {
  flows: HybridDetectionResult[];
  height?: number;
}

export const OutlierScatterCanvas: React.FC<OutlierScatterCanvasProps> = ({
  flows,
  height = 220,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [hoveredFlow, setHoveredFlow] = useState<HybridDetectionResult | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const width = rect.width;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    ctx.clearRect(0, 0, width, height);

    const padding = { top: 20, right: 20, bottom: 35, left: 45 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    // Draw coordinate axes
    ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
    ctx.lineWidth = 1;

    // Horizontal grid lines (Flow Packets/s)
    const ySteps = 4;
    for (let i = 0; i <= ySteps; i++) {
      const y = padding.top + (chartH / ySteps) * i;
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();
    }

    // Vertical grid lines (Flow Bytes/s)
    const xSteps = 5;
    for (let i = 0; i <= xSteps; i++) {
      const x = padding.left + (chartW / xSteps) * i;
      ctx.beginPath();
      ctx.moveTo(x, padding.top);
      ctx.lineTo(x, height - padding.bottom);
      ctx.stroke();
    }

    // Axis labels
    ctx.fillStyle = '#64748b';
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.textAlign = 'right';
    ctx.fillText('10k pkts/s', padding.left - 6, padding.top + 8);
    ctx.fillText('0', padding.left - 6, height - padding.bottom);

    ctx.textAlign = 'center';
    ctx.fillText('100 B/s', padding.left + 15, height - 12);
    ctx.fillText('Flow Bytes/sec (Log Scale) →', width / 2, height - 8);
    ctx.fillText('100 MB/s', width - padding.right - 20, height - 12);

    // Render sample points (limit to most recent 250 for crisp rendering)
    const renderedFlows = flows.slice(-250);

    renderedFlows.forEach((res) => {
      const f = res.flow;

      // X coordinate: Log10 of Bytes/sec mapped between log10(50) and log10(20,000,000)
      const minLogX = Math.log10(50);
      const maxLogX = Math.log10(20000000);
      const currentLogX = Math.log10(Math.max(50, f.flowBytesPerSec));
      const normX = Math.min(1, Math.max(0, (currentLogX - minLogX) / (maxLogX - minLogX)));
      const x = padding.left + normX * chartW;

      // Y coordinate: Packets/sec mapped between 0 and 5000 (with sqrt compress for visibility)
      const maxPps = 5000;
      const normY = Math.min(1, Math.max(0, Math.sqrt(f.flowPacketsPerSec) / Math.sqrt(maxPps)));
      const y = padding.top + chartH - normY * chartH;

      ctx.beginPath();
      if (res.finalVerdict === 'ZeroDay') {
        // Zero-day outlier: Cyan glowing diamond
        ctx.fillStyle = '#06b6d4';
        ctx.arc(x, y, 4.5, 0, 2 * Math.PI);
        ctx.fill();
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.2;
        ctx.stroke();
      } else if (res.isThreat) {
        // Known threat: Crimson circle
        ctx.fillStyle = '#ef4444';
        ctx.arc(x, y, 3.5, 0, 2 * Math.PI);
        ctx.fill();
      } else {
        // Benign: Quiet emerald dot
        ctx.fillStyle = 'rgba(16, 185, 129, 0.45)';
        ctx.arc(x, y, 2.5, 0, 2 * Math.PI);
        ctx.fill();
      }
    });
  }, [flows, height]);

  return (
    <div className="w-full bg-slate-900/70 border border-slate-800 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <div>
          <h4 className="text-sm font-semibold text-slate-200">Isolation Forest 2D Feature Space</h4>
          <p className="text-xs text-slate-500 mt-0.5">Multivariate outlier projection (Flow Volume vs. Packet Frequency)</p>
        </div>
        <div className="flex items-center gap-3 text-[11px] font-mono">
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500/60 inline-block" /> Benign
          </span>
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-red-500 inline-block" /> Known Attack
          </span>
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 border border-white inline-block" /> Zero-Day Outlier
          </span>
        </div>
      </div>

      <div className="w-full relative mt-3">
        <canvas
          ref={canvasRef}
          style={{ width: '100%', height: `${height}px` }}
          className="block"
        />
      </div>
    </div>
  );
};
