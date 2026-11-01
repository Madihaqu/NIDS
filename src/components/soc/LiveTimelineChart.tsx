import React, { useEffect, useRef } from 'react';

export interface TimelineDataPoint {
  timestamp: number;
  totalCount: number;
  threatCount: number;
}

interface LiveTimelineChartProps {
  data: TimelineDataPoint[];
  height?: number;
}

export const LiveTimelineChart: React.FC<LiveTimelineChartProps> = ({
  data,
  height = 180,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Handle high DPI displays
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const width = rect.width;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    // Clear
    ctx.clearRect(0, 0, width, height);

    if (data.length < 2) {
      ctx.fillStyle = '#64748b';
      ctx.font = '12px "JetBrains Mono", monospace';
      ctx.textAlign = 'center';
      ctx.fillText('Listening for flow packets...', width / 2, height / 2);
      return;
    }

    const padding = { top: 20, right: 15, bottom: 25, left: 35 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    // Find max value
    let maxVal = 10;
    data.forEach((d) => {
      if (d.totalCount > maxVal) maxVal = d.totalCount;
    });
    maxVal = Math.ceil(maxVal * 1.2);

    // Draw background grid lines
    ctx.strokeStyle = 'rgba(51, 65, 85, 0.3)';
    ctx.lineWidth = 1;
    const gridLines = 4;
    for (let i = 0; i <= gridLines; i++) {
      const y = padding.top + (chartH / gridLines) * i;
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();

      const labelVal = Math.round(maxVal - (maxVal / gridLines) * i);
      ctx.fillStyle = '#64748b';
      ctx.font = '10px "JetBrains Mono", monospace';
      ctx.textAlign = 'right';
      ctx.fillText(labelVal.toString(), padding.left - 6, y + 3);
    }

    const stepX = chartW / (data.length - 1);

    // 1. Draw Total Flows Curve (Cyan)
    ctx.beginPath();
    data.forEach((d, idx) => {
      const x = padding.left + idx * stepX;
      const y = padding.top + chartH - (d.totalCount / maxVal) * chartH;
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#06b6d4'; // Cyan-500
    ctx.lineWidth = 2;
    ctx.stroke();

    // Fill Total Area Gradient
    ctx.lineTo(padding.left + (data.length - 1) * stepX, padding.top + chartH);
    ctx.lineTo(padding.left, padding.top + chartH);
    ctx.closePath();
    const gradTotal = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartH);
    gradTotal.addColorStop(0, 'rgba(6, 182, 212, 0.25)');
    gradTotal.addColorStop(1, 'rgba(6, 182, 212, 0.01)');
    ctx.fillStyle = gradTotal;
    ctx.fill();

    // 2. Draw Threat Flows Curve (Crimson / Red-500)
    ctx.beginPath();
    data.forEach((d, idx) => {
      const x = padding.left + idx * stepX;
      const y = padding.top + chartH - (d.threatCount / maxVal) * chartH;
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#ef4444'; // Red-500
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // Fill Threat Area Gradient
    ctx.lineTo(padding.left + (data.length - 1) * stepX, padding.top + chartH);
    ctx.lineTo(padding.left, padding.top + chartH);
    ctx.closePath();
    const gradThreat = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartH);
    gradThreat.addColorStop(0, 'rgba(239, 68, 68, 0.35)');
    gradThreat.addColorStop(1, 'rgba(239, 68, 68, 0.02)');
    ctx.fillStyle = gradThreat;
    ctx.fill();

    // Draw bottom time labels
    ctx.fillStyle = '#64748b';
    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.textAlign = 'left';
    ctx.fillText('60s ago', padding.left, height - 8);
    ctx.textAlign = 'right';
    ctx.fillText('Live now', width - padding.right, height - 8);
  }, [data, height]);

  return (
    <div className="w-full relative">
      <div className="flex items-center justify-between mb-2 text-xs">
        <span className="font-medium text-slate-300">Flow Throughput & Threat Velocity</span>
        <div className="flex items-center gap-4 text-[11px] font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-cyan-500 rounded-full inline-block"></span>
            <span className="text-slate-400">Total Flows</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-red-500 rounded-full inline-block"></span>
            <span className="text-slate-400">Anomalous / Attacks</span>
          </div>
        </div>
      </div>
      <div className="w-full bg-slate-900/70 border border-slate-800 rounded-lg p-2">
        <canvas
          ref={canvasRef}
          style={{ width: '100%', height: `${height}px` }}
          className="block"
        />
      </div>
    </div>
  );
};
