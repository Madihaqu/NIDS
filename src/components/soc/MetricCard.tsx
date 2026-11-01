import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon: LucideIcon;
  variant?: 'default' | 'alert' | 'success' | 'warning';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtext,
  icon: Icon,
  variant = 'default',
}) => {
  const getVariantStyles = () => {
    switch (variant) {
      case 'alert':
        return {
          iconColor: 'text-red-400',
          valueColor: 'text-red-300',
          borderColor: 'border-slate-800 hover:border-red-900/60',
        };
      case 'success':
        return {
          iconColor: 'text-emerald-400',
          valueColor: 'text-emerald-300',
          borderColor: 'border-slate-800 hover:border-emerald-900/60',
        };
      case 'warning':
        return {
          iconColor: 'text-amber-400',
          valueColor: 'text-amber-300',
          borderColor: 'border-slate-800 hover:border-amber-900/60',
        };
      default:
        return {
          iconColor: 'text-cyan-400',
          valueColor: 'text-slate-100',
          borderColor: 'border-slate-800 hover:border-slate-700',
        };
    }
  };

  const styles = getVariantStyles();

  return (
    <div
      className={`bg-slate-900/80 border ${styles.borderColor} rounded-lg p-4 transition-all duration-200 flex flex-col justify-between`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-slate-400 tracking-wide">{label}</span>
        <Icon className={`w-4 h-4 ${styles.iconColor} shrink-0`} />
      </div>

      <div className="mt-3">
        <div className={`text-2xl font-bold font-mono tracking-tight tabular-nums ${styles.valueColor}`}>
          {value}
        </div>
        {subtext && (
          <div className="text-xs text-slate-500 mt-1 font-mono tracking-tight truncate">
            {subtext}
          </div>
        )}
      </div>
    </div>
  );
};
