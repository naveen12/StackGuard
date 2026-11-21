import { memo } from 'react';
import { Severity } from '../types/security';

interface SeverityStyle {
  label: string;
  code: string;
  bg: string;
  border: string;
  text: string;
  stripe: string;
  dot: string;
}

export const SEVERITY_STYLES: Record<Severity, SeverityStyle> = {
  critical: {
    label: 'CRITICAL',
    code: 'CRIT',
    bg: 'bg-[#EF4444]/12',
    border: 'border-[#EF4444]/40',
    text: 'text-[#F87171]',
    stripe: 'bg-[#EF4444]',
    dot: 'bg-[#EF4444]',
  },
  high: {
    label: 'HIGH',
    code: 'HIGH',
    bg: 'bg-[#F97316]/12',
    border: 'border-[#F97316]/40',
    text: 'text-[#FB923C]',
    stripe: 'bg-[#F97316]',
    dot: 'bg-[#F97316]',
  },
  moderate: {
    label: 'MODERATE',
    code: 'MOD',
    bg: 'bg-[#F59E0B]/12',
    border: 'border-[#F59E0B]/40',
    text: 'text-[#FBBF24]',
    stripe: 'bg-[#F59E0B]',
    dot: 'bg-[#F59E0B]',
  },
  low: {
    label: 'LOW',
    code: 'LOW',
    bg: 'bg-[#64748B]/15',
    border: 'border-[#64748B]/40',
    text: 'text-[#94A3B8]',
    stripe: 'bg-[#64748B]',
    dot: 'bg-[#64748B]',
  },
  safe: {
    label: 'REMEDIATED',
    code: 'SAFE',
    bg: 'bg-[#10B981]/12',
    border: 'border-[#10B981]/40',
    text: 'text-[#34D399]',
    stripe: 'bg-[#10B981]',
    dot: 'bg-[#10B981]',
  },
};

interface SeverityBadgeProps {
  severity: Severity;
  cvssScore?: number;
  compact?: boolean;
}

export const SeverityBadge = memo(function SeverityBadge({ severity, cvssScore, compact = false }: SeverityBadgeProps) {
  const style = SEVERITY_STYLES[severity];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] whitespace-nowrap shrink-0 tabular-nums ${style.bg} ${style.border} ${style.text}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${style.dot}`} aria-hidden="true" />
      {typeof cvssScore === 'number' && severity !== 'safe' && (
        <span className="font-semibold">{cvssScore.toFixed(1)}</span>
      )}
      <span>{compact ? style.code : style.label}</span>
    </span>
  );
});
