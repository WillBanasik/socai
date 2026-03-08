import type { Severity } from '../types';

export const severityColours: Record<string, string> = {
  critical: 'bg-sev-critical/20 text-sev-critical border-sev-critical/30',
  high: 'bg-sev-high/20 text-sev-high border-sev-high/30',
  medium: 'bg-sev-medium/20 text-sev-medium border-sev-medium/30',
  low: 'bg-sev-low/20 text-sev-low border-sev-low/30',
  info: 'bg-sev-info/20 text-sev-info border-sev-info/30',
};

export const statusColours: Record<string, string> = {
  open: 'bg-status-open/20 text-status-open border-status-open/30',
  closed: 'bg-status-closed/20 text-status-closed border-status-closed/30',
  running: 'bg-status-running/20 text-status-running border-status-running/30',
  queued: 'bg-status-running/20 text-status-running border-status-running/30',
  complete: 'bg-status-complete/20 text-status-complete border-status-complete/30',
  failed: 'bg-status-failed/20 text-status-failed border-status-failed/30',
};

export const dispositionColours: Record<string, string> = {
  malicious: 'bg-disp-malicious/20 text-disp-malicious border-disp-malicious/30',
  true_positive: 'bg-disp-tp/20 text-disp-tp border-disp-tp/30',
  suspicious: 'bg-disp-suspicious/20 text-disp-suspicious border-disp-suspicious/30',
  benign: 'bg-disp-benign/20 text-disp-benign border-disp-benign/30',
  false_positive: 'bg-disp-fp/20 text-disp-fp border-disp-fp/30',
  inconclusive: 'bg-disp-inconclusive/20 text-disp-inconclusive border-disp-inconclusive/30',
};

export function getBadgeClass(type: 'severity' | 'status' | 'disposition', value: string): string {
  const map = type === 'severity' ? severityColours : type === 'status' ? statusColours : dispositionColours;
  return map[value] || 'bg-gray-700/20 text-gray-400 border-gray-600/30';
}
