import { apiJson, apiPost, apiFetch } from './client';
import type { CaseBrowseItem, CaseDetail, CaseSummary, IOCSet, JobStatus, LogEntry } from '../types';

export async function browseCases(): Promise<CaseBrowseItem[]> {
  return apiJson<CaseBrowseItem[]>('/api/investigations/browse');
}

export async function getCaseDetail(caseId: string): Promise<CaseDetail> {
  return apiJson<CaseDetail>(`/api/investigations/${caseId}`);
}

export async function getCaseReport(caseId: string): Promise<string> {
  const resp = await apiFetch(`/api/investigations/${caseId}/report`);
  const data = await resp.json();
  return data.report || data.content || '';
}

export async function getCaseIOCs(caseId: string): Promise<IOCSet> {
  const data = await apiJson<{ iocs: IOCSet }>(`/api/investigations/${caseId}/iocs`);
  return data.iocs || {};
}

export async function getCaseVerdicts(caseId: string): Promise<any> {
  return apiJson(`/api/investigations/${caseId}/verdicts`);
}

export async function getCaseTimeline(caseId: string): Promise<LogEntry[]> {
  return apiJson<LogEntry[]>(`/api/cases/${caseId}/timeline`);
}

export async function createCase(data: {
  text: string;
  severity: string;
  title?: string;
  zip_file?: File;
  eml_files?: File[];
}): Promise<CaseSummary> {
  return apiPost<CaseSummary>('/api/cases', data);
}

export async function submitInvestigation(data: {
  text: string;
  severity: string;
  title?: string;
  zip_file?: File;
  eml_files?: File[];
  zip_pass?: string;
  detonate?: boolean;
  close_case?: boolean;
}): Promise<{ case_id: string; status: string }> {
  return apiPost('/api/investigations', data);
}

export async function getJobStatus(caseId: string): Promise<JobStatus> {
  return apiJson<JobStatus>(`/api/investigations/${caseId}/status`);
}

export async function runCaseAction(caseId: string, action: string, data: Record<string, any> = {}): Promise<any> {
  return apiPost(`/api/cases/${caseId}/actions/${action}`, data);
}

export async function getChatHistory(caseId: string): Promise<any[]> {
  return apiJson<any[]>(`/api/cases/${caseId}/chat-history`);
}

export async function getContextSummary(): Promise<any> {
  return apiJson('/api/investigations/context-summary');
}
