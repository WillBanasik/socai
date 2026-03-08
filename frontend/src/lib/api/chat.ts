import { apiFetch } from './client';

export interface StreamChatParams {
  caseId?: string;
  sessionId?: string;
  message: string;
  modelTier?: string;
  files?: File[];
}

export async function streamChat(params: StreamChatParams): Promise<Response> {
  const fd = new FormData();
  fd.append('message', params.message);
  if (params.modelTier) fd.append('model_tier', params.modelTier);
  if (params.files) {
    for (const f of params.files) fd.append('files', f);
  }

  let url: string;
  if (params.sessionId) {
    url = `/api/sessions/${params.sessionId}/chat/stream`;
  } else if (params.caseId) {
    url = `/api/cases/${params.caseId}/chat/stream`;
  } else {
    url = '/api/chat/stream';
    if (params.caseId) fd.append('case_id', params.caseId);
  }

  return apiFetch(url, { method: 'POST', body: fd });
}

export async function getGlobalChatHistory(): Promise<any[]> {
  const resp = await apiFetch('/api/chat/history');
  return resp.json();
}
