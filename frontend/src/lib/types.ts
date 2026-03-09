// -- Auth --
export interface User {
  email: string;
  role: string;
  permissions: string[];
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

// -- Cases --
export interface CaseBrowseItem {
  case_id: string;
  title: string;
  severity: Severity;
  status: string;
  disposition?: string;
  analyst?: string;
  created?: string;
  ioc_totals?: Record<string, number>;
  external_refs?: string[];
}

export interface CaseDetail extends CaseBrowseItem {
  report_path?: string;
  findings?: Finding[];
  verdicts?: Verdict[];
  iocs?: IOCSet;
  kql_queries?: KQLQuery[];
  investigation_log?: LogEntry[];
}

export interface CaseSummary {
  case_id: string;
  title: string;
  severity: Severity;
  parsed?: ParsedInput;
}

// -- IOCs --
export interface IOCSet {
  ips?: string[];
  domains?: string[];
  hashes?: string[];
  urls?: string[];
  emails?: string[];
  [key: string]: string[] | undefined;
}

export interface Finding {
  type: string;
  summary: string;
  detail?: string;
}

export interface Verdict {
  priority: 'high' | 'medium' | 'low';
  iocs: string[];
  summary: string;
}

export interface KQLQuery {
  query: string;
  status: 'executed' | 'suggested';
  description?: string;
}

export interface LogEntry {
  ts: string;
  action: string;
  detail?: string;
  duration?: number;
  entries?: LogEntry[];
}

// -- Chat --
export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  ts?: string;
  tool_calls?: ToolCall[];
  files?: string[];
}

export interface ToolCall {
  name: string;
  input?: Record<string, any>;
  result?: string;
}

export interface SSEEvent {
  type: 'text_delta' | 'tool_start' | 'tool_result' | 'case_context_loaded' | 'done' | 'error';
  text?: string;
  name?: string;
  input?: Record<string, any>;
  result?: string;
  reply?: string;
  tool_calls?: ToolCall[];
  case_id?: string;
  title?: string;
  severity?: string;
  message?: string;
  usage?: TokenUsage;
}

export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
}

export interface ActivityItem {
  name: string;
  status: 'running' | 'done' | 'error';
  input?: Record<string, any>;
  result?: string;
}

// -- Sessions --
export interface SessionMeta {
  session_id: string;
  user_email: string;
  status: 'active' | 'materialised' | 'expired';
  title?: string;
  created: string;
  expires: string;
  case_id?: string;
  pinned?: boolean;
  tags?: string[];
}

export interface UserPreferences {
  custom_instructions: string;
  default_model_tier: string;
  response_style: string;
  pinned_sessions: string[];
  session_tags: Record<string, string[]>;
}

export interface SessionContext {
  iocs?: IOCSet;
  findings?: Finding[];
  telemetry_summaries?: string[];
  disposition?: string;
  active_thread_id?: string;
  active_thread_label?: string;
}

export interface ThreadSummary {
  id: string;
  label: string;
  created: string;
  active: boolean;
  ioc_count: number;
  finding_count: number;
  telemetry_count: number;
  disposition?: string;
}

// -- Dashboard / CTI --
export interface CTIFeedItem {
  title: string;
  url?: string;
  source?: string;
  date?: string;
  tags?: CTITag[];
}

export interface CTITag {
  type: 'actor' | 'malware' | 'campaign' | 'sector';
  name: string;
}

export interface TrendingIndicator {
  name: string;
  score: number;
  date?: string;
}

export interface WatchlistEntry {
  name: string;
  description?: string;
  activity_summary?: string;
}

export interface HeatmapCell {
  tactic: string;
  technique: string;
  count: number;
}

export interface IOCDecayEntry {
  ioc: string;
  status: 'active' | 'expired' | 'revoked' | 'not_in_cti';
  case_id?: string;
}

// -- Investigate --
export interface ParsedInput {
  urls?: string[];
  ips?: string[];
  hashes?: string[];
  emails?: string[];
  cves?: string[];
  severity?: string;
  title?: string;
}

// -- Misc --
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Status = 'open' | 'closed' | 'running' | 'complete' | 'failed' | 'queued';

export interface Toast {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  message: string;
  duration?: number;
}

// -- Job Status --
export interface JobStatus {
  case_id: string;
  status: 'queued' | 'running' | 'complete' | 'failed';
  error?: string;
}

// -- Command Palette --
export interface CommandAction {
  id: string;
  label: string;
  shortcut?: string;
  section: string;
  action: () => void;
}

// -- Landscape --
export interface LandscapeData {
  case_stats?: Record<string, number>;
  ioc_intelligence?: any;
  link_analysis?: any;
}
