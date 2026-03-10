/** Friendly labels for tool calls — maps tool_name to [agent, task description]. */
const TOOL_LABELS: Record<string, [string, string]> = {
  // Collection & capture
  capture_urls:           ['Web Capture',       'Fetching page content and screenshots'],
  analyse_email:          ['Email Analyst',     'Parsing email headers and extracting IOCs'],
  ingest_velociraptor:    ['Forensics',         'Ingesting Velociraptor collection'],
  ingest_mde_package:     ['Forensics',         'Ingesting MDE investigation package'],
  analyse_telemetry:      ['Telemetry',         'Parsing uploaded telemetry files'],
  read_uploaded_file:     ['File Reader',       'Reading uploaded file contents'],
  read_case_file:         ['File Reader',       'Reading case artefact'],
  add_evidence:           ['Evidence',          'Adding evidence to case'],

  // Analysis
  triage_iocs:            ['Triage',            'Checking IOCs against known intelligence'],
  extract_iocs:           ['IOC Extraction',    'Extracting indicators from artefacts'],
  enrich_iocs:            ['Enrichment',        'Enriching IOCs across threat intel providers'],
  detect_phishing:        ['Phishing Detection','Analysing page for phishing indicators'],
  correlate:              ['Correlation',       'Cross-referencing IOCs with log entities'],
  correlate_event_logs:   ['EVTX Analysis',     'Correlating Windows event log attack chains'],
  analyse_pe_files:       ['PE Analysis',       'Static analysis of PE executables'],
  yara_scan:              ['YARA',              'Scanning files with YARA rules'],
  contextualise_cves:     ['CVE Context',       'Enriching CVEs with NVD, EPSS, and KEV data'],
  campaign_cluster:       ['Campaign Intel',    'Clustering IOCs across cases'],
  memory_dump_guide:      ['Memory Forensics',  'Generating memory dump acquisition guide'],
  analyse_memory_dump:    ['Memory Forensics',  'Analysing process memory dump'],

  // Queries & KQL
  run_kql:                ['KQL',               'Executing query against Sentinel workspace'],
  generate_queries:       ['Query Generation',  'Generating SIEM hunt queries'],
  load_kql_playbook:      ['KQL Playbook',      'Loading investigation playbook queries'],

  // Reporting
  generate_report:        ['Report Writer',     'Generating investigation report'],
  generate_mdr_report:    ['MDR Report',        'Generating client-facing MDR report'],
  generate_fp_ticket:     ['FP Ticket',         'Generating false positive suppression ticket'],
  generate_fp_comment:    ['FP Comment',        'Generating false positive comment'],
  generate_executive_summary: ['Exec Summary',  'Generating executive summary for leadership'],
  security_arch_review:   ['Security Arch',     'Running security architecture review'],
  reconstruct_timeline:   ['Timeline',          'Reconstructing forensic timeline'],

  // Case & session management
  assess_landscape:       ['Landscape',         'Assessing threat landscape across cases'],
  link_cases:             ['Case Links',        'Linking related cases'],
  merge_cases:            ['Case Links',        'Merging duplicate cases'],
  recall_cases:           ['Case Search',       'Searching past investigations'],
  finalise_case:          ['Case Manager',      'Finalising investigation case'],
  materialise_case:       ['Case Manager',      'Finalising investigation case'],
  load_case_context:      ['Context',           'Loading existing case into session'],
  save_to_case:           ['Context',           'Saving findings back to case'],
  add_finding:            ['Findings',          'Recording investigation finding'],
  run_full_pipeline:      ['Chief',             'Running full investigation pipeline'],

  // Browser sessions
  start_browser_session:  ['Browser',           'Launching disposable browser session'],
  stop_browser_session:   ['Browser',           'Stopping browser session and collecting data'],
  list_browser_sessions:  ['Browser',           'Listing active browser sessions'],

  // Threat articles
  search_threat_articles: ['Threat Intel',      'Searching threat article feeds'],
  generate_threat_article:['Threat Intel',      'Generating threat article summary'],
  list_threat_articles:   ['Threat Intel',      'Listing published threat articles'],
};

export function getToolLabel(toolName: string): { agent: string; task: string } {
  const entry = TOOL_LABELS[toolName];
  if (entry) return { agent: entry[0], task: entry[1] };
  // Fallback: humanise the tool name
  const humanised = toolName.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  return { agent: 'Tool', task: humanised };
}
