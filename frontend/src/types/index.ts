export interface Profile {
  id: string;
  email?: string;
  full_name?: string;
  avatar_url?: string;
  gemini_api_key?: string;
  created_at?: string;
}

export interface Scan {
  id: string;
  user_id: string;
  project_name: string;
  source_type: 'paste' | 'zip' | 'github';
  status: 'pending' | 'scanning' | 'done' | 'error';
  overall_score?: number;
  projected_score?: number;
  grade?: string;
  raw_code?: string;
  created_at?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  cvss_score?: number;
  owasp_category?: string;
  cwe_id?: string;
  vulnerable_snippet?: string;
  secure_fix?: string;
  fix_recommendation?: string;
  impact_analysis?: string;
  attack_narrative?: string;
  file_path?: string;
  line_number?: number;
  is_ai_smell?: boolean;
  is_fixed?: boolean;
  created_at?: string;
}

export interface IdorEndpoint {
  id: string;
  scan_id: string;
  endpoint: string;
  method?: string;
  risk_level: 'High' | 'Medium' | 'Low';
  has_auth_check?: boolean;
  has_ownership_check?: boolean;
  reasoning?: string;
  line_number?: number;
  created_at?: string;
}

export interface ComplianceFlag {
  id: string;
  scan_id: string;
  framework?: 'GDPR' | 'PCI-DSS' | 'SOC2' | 'OWASP ASVS';
  risk_level?: 'Critical' | 'High' | 'Medium';
  reason?: string;
  created_at?: string;
}

export interface Report {
  id: string;
  scan_id: string;
  pdf_url?: string;
  created_at?: string;
}
