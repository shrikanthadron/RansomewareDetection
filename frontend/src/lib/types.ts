export type UserRole = "USER" | "ADMIN";

export interface User {
  id: string;
  full_name: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  preferences?: Record<string, unknown>;
  created_at: string;
  last_login?: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  user: User;
}

export interface ScanSignal {
  indicator: string;
  severity: string;
  contribution: number;
  detail: string;
}

export interface ScanPrediction {
  id: string;
  prediction: "BENIGN" | "SUSPICIOUS" | "RANSOMWARE";
  risk_score: number;
  risk_level: "LOW" | "GUARDED" | "MODERATE" | "HIGH" | "CRITICAL";
  confidence: number;
  ml_used: boolean;
  model_name?: string | null;
  model_version?: string | null;
  explanation?: {
    summary?: string;
    ml_probability?: number | null;
    static_heuristic_score?: number;
    ml_notice?: string | null;
    schema_version?: string;
    signals?: ScanSignal[];
    top_model_features?: Array<{ feature: string; importance: number }>;
    pe_metadata?: {
      schema_version?: string;
      sections?: Array<{
        name: string;
        virtual_size: number;
        raw_size: number;
        entropy: number;
        executable: boolean;
        writable: boolean;
        wx: boolean;
      }>;
      imported_dlls?: string[];
      parse_warnings?: string[];
    };
  };
  created_at: string;
}

export interface ExtractedFeature {
  feature_name: string;
  feature_value: string;
  feature_type: string;
}

export interface ScanDetail {
  id: string;
  user_id: string;
  original_file_name: string;
  file_name: string;
  file_path?: string | null;
  file_size: number;
  file_type: string;
  sha256_hash: string;
  md5_hash: string;
  upload_timestamp: string;
  scan_status: string;
  scan_duration?: number | null;
  is_user_flagged: boolean;
  prediction?: ScanPrediction | null;
  features: ExtractedFeature[];
}

export interface DatasetItem {
  id: string;
  name: string;
  description?: string | null;
  dataset_type: string;
  sample_count: number;
  benign_count: number;
  ransomware_count: number;
  validation_status: string;
  metadata: {
    row_count?: number;
    column_count?: number;
    columns?: string[];
    label_column?: string;
    feature_columns?: string[];
    missing_values_total?: number;
    missing_by_column?: Record<string, number>;
    duplicate_rows?: number;
    file_size_bytes?: number;
    matches_pe_schema?: boolean;
    pe_schema_version?: string;
    preview?: Record<string, unknown>[];
  };
  created_at: string;
}

export interface AlgorithmItem {
  id: string;
  algorithm_name: string;
  model_version: string;
  description?: string | null;
}

export interface TrainedModelItem {
  id: string;
  dataset_id: string;
  dataset_name: string;
  algorithm_id: string;
  algorithm_name: string;
  training_status: string;
  training_date: string;
  model_version: string;
  accuracy?: number | null;
  precision?: number | null;
  recall?: number | null;
  f1_score?: number | null;
  roc_auc?: number | null;
  confusion_matrix?: { tn: number; fp: number; fn: number; tp: number; matrix: number[][] } | null;
  training_parameters?: Record<string, unknown>;
  evaluation_details?: {
    fpr?: number;
    fnr?: number;
    training_duration_sec?: number;
    prediction_duration_sec?: number;
    train_samples?: number;
    test_samples?: number;
    selected_features?: string[];
    top_features?: Array<{ feature: string; importance: number }>;
    roc_curve?: Array<{ x: number; y: number }>;
    pr_curve?: Array<{ x: number; y: number }>;
    cv_summary?: { folds: number; mean_f1: number; std_f1: number } | null;
    logs?: string[];
    error?: string;
  } | null;
  is_active: boolean;
  live_progress?: { progress: number; stage: string; logs: string[] } | null;
}

export interface ProcessItem {
  pid: number;
  ppid?: number | null;
  process_name: string;
  executable_path?: string | null;
  username?: string | null;
  cpu_percent: number;
  memory_percent: number;
  sha256_hash?: string | null;
  risk_score: number;
  risk_level: string;
  classification: string;
  reasons: string[];
  is_protected: boolean;
  timestamp: string;
}

export interface AlertItem {
  id: string;
  scan_id?: string | null;
  alert_type: string;
  severity: string;
  title: string;
  description: string;
  is_read: boolean;
  created_at: string;
}
