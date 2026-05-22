export const API_BASE = "";

// Typings for API responses
export interface HealthStatus {
  llm_enabled: boolean;
  tasks_count: number;
  server_time: string;
}

export interface AppConfig {
  llm_protocol: string;
  llm_model: string;
  llm_api_key: string;
  llm_api_url: string;
  llm_system_prompt: string;
}

export interface Task {
  task_id: string;
  hostname: string;
  status: "queued" | "analyzing" | "completed" | "failed";
  submitted_at: string;
}

export interface AnalysisResult {
  summary?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  };
  threats?: Threat[];
  attack_chain?: {
    attack_phases?: AttackPhase[];
  };
  attacker_profile?: {
    attacker_characteristics?: {
      primary_source_ip?: string;
      attack_frequency?: number;
      unique_sources?: number;
    };
    threat_assessment?: {
      overall_threat_level?: string;
      attack_sophistication?: string;
    };
  };
}

export interface Threat {
  severity?: string;
  title?: string;
  description?: string;
  recommendation?: string;
}

export interface AttackPhase {
  phase?: string;
  name?: string;
  description?: string;
  mitre_technique?: string;
}

export interface TaskProgress {
  task_id: string;
  status: string;
  hostname: string;
  progress?: { step: string; detail: string; percent: number };
  error?: string;
  analysis?: AnalysisResult;
  report_md?: string;
}

// Fetch Wrapper
async function fetchApi<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, options);
  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    throw new Error(errText || `HTTP error ${res.status}`);
  }
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("json")) {
    return res.json() as Promise<T>;
  }
  return res.text() as unknown as Promise<T>;
}

// API Methods
export async function getHealth(): Promise<HealthStatus> {
  return fetchApi<HealthStatus>("/api/v1/health");
}

export async function getTasks(): Promise<{ tasks: Task[] }> {
  return fetchApi<{ tasks: Task[] }>("/api/v1/tasks");
}

export async function getConfig(): Promise<AppConfig> {
  return fetchApi<AppConfig>("/web/api/config");
}

export async function saveConfig(config: Partial<AppConfig>): Promise<{ status: string; message: string }> {
  return fetchApi<{ status: string; message: string }>("/web/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
}

export async function testLLM(): Promise<{ success: boolean; reply?: string; error?: string }> {
  return fetchApi<{ success: boolean; reply?: string; error?: string }>("/web/api/test-llm", {
    method: "POST",
  });
}

export async function submitAnalysis(evidenceData: Record<string, unknown>): Promise<{ task_id: string; status: string }> {
  return fetchApi<{ task_id: string; status: string }>("/web/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(evidenceData),
  });
}

export async function getTaskProgress(taskId: string): Promise<TaskProgress> {
  return fetchApi<TaskProgress>(`/web/api/task/${taskId}`);
}
