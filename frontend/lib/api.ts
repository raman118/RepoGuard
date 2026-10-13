export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(
  token: string,
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(`/api/bridge${path}`, {
    method: body === undefined ? "GET" : "POST",
    signal,
    cache: "no-store",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new ApiError(
      response.status,
      typeof data.detail === "string"
        ? data.detail
        : "Request failed. Check access and input.",
    );
  }
  return data as T;
}

export type Repository = {
  id: string;
  owner: string;
  name: string;
  fixture_id: string | null;
};
export type Finding = {
  id: string;
  rule_id: string;
  severity: string;
  category: string;
  path: string;
  line: number;
  evidence: string;
  explanation: string;
  remediation: string;
};
export type Category = {
  weight: number;
  status: string;
  earned_points: number;
  available_points: number;
  rules_scanned: number;
  rules_total: number;
  deductions: { rule_id: string; points: number }[];
};
export type Scan = {
  id: string;
  sha: string;
  state: string;
  created_at: string;
  findings: Finding[];
  job: {
    attempts: number;
    state: string;
    error_code: string | null;
    cancel_requested: boolean;
  } | null;
  result: {
    score: {
      value: number;
      coverage_points: number;
      categories: Record<string, Category>;
      policy_version: string;
      digest: string;
      limitation: string;
    };
    coverage: Record<string, { status: string; reason: string }>;
    errors: { path: string; code: string }[];
  } | null;
};
