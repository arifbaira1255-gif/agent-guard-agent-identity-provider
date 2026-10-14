/**
 * Public types for the AQL-1 TypeScript SDK.
 *
 * Every request and response shape is declared here — the SDK never exposes
 * `any`. All fields mirror the REST API exactly.
 */

/** A JSON-serialisable value. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/** A JSON object. */
export type JsonObject = { [key: string]: JsonValue };

/** Statuses after which a run will not change again on its own. */
export const TERMINAL_STATUSES = [
  'completed',
  'failed',
  'rejected',
  'cancelled',
  'pending_approval',
] as const;

export type TerminalStatus = (typeof TERMINAL_STATUSES)[number];

/** Any status a run can report. */
export type RunStatus =
  | 'running'
  | 'pending'
  | 'pending_approval'
  | 'completed'
  | 'failed'
  | 'rejected'
  | 'cancelled'
  | 'unknown';

/** Step progress for a run. */
export interface Progress {
  steps_completed: number;
  steps_total: number;
  percent: number;
}

/** The immediate answer to `POST /v1/agent/run`. */
export interface RunResponse {
  task_id: string;
  status: RunStatus;
  approval_id: string | null;
  result: JsonObject | null;
  status_url: string | null;
  api_key: ApiKeyIdentity | null;
}

/** The answer to `GET /v1/agent/status/{task_id}`. */
export interface TaskStatus {
  task_id: string;
  status: RunStatus;
  progress: Progress;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number;
  cost_usd: number;
  tokens: number;
  approval_id: string | null;
  error: string | null;
  result: JsonObject | null;
}

/** The identity attached to the calling API key. */
export interface ApiKeyIdentity {
  key_id: string;
  name: string;
  owner_id: string;
  scopes: string[];
}

/** Metadata for an API key. The raw key and its hash are never included. */
export interface APIKey {
  key_id: string;
  name: string;
  owner_id: string;
  scopes: string[];
  active: boolean;
  created_at: string | null;
  last_used_at: string | null;
  rate_limit_requests: number;
  rate_limit_window_seconds: number;
  prefix: string | null;
}

/** The one-time result of minting a key — `api_key` is shown only here. */
export interface APIKeyCreated {
  api_key: string;
  key: APIKey;
  warning: string;
}

/** Options for `runAgent`. */
export interface RunAgentOptions {
  /** Allow a high-risk action to pause for human approval (default `true`). */
  allowHumanApproval?: boolean;
  /** Run synchronously server-side and return the full result. */
  wait?: boolean;
  /** Action the agent will take, e.g. `"email.send"`. */
  actionType?: string;
  /** Payload for the action. */
  payload?: JsonObject;
  userId?: string;
  sessionId?: string;
  provider?: string;
}

/** Options for `waitForCompletion`. */
export interface WaitOptions {
  /** Seconds between polls (default 1). */
  pollInterval?: number;
  /** Overall timeout in seconds (default 300). */
  timeout?: number;
  /** Called after every poll with the latest status. */
  onProgress?: (status: TaskStatus) => void;
  /** Abort the wait. */
  signal?: AbortSignal;
}

/** Options for `createKey`. */
export interface CreateKeyOptions {
  ownerId?: string;
  scopes?: string[];
  rateLimitRequests?: number;
  rateLimitWindowSeconds?: number;
}

/** A raw HTTP response, transport-agnostic. */
export interface TransportResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** The request a transport must perform. */
export interface TransportRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
  timeout: number;
  signal?: AbortSignal;
}

/**
 * The transport contract. Implement this to plug in a custom HTTP client
 * (axios, undici, a proxy, a test double...).
 */
export interface Transport {
  request(req: TransportRequest): Promise<TransportResponse>;
}

/** Constructor options for the client. */
export interface AQL1Options {
  /** Required. Sent as `Authorization: Bearer <key>`. */
  apiKey: string;
  /** API root (default `http://localhost:8000`). */
  baseUrl?: string;
  /** Per-request timeout in seconds (default 30). */
  timeout?: number;
  /** Retries for 429/5xx/network errors (default 2 → 3 attempts total). */
  maxRetries?: number;
  /** Custom transport. Defaults to the global `fetch`. */
  transport?: Transport;
  /** Base for exponential backoff in seconds (default 0.5). */
  backoffFactor?: number;
  /** Backoff ceiling in seconds (default 30). */
  maxBackoff?: number;
  /** Extra headers merged into every request. */
  defaultHeaders?: Record<string, string>;
}
