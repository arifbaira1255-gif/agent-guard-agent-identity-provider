/**
 * AQL-1 TypeScript SDK — a lightweight, fully-typed client for the AQL-1 REST API.
 *
 * ```ts
 * import { AQL1 } from 'aql1';
 *
 * const client = new AQL1({ apiKey: 'sk-...' });
 * const response = await client.runAgent({ prompt: 'Hello!', allowHumanApproval: true });
 * console.log(response.task_id, response.status);
 * ```
 *
 * Design notes
 * ------------
 * - The default transport is the global `fetch`; pass a custom `Transport` to
 *   swap in axios, undici, a proxy, or a test double.
 * - Every non-2xx response becomes a typed error — nothing is swallowed.
 * - `429`/`5xx` responses and network failures are retried with exponential
 *   backoff plus jitter, honouring `Retry-After`.
 * - No `any` anywhere in the public surface.
 */

import {
  APIError,
  APIConnectionError,
  AQL1Error,
  ApprovalRejectedError,
  ApprovalRequiredError,
  AuthenticationError,
  NotFoundError,
  RateLimitError,
  TimeoutError,
  ValidationError,
} from './errors.js';
import {
  TERMINAL_STATUSES,
  type APIKey,
  type APIKeyCreated,
  type AQL1Options,
  type ApiKeyIdentity,
  type CreateKeyOptions,
  type JsonObject,
  type JsonValue,
  type Progress,
  type RunAgentOptions,
  type RunResponse,
  type RunStatus,
  type TaskStatus,
  type Transport,
  type TransportRequest,
  type TransportResponse,
  type WaitOptions,
} from './types.js';

export * from './types.js';
export * from './errors.js';

export const VERSION = '1.0.0';
export const DEFAULT_BASE_URL = 'http://localhost:8000';
const USER_AGENT = `aql1-ts/${VERSION}`;

/** HTTP statuses worth retrying. */
const RETRYABLE_STATUSES = new Set([408, 409, 425, 429, 500, 502, 503, 504]);

// ══════════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════════

/** Narrow an unknown value to a plain object. */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Parse a JSON body, returning `null` for an empty or malformed body. */
function parseJson(text: string): JsonValue | null {
  if (!text) return null;
  try {
    return JSON.parse(text) as JsonValue;
  } catch {
    return null;
  }
}

/** Lower-case every header key so lookups are case-insensitive. */
function lowerHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key.toLowerCase()] = value;
  }
  return out;
}

/** Read an integer header, or `null` when absent/unparseable. */
function headerInt(headers: Record<string, string>, name: string): number | null {
  const raw = headers[name.toLowerCase()];
  if (raw === undefined) return null;
  const parsed = Number.parseInt(raw, 10);
  return Number.isNaN(parsed) ? null : parsed;
}

/** Parse `Retry-After` (seconds or an HTTP date) into seconds. */
function parseRetryAfter(headers: Record<string, string>): number | null {
  const raw = headers['retry-after'];
  if (raw === undefined) return null;
  const seconds = Number.parseFloat(raw);
  if (!Number.isNaN(seconds)) return Math.max(0, seconds);
  const date = Date.parse(raw);
  if (!Number.isNaN(date)) return Math.max(0, (date - Date.now()) / 1000);
  return null;
}

/** Exponential backoff with full jitter, capped. */
function backoffDelay(attempt: number, factor: number, cap: number): number {
  const base = Math.min(cap, factor * 2 ** attempt);
  return base * (0.5 + Math.random() / 2);
}

/** Sleep, rejecting early if the signal aborts. */
function sleep(seconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new APIConnectionError('Request aborted'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, seconds * 1000);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new APIConnectionError('Request aborted'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** Map a non-2xx response onto the right typed error. */
function errorFromResponse(response: TransportResponse): AQL1Error {
  const body = parseJson(response.body);
  const obj = isObject(body) ? body : null;
  const rawDetail = obj ? obj['detail'] ?? obj['error'] ?? obj['message'] : null;
  const detail =
    typeof rawDetail === 'string' && rawDetail.length > 0
      ? rawDetail
      : response.body.slice(0, 500) || `HTTP ${response.status}`;
  const code = obj && typeof obj['code'] === 'string' ? obj['code'] : null;
  const headers = lowerHeaders(response.headers);
  const options = { statusCode: response.status, body, code };

  switch (response.status) {
    case 401:
      return new AuthenticationError(detail, options);
    case 404:
      return new NotFoundError(detail, options);
    case 422:
      return new ValidationError(detail, options);
    case 429:
      return new RateLimitError(detail, {
        ...options,
        retryAfter: parseRetryAfter(headers),
        limit: headerInt(headers, 'x-ratelimit-limit'),
        remaining: headerInt(headers, 'x-ratelimit-remaining'),
        reset: headerInt(headers, 'x-ratelimit-reset'),
      });
    default:
      return new APIError(detail, options);
  }
}

/** True when an error is worth retrying. */
function isRetryableError(error: unknown): boolean {
  return error instanceof APIConnectionError || error instanceof TimeoutError;
}

// ── response parsing ─────────────────────────────────────────────────────────
function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function asNullableString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function asObject(value: unknown): JsonObject | null {
  return isObject(value) ? (value as JsonObject) : null;
}

function parseProgress(value: unknown): Progress {
  const obj = isObject(value) ? value : {};
  return {
    steps_completed: asNumber(obj['steps_completed']),
    steps_total: asNumber(obj['steps_total']),
    percent: asNumber(obj['percent']),
  };
}

function parseIdentity(value: unknown): ApiKeyIdentity | null {
  if (!isObject(value)) return null;
  return {
    key_id: asString(value['key_id']),
    name: asString(value['name']),
    owner_id: asString(value['owner_id'], 'anonymous'),
    scopes: Array.isArray(value['scopes']) ? value['scopes'].map((s) => asString(s)) : [],
  };
}

function parseRunResponse(data: JsonValue | null): RunResponse {
  const obj = isObject(data) ? data : {};
  return {
    task_id: asString(obj['task_id']),
    status: asString(obj['status'], 'unknown') as RunStatus,
    approval_id: asNullableString(obj['approval_id']),
    result: asObject(obj['result']),
    status_url: asNullableString(obj['status_url']),
    api_key: parseIdentity(obj['api_key']),
  };
}

function parseTaskStatus(data: JsonValue | null): TaskStatus {
  const obj = isObject(data) ? data : {};
  return {
    task_id: asString(obj['task_id']),
    status: asString(obj['status'], 'unknown') as RunStatus,
    progress: parseProgress(obj['progress']),
    created_at: asNullableString(obj['created_at']),
    started_at: asNullableString(obj['started_at']),
    finished_at: asNullableString(obj['finished_at']),
    duration_ms: asNumber(obj['duration_ms']),
    cost_usd: asNumber(obj['cost_usd']),
    tokens: asNumber(obj['tokens']),
    approval_id: asNullableString(obj['approval_id']),
    error: asNullableString(obj['error']),
    result: asObject(obj['result']),
  };
}

function parseApiKey(value: unknown): APIKey {
  const obj = isObject(value) ? value : {};
  return {
    key_id: asString(obj['key_id']),
    name: asString(obj['name']),
    owner_id: asString(obj['owner_id'], 'anonymous'),
    scopes: Array.isArray(obj['scopes']) ? obj['scopes'].map((s) => asString(s)) : [],
    active: obj['active'] !== false,
    created_at: asNullableString(obj['created_at']),
    last_used_at: asNullableString(obj['last_used_at']),
    rate_limit_requests: asNumber(obj['rate_limit_requests']),
    rate_limit_window_seconds: asNumber(obj['rate_limit_window_seconds']),
    prefix: asNullableString(obj['prefix']),
  };
}

/** True when a status will not change again on its own. */
export function isTerminalStatus(status: string): boolean {
  return (TERMINAL_STATUSES as readonly string[]).includes(status);
}

// ══════════════════════════════════════════════════════════════════════════════
// Default transport
// ══════════════════════════════════════════════════════════════════════════════

/**
 * The default transport, backed by the global `fetch`.
 *
 * Applies the per-request timeout with an `AbortController` and normalises
 * network failures into `APIConnectionError` / `TimeoutError`.
 */
export class FetchTransport implements Transport {
  async request(req: TransportRequest): Promise<TransportResponse> {
    const controller = new AbortController();
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, req.timeout * 1000);

    if (req.signal) {
      if (req.signal.aborted) controller.abort();
      else req.signal.addEventListener('abort', () => controller.abort(), { once: true });
    }

    try {
      const response = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body ?? undefined,
        signal: controller.signal,
      });

      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });

      return { status: response.status, headers, body: await response.text() };
    } catch (error) {
      if (timedOut) {
        throw new TimeoutError(`Request to ${req.url} timed out after ${req.timeout}s`);
      }
      if (req.signal?.aborted) {
        throw new APIConnectionError('Request aborted');
      }
      const reason = error instanceof Error ? error.message : String(error);
      throw new APIConnectionError(`Request to ${req.url} failed: ${reason}`);
    } finally {
      clearTimeout(timer);
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Client
// ══════════════════════════════════════════════════════════════════════════════

/**
 * The AQL-1 API client.
 *
 * ```ts
 * const client = new AQL1({ apiKey: 'sk-...', baseUrl: 'https://api.example.com' });
 * ```
 */
export class AQL1 {
  readonly baseUrl: string;
  readonly timeout: number;
  readonly maxRetries: number;

  private readonly apiKey: string;
  private readonly transport: Transport;
  private readonly backoffFactor: number;
  private readonly maxBackoff: number;
  private readonly defaultHeaders: Record<string, string>;

  constructor(options: AQL1Options) {
    if (!options.apiKey) {
      throw new Error('apiKey is required');
    }
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.timeout = options.timeout ?? 30;
    this.maxRetries = Math.max(0, options.maxRetries ?? 2);
    this.transport = options.transport ?? new FetchTransport();
    this.backoffFactor = options.backoffFactor ?? 0.5;
    this.maxBackoff = options.maxBackoff ?? 30;
    this.defaultHeaders = options.defaultHeaders ?? {};
  }

  /** Never leak the key through `console.log` / template strings. */
  toString(): string {
    return `AQL1(baseUrl=${this.baseUrl}, apiKey=***)`;
  }

  // ── internals ────────────────────────────────────────────────────────────
  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'User-Agent': USER_AGENT,
      ...this.defaultHeaders,
    };
  }

  /** Perform a request with retries, returning the parsed JSON body. */
  private async request(
    method: string,
    path: string,
    options: { body?: JsonValue; signal?: AbortSignal } = {},
  ): Promise<JsonValue | null> {
    const url = `${this.baseUrl}${path}`;
    const payload = options.body === undefined ? null : JSON.stringify(options.body);

    let attempt = 0;
    for (;;) {
      let response: TransportResponse;
      try {
        response = await this.transport.request({
          method,
          url,
          headers: this.headers(),
          body: payload,
          timeout: this.timeout,
          signal: options.signal,
        });
      } catch (error) {
        if (error instanceof AQL1Error) {
          if (isRetryableError(error) && attempt < this.maxRetries) {
            const delay = backoffDelay(attempt, this.backoffFactor, this.maxBackoff);
            await sleep(delay, options.signal);
            attempt += 1;
            continue;
          }
          throw error;
        }
        if (attempt < this.maxRetries) {
          const delay = backoffDelay(attempt, this.backoffFactor, this.maxBackoff);
          await sleep(delay, options.signal);
          attempt += 1;
          continue;
        }
        const reason = error instanceof Error ? error.message : String(error);
        throw new APIConnectionError(`Request to ${url} failed: ${reason}`);
      }

      if (response.status >= 400) {
        if (RETRYABLE_STATUSES.has(response.status) && attempt < this.maxRetries) {
          const headers = lowerHeaders(response.headers);
          const retryAfter = parseRetryAfter(headers);
          const delay =
            retryAfter ?? backoffDelay(attempt, this.backoffFactor, this.maxBackoff);
          await sleep(delay, options.signal);
          attempt += 1;
          continue;
        }
        throw errorFromResponse(response);
      }

      return parseJson(response.body);
    }
  }

  // ── agent runs ───────────────────────────────────────────────────────────
  /**
   * Start an autonomous agent run.
   *
   * Async by default — resolves with a task handle carrying the `task_id`.
   * Pass `wait: true` to run synchronously server-side, or
   * `waitForCompletion: true` to poll client-side until the run settles.
   *
   * A high-risk action pauses the run: the response carries
   * `status: 'pending_approval'` and an `approval_id`. With
   * `allowHumanApproval: false`, `ApprovalRequiredError` is thrown instead.
   */
  async runAgent(
    options: RunAgentOptions & {
      prompt: string;
      waitForCompletion?: boolean;
      pollInterval?: number;
      timeout?: number;
      onProgress?: (status: TaskStatus) => void;
      signal?: AbortSignal;
    },
  ): Promise<RunResponse> {
    const body: JsonObject = {
      task: options.prompt,
      wait: options.wait ?? false,
      user_id: options.userId ?? 'anonymous',
      session_id: options.sessionId ?? 'default',
      payload: options.payload ?? {},
    };
    if (options.actionType !== undefined) body['action_type'] = options.actionType;
    if (options.provider !== undefined) body['provider'] = options.provider;

    const data = await this.request('POST', '/v1/agent/run', {
      body,
      signal: options.signal,
    });
    const response = parseRunResponse(data);

    if (response.status === 'pending_approval' && options.allowHumanApproval === false) {
      throw new ApprovalRequiredError(
        'The action was classified as high-risk and requires human approval, but ' +
          'allowHumanApproval=false. Approve it via approve(approvalId) or re-run with ' +
          'allowHumanApproval=true.',
        { approvalId: response.approval_id, body: data },
      );
    }

    if (options.waitForCompletion && !isTerminalStatus(response.status)) {
      const status = await this.waitForCompletion(response.task_id, {
        pollInterval: options.pollInterval,
        timeout: options.timeout,
        onProgress: options.onProgress,
        signal: options.signal,
      });
      return {
        task_id: status.task_id,
        status: status.status,
        approval_id: status.approval_id,
        result: status.result,
        status_url: response.status_url,
        api_key: response.api_key,
      };
    }

    return response;
  }

  /** Fetch the current status of a run. Throws `NotFoundError` for an unknown id. */
  async getStatus(taskId: string, options: { signal?: AbortSignal } = {}): Promise<TaskStatus> {
    const data = await this.request(
      'GET',
      `/v1/agent/status/${encodeURIComponent(taskId)}`,
      { signal: options.signal },
    );
    return parseTaskStatus(data);
  }

  /**
   * Poll until the run reaches a terminal status.
   *
   * `pending_approval` counts as terminal — the run is paused on a human, so
   * polling further would spin forever. Throws `TimeoutError` on timeout.
   */
  async waitForCompletion(taskId: string, options: WaitOptions = {}): Promise<TaskStatus> {
    const pollInterval = options.pollInterval ?? 1;
    const timeout = options.timeout ?? 300;
    const deadline = Date.now() + timeout * 1000;

    for (;;) {
      const status = await this.getStatus(taskId, { signal: options.signal });
      options.onProgress?.(status);
      if (isTerminalStatus(status.status)) return status;
      if (Date.now() >= deadline) {
        throw new TimeoutError(
          `Run ${taskId} did not finish within ${timeout}s (last status: ${status.status})`,
        );
      }
      await sleep(Math.max(0, pollInterval), options.signal);
    }
  }

  /**
   * Async-iterate status updates until the run reaches a terminal state.
   *
   * ```ts
   * for await (const status of client.streamProgress(taskId)) {
   *   console.log(status.status, status.progress.percent);
   * }
   * ```
   */
  async *streamProgress(
    taskId: string,
    options: WaitOptions = {},
  ): AsyncGenerator<TaskStatus, void, unknown> {
    const pollInterval = options.pollInterval ?? 1;
    const timeout = options.timeout ?? 300;
    const deadline = Date.now() + timeout * 1000;

    for (;;) {
      const status = await this.getStatus(taskId, { signal: options.signal });
      yield status;
      if (isTerminalStatus(status.status)) return;
      if (Date.now() >= deadline) {
        throw new TimeoutError(
          `Run ${taskId} did not finish within ${timeout}s (last status: ${status.status})`,
        );
      }
      await sleep(Math.max(0, pollInterval), options.signal);
    }
  }

  /** Approve or reject a paused run, resuming it when approved. */
  async approve(
    approvalId: string,
    options: {
      decision?: 'approve' | 'reject';
      approver?: string;
      note?: string;
      signal?: AbortSignal;
    } = {},
  ): Promise<JsonObject> {
    const decision = options.decision ?? 'approve';
    if (decision !== 'approve' && decision !== 'reject') {
      throw new Error("decision must be 'approve' or 'reject'");
    }
    const body: JsonObject = {
      approval_id: approvalId,
      decision,
      note: options.note ?? '',
    };
    if (options.approver !== undefined) body['approver'] = options.approver;
    const data = await this.request('POST', '/agent/approve', {
      body,
      signal: options.signal,
    });
    return asObject(data) ?? {};
  }

  /** Poll `GET /agent/approvals/{id}` until a human decides. */
  async waitForApproval(
    approvalId: string,
    options: { pollInterval?: number; timeout?: number; signal?: AbortSignal } = {},
  ): Promise<JsonObject> {
    const pollInterval = options.pollInterval ?? 2;
    const timeout = options.timeout ?? 600;
    const deadline = Date.now() + timeout * 1000;

    for (;;) {
      const data = await this.request(
        'GET',
        `/agent/approvals/${encodeURIComponent(approvalId)}`,
        { signal: options.signal },
      );
      const record = asObject(data);
      if (record && record['status'] !== 'pending') return record;
      if (Date.now() >= deadline) {
        throw new TimeoutError(`Approval ${approvalId} was not decided within ${timeout}s`);
      }
      await sleep(Math.max(0, pollInterval), options.signal);
    }
  }

  /**
   * Wait for a human decision, then return the resumed run's record.
   * Throws `ApprovalRejectedError` when the decision was a rejection.
   */
  async resumeAfterApproval(
    approvalId: string,
    options: { pollInterval?: number; timeout?: number; signal?: AbortSignal } = {},
  ): Promise<JsonObject> {
    const record = await this.waitForApproval(approvalId, options);
    if (record['status'] === 'rejected') {
      throw new ApprovalRejectedError(`Approval ${approvalId} was rejected`, {
        approvalId,
        body: record,
      });
    }
    return record;
  }

  // ── key management ───────────────────────────────────────────────────────
  /** Mint a new API key. The raw key is returned **once**. */
  async createKey(
    name: string,
    options: CreateKeyOptions & { signal?: AbortSignal } = {},
  ): Promise<APIKeyCreated> {
    const body: JsonObject = {
      name,
      owner_id: options.ownerId ?? 'anonymous',
      scopes: options.scopes ?? [],
    };
    if (options.rateLimitRequests !== undefined) {
      body['rate_limit_requests'] = options.rateLimitRequests;
    }
    if (options.rateLimitWindowSeconds !== undefined) {
      body['rate_limit_window_seconds'] = options.rateLimitWindowSeconds;
    }
    const data = await this.request('POST', '/v1/keys', { body, signal: options.signal });
    const obj = isObject(data) ? data : {};
    return {
      api_key: asString(obj['api_key']),
      key: parseApiKey(obj['key']),
      warning: asString(obj['warning']),
    };
  }

  /** List API key metadata (never the raw key or its hash). */
  async listKeys(options: { signal?: AbortSignal } = {}): Promise<APIKey[]> {
    const data = await this.request('GET', '/v1/keys', { signal: options.signal });
    const obj = isObject(data) ? data : {};
    const keys = Array.isArray(obj['keys']) ? obj['keys'] : [];
    return keys.map((key) => parseApiKey(key));
  }

  /** Revoke (deactivate) a key by its `key_id`. */
  async revokeKey(keyId: string, options: { signal?: AbortSignal } = {}): Promise<APIKey> {
    const data = await this.request('DELETE', `/v1/keys/${encodeURIComponent(keyId)}`, {
      signal: options.signal,
    });
    const obj = isObject(data) ? data : {};
    return parseApiKey(obj['key']);
  }
}

export default AQL1;
