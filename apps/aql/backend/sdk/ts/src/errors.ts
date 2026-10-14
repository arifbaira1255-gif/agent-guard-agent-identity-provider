/**
 * Typed error hierarchy for the AQL-1 TypeScript SDK.
 *
 * Every non-2xx response becomes one of these — errors are never swallowed.
 */

import type { JsonValue } from './types.js';

/** Base class for every error raised by this SDK. */
export class AQL1Error extends Error {
  /** HTTP status, when the error came from a response. */
  readonly statusCode: number | null;
  /** Parsed response body, when available. */
  readonly body: JsonValue | null;
  /** Machine-readable error code from the API (e.g. `invalid_api_key`). */
  readonly code: string | null;

  constructor(
    message: string,
    options: { statusCode?: number | null; body?: JsonValue | null; code?: string | null } = {},
  ) {
    super(message);
    this.name = 'AQL1Error';
    this.statusCode = options.statusCode ?? null;
    this.body = options.body ?? null;
    this.code = options.code ?? null;
    // Restore the prototype chain when compiled down to ES5.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 401 — the API key is missing, invalid, or revoked. */
export class AuthenticationError extends AQL1Error {
  constructor(
    message: string,
    options: { statusCode?: number | null; body?: JsonValue | null; code?: string | null } = {},
  ) {
    super(message, options);
    this.name = 'AuthenticationError';
  }
}

/** 429 — the key's rate limit was exceeded. */
export class RateLimitError extends AQL1Error {
  /** Seconds to wait before retrying, from `Retry-After`. */
  readonly retryAfter: number | null;
  /** Value of `X-RateLimit-Limit`. */
  readonly limit: number | null;
  /** Value of `X-RateLimit-Remaining`. */
  readonly remaining: number | null;
  /** Value of `X-RateLimit-Reset`. */
  readonly reset: number | null;

  constructor(
    message: string,
    options: {
      retryAfter?: number | null;
      limit?: number | null;
      remaining?: number | null;
      reset?: number | null;
      statusCode?: number | null;
      body?: JsonValue | null;
      code?: string | null;
    } = {},
  ) {
    super(message, { ...options, statusCode: options.statusCode ?? 429 });
    this.name = 'RateLimitError';
    this.retryAfter = options.retryAfter ?? null;
    this.limit = options.limit ?? null;
    this.remaining = options.remaining ?? null;
    this.reset = options.reset ?? null;
  }
}

/** 404 — the requested resource does not exist. */
export class NotFoundError extends AQL1Error {
  constructor(
    message: string,
    options: { statusCode?: number | null; body?: JsonValue | null; code?: string | null } = {},
  ) {
    super(message, options);
    this.name = 'NotFoundError';
  }
}

/** 422 — the request body failed validation. */
export class ValidationError extends AQL1Error {
  constructor(
    message: string,
    options: { statusCode?: number | null; body?: JsonValue | null; code?: string | null } = {},
  ) {
    super(message, options);
    this.name = 'ValidationError';
  }
}

/** Any other non-2xx response. */
export class APIError extends AQL1Error {
  constructor(
    message: string,
    options: { statusCode?: number | null; body?: JsonValue | null; code?: string | null } = {},
  ) {
    super(message, options);
    this.name = 'APIError';
  }
}

/** The request never produced a response (DNS, refused, reset, TLS...). */
export class APIConnectionError extends AQL1Error {
  constructor(message: string, options: { body?: JsonValue | null } = {}) {
    super(message, options);
    this.name = 'APIConnectionError';
  }
}

/** The request exceeded the configured timeout. */
export class TimeoutError extends AQL1Error {
  constructor(message: string, options: { body?: JsonValue | null } = {}) {
    super(message, options);
    this.name = 'TimeoutError';
  }
}

/** A run paused for human approval but `allowHumanApproval` was false. */
export class ApprovalRequiredError extends AQL1Error {
  /** The approval id, so the caller can still approve it out of band. */
  readonly approvalId: string | null;

  constructor(
    message: string,
    options: { approvalId?: string | null; body?: JsonValue | null } = {},
  ) {
    super(message, { ...options, code: 'approval_required' });
    this.name = 'ApprovalRequiredError';
    this.approvalId = options.approvalId ?? null;
  }
}

/** A paused run was rejected by a human approver. */
export class ApprovalRejectedError extends AQL1Error {
  readonly approvalId: string | null;

  constructor(
    message: string,
    options: { approvalId?: string | null; body?: JsonValue | null } = {},
  ) {
    super(message, { ...options, code: 'approval_rejected' });
    this.name = 'ApprovalRejectedError';
    this.approvalId = options.approvalId ?? null;
  }
}
