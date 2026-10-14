/**
 * Unit tests for the AQL-1 TypeScript SDK.
 *
 * Every test injects a `MockTransport`, so nothing here touches the network.
 * Covered: successful run, async run + polling, the pending-approval path,
 * 401/404/422/429/5xx mapping, retry with `Retry-After`, timeout, key
 * management, and the async progress iterator.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  AQL1,
  APIError,
  APIConnectionError,
  ApprovalRejectedError,
  ApprovalRequiredError,
  AuthenticationError,
  NotFoundError,
  RateLimitError,
  TimeoutError,
  ValidationError,
  isTerminalStatus,
  type Transport,
  type TransportRequest,
  type TransportResponse,
} from '../src/index.js';

// ══════════════════════════════════════════════════════════════════════════════
// Test doubles
// ══════════════════════════════════════════════════════════════════════════════

/** A scripted transport: shifts one queued response per request. */
class MockTransport implements Transport {
  readonly calls: TransportRequest[] = [];
  private readonly queue: Array<TransportResponse | Error>;

  constructor(responses: Array<TransportResponse | Error> = []) {
    this.queue = [...responses];
  }

  queueResponse(...responses: Array<TransportResponse | Error>): this {
    this.queue.push(...responses);
    return this;
  }

  async request(req: TransportRequest): Promise<TransportResponse> {
    this.calls.push(req);
    const item = this.queue.shift();
    if (item === undefined) {
      throw new Error(`MockTransport ran out of responses for ${req.method} ${req.url}`);
    }
    if (item instanceof Error) throw item;
    return item;
  }
}

/** Build a transport response with a JSON body. */
function resp(
  status: number,
  body: unknown = null,
  headers: Record<string, string> = {},
): TransportResponse {
  return {
    status,
    headers,
    body: body === null ? '' : JSON.stringify(body),
  };
}

/** A client wired to a mock transport, with retries off by default. */
function makeClient(
  transport: MockTransport,
  overrides: Partial<ConstructorParameters<typeof AQL1>[0]> = {},
): AQL1 {
  return new AQL1({
    apiKey: 'sk-test',
    baseUrl: 'http://api.test',
    maxRetries: 0,
    backoffFactor: 0,
    transport,
    ...overrides,
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// Constructor / config
// ══════════════════════════════════════════════════════════════════════════════
describe('constructor', () => {
  it('requires an api key', () => {
    assert.throws(() => new AQL1({ apiKey: '' }), /apiKey is required/);
  });

  it('applies defaults', () => {
    const client = new AQL1({ apiKey: 'sk-test' });
    assert.equal(client.baseUrl, 'http://localhost:8000');
    assert.equal(client.timeout, 30);
    assert.equal(client.maxRetries, 2);
  });

  it('normalises a trailing slash on baseUrl', () => {
    const client = new AQL1({ apiKey: 'sk-test', baseUrl: 'http://api.test/' });
    assert.equal(client.baseUrl, 'http://api.test');
  });

  it('never leaks the key through toString', () => {
    const client = new AQL1({ apiKey: 'sk-super-secret' });
    assert.ok(!client.toString().includes('sk-super-secret'));
    assert.ok(client.toString().includes('***'));
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Successful run
// ══════════════════════════════════════════════════════════════════════════════
describe('runAgent', () => {
  it('returns a task handle for an async run', async () => {
    const transport = new MockTransport([
      resp(200, { task_id: 't-1', status: 'running', status_url: '/v1/agent/status/t-1' }),
    ]);
    const client = makeClient(transport);

    const result = await client.runAgent({ prompt: 'Do the thing' });

    assert.equal(result.task_id, 't-1');
    assert.equal(result.status, 'running');
    const call = transport.calls[0];
    assert.equal(call.method, 'POST');
    assert.equal(call.url, 'http://api.test/v1/agent/run');
    assert.equal(call.headers['Authorization'], 'Bearer sk-test');
    const body = JSON.parse(call.body ?? '{}') as Record<string, unknown>;
    assert.equal(body['task'], 'Do the thing');
    assert.equal(body['wait'], false);
  });

  it('returns the full result in sync mode', async () => {
    const transport = new MockTransport([
      resp(200, {
        task_id: 't-2',
        status: 'completed',
        result: { answer: '42' },
      }),
    ]);
    const client = makeClient(transport);

    const result = await client.runAgent({ prompt: 'Answer', wait: true });

    assert.equal(result.status, 'completed');
    assert.equal(result.result?.['answer'], '42');
    const body = JSON.parse(transport.calls[0].body ?? '{}') as Record<string, unknown>;
    assert.equal(body['wait'], true);
  });

  it('forwards optional fields', async () => {
    const transport = new MockTransport([resp(200, { task_id: 't-3', status: 'running' })]);
    const client = makeClient(transport);

    await client.runAgent({
      prompt: 'Pay the invoice',
      actionType: 'payment.transfer',
      payload: { amount: 100 },
      userId: 'u-9',
      sessionId: 's-9',
      provider: 'unorouter',
    });

    const body = JSON.parse(transport.calls[0].body ?? '{}') as Record<string, unknown>;
    assert.equal(body['action_type'], 'payment.transfer');
    assert.deepEqual(body['payload'], { amount: 100 });
    assert.equal(body['user_id'], 'u-9');
    assert.equal(body['session_id'], 's-9');
    assert.equal(body['provider'], 'unorouter');
  });

  it('polls to completion when waitForCompletion is set', async () => {
    const transport = new MockTransport([
      resp(200, { task_id: 't-4', status: 'running' }),
      resp(200, { task_id: 't-4', status: 'running', progress: { percent: 50 } }),
      resp(200, { task_id: 't-4', status: 'completed', result: { answer: 'done' } }),
    ]);
    const client = makeClient(transport);

    const result = await client.runAgent({
      prompt: 'Async',
      waitForCompletion: true,
      pollInterval: 0,
      timeout: 5,
    });

    assert.equal(result.status, 'completed');
    assert.equal(result.result?.['answer'], 'done');
    assert.equal(transport.calls.length, 3);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Polling
// ══════════════════════════════════════════════════════════════════════════════
describe('waitForCompletion', () => {
  it('polls until terminal and reports progress', async () => {
    const transport = new MockTransport([
      resp(200, { task_id: 't-5', status: 'running', progress: { percent: 25 } }),
      resp(200, {
        task_id: 't-5',
        status: 'completed',
        progress: { steps_completed: 2, steps_total: 2, percent: 100 },
        cost_usd: 0.0042,
        tokens: 1234,
        result: { answer: 'done' },
      }),
    ]);
    const client = makeClient(transport);
    const seen: string[] = [];

    const status = await client.waitForCompletion('t-5', {
      pollInterval: 0,
      timeout: 5,
      onProgress: (s) => seen.push(s.status),
    });

    assert.equal(status.status, 'completed');
    assert.equal(status.progress.percent, 100);
    assert.equal(status.cost_usd, 0.0042);
    assert.equal(status.tokens, 1234);
    assert.deepEqual(seen, ['running', 'completed']);
  });

  it('parses every status field', async () => {
    const transport = new MockTransport([
      resp(200, {
        task_id: 't-6',
        status: 'completed',
        progress: { steps_completed: 3, steps_total: 3, percent: 100 },
        created_at: '2026-10-01T00:00:00Z',
        started_at: '2026-10-01T00:00:01Z',
        finished_at: '2026-10-01T00:00:09Z',
        duration_ms: 8000,
        cost_usd: 0.01,
        tokens: 500,
        approval_id: null,
        error: null,
        result: { answer: 'ok' },
      }),
    ]);
    const client = makeClient(transport);

    const status = await client.getStatus('t-6');

    assert.equal(status.duration_ms, 8000);
    assert.equal(status.progress.steps_completed, 3);
    assert.equal(status.created_at, '2026-10-01T00:00:00Z');
    assert.equal(transport.calls[0].url, 'http://api.test/v1/agent/status/t-6');
  });

  it('throws TimeoutError when the deadline passes', async () => {
    const transport = new MockTransport(
      Array.from({ length: 50 }, () => resp(200, { task_id: 't-7', status: 'running' })),
    );
    const client = makeClient(transport);

    await assert.rejects(
      () => client.waitForCompletion('t-7', { pollInterval: 0, timeout: 0 }),
      TimeoutError,
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Pending approval
// ══════════════════════════════════════════════════════════════════════════════
describe('pending approval', () => {
  it('surfaces the approval id when allowed', async () => {
    const transport = new MockTransport([
      resp(200, { task_id: 't-8', status: 'pending_approval', approval_id: 'ap-1' }),
    ]);
    const client = makeClient(transport);

    const result = await client.runAgent({ prompt: 'Email the client' });

    assert.equal(result.status, 'pending_approval');
    assert.equal(result.approval_id, 'ap-1');
    assert.ok(isTerminalStatus(result.status));
  });

  it('throws ApprovalRequiredError when disallowed', async () => {
    const transport = new MockTransport([
      resp(200, { task_id: 't-9', status: 'pending_approval', approval_id: 'ap-2' }),
    ]);
    const client = makeClient(transport);

    await assert.rejects(
      () => client.runAgent({ prompt: 'Delete the table', allowHumanApproval: false }),
      (error: unknown) => {
        assert.ok(error instanceof ApprovalRequiredError);
        assert.equal(error.approvalId, 'ap-2');
        return true;
      },
    );
  });

  it('stops polling on pending_approval', async () => {
    const transport = new MockTransport([
      resp(200, { task_id: 't-10', status: 'pending_approval', approval_id: 'ap-3' }),
    ]);
    const client = makeClient(transport);

    const status = await client.waitForCompletion('t-10', { pollInterval: 0, timeout: 5 });

    assert.equal(status.status, 'pending_approval');
    assert.equal(status.approval_id, 'ap-3');
    assert.equal(transport.calls.length, 1);
  });

  it('posts the approval decision', async () => {
    const transport = new MockTransport([
      resp(200, { status: 'approved', result: { answer: 'sent' } }),
    ]);
    const client = makeClient(transport);

    const result = await client.approve('ap-4', {
      decision: 'approve',
      approver: 'arif',
      note: 'looks fine',
    });

    assert.equal(result['status'], 'approved');
    const body = JSON.parse(transport.calls[0].body ?? '{}') as Record<string, unknown>;
    assert.deepEqual(body, {
      approval_id: 'ap-4',
      decision: 'approve',
      note: 'looks fine',
      approver: 'arif',
    });
  });

  it('rejects an invalid decision', async () => {
    const client = makeClient(new MockTransport());
    await assert.rejects(
      // @ts-expect-error - deliberately invalid at the type level
      () => client.approve('ap-5', { decision: 'maybe' }),
      /decision must be/,
    );
  });

  it('raises ApprovalRejectedError on rejection', async () => {
    const transport = new MockTransport([
      resp(200, { approval_id: 'ap-6', status: 'rejected' }),
    ]);
    const client = makeClient(transport);

    await assert.rejects(
      () => client.resumeAfterApproval('ap-6', { pollInterval: 0, timeout: 5 }),
      (error: unknown) => {
        assert.ok(error instanceof ApprovalRejectedError);
        assert.equal(error.approvalId, 'ap-6');
        return true;
      },
    );
  });

  it('returns the record when approved', async () => {
    const transport = new MockTransport([
      resp(200, { approval_id: 'ap-7', status: 'approved', result: { answer: 'ok' } }),
    ]);
    const client = makeClient(transport);

    const record = await client.resumeAfterApproval('ap-7', { pollInterval: 0, timeout: 5 });

    assert.equal(record['status'], 'approved');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Error mapping
// ══════════════════════════════════════════════════════════════════════════════
describe('error mapping', () => {
  it('maps 401 to AuthenticationError', async () => {
    const transport = new MockTransport([
      resp(401, { error: 'unauthorized', code: 'invalid_api_key', detail: 'bad key' }),
    ]);
    const client = makeClient(transport);

    await assert.rejects(
      () => client.getStatus('t-1'),
      (error: unknown) => {
        assert.ok(error instanceof AuthenticationError);
        assert.equal(error.statusCode, 401);
        assert.equal(error.code, 'invalid_api_key');
        assert.match(error.message, /bad key/);
        return true;
      },
    );
  });

  it('maps 404 to NotFoundError', async () => {
    const transport = new MockTransport([resp(404, { detail: 'Unknown task id: nope' })]);
    const client = makeClient(transport);

    await assert.rejects(
      () => client.getStatus('nope'),
      (error: unknown) => {
        assert.ok(error instanceof NotFoundError);
        assert.equal(error.statusCode, 404);
        return true;
      },
    );
  });

  it('maps 422 to ValidationError', async () => {
    const transport = new MockTransport([resp(422, { detail: 'task is required' })]);
    const client = makeClient(transport);

    await assert.rejects(() => client.runAgent({ prompt: '' }), ValidationError);
  });

  it('maps 500 to APIError', async () => {
    const transport = new MockTransport([resp(500, { detail: 'boom' })]);
    const client = makeClient(transport);

    await assert.rejects(
      () => client.getStatus('t-1'),
      (error: unknown) => {
        assert.ok(error instanceof APIError);
        assert.equal(error.statusCode, 500);
        assert.match(error.message, /boom/);
        return true;
      },
    );
  });

  it('handles a non-JSON error body', async () => {
    const transport = new MockTransport([
      { status: 502, headers: {}, body: '<html>bad gateway</html>' },
    ]);
    const client = makeClient(transport);

    await assert.rejects(
      () => client.getStatus('t-1'),
      (error: unknown) => {
        assert.ok(error instanceof APIError);
        assert.match(error.message, /bad gateway/);
        return true;
      },
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Rate limiting & retries
// ══════════════════════════════════════════════════════════════════════════════
describe('rate limiting and retries', () => {
  it('maps 429 to RateLimitError with headers', async () => {
    const transport = new MockTransport([
      resp(
        429,
        { error: 'rate_limited', code: 'rate_limit_exceeded', detail: 'slow down' },
        {
          'Retry-After': '60',
          'X-RateLimit-Limit': '60',
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': '1730000000',
        },
      ),
    ]);
    const client = makeClient(transport);

    await assert.rejects(
      () => client.getStatus('t-1'),
      (error: unknown) => {
        assert.ok(error instanceof RateLimitError);
        assert.equal(error.statusCode, 429);
        assert.equal(error.retryAfter, 60);
        assert.equal(error.limit, 60);
        assert.equal(error.remaining, 0);
        assert.equal(error.reset, 1730000000);
        return true;
      },
    );
  });

  it('retries a 429 then succeeds', async () => {
    const transport = new MockTransport([
      resp(429, { detail: 'slow down' }, { 'Retry-After': '0' }),
      resp(200, { task_id: 't-1', status: 'completed' }),
    ]);
    const client = makeClient(transport, { maxRetries: 1 });

    const status = await client.getStatus('t-1');

    assert.equal(status.status, 'completed');
    assert.equal(transport.calls.length, 2);
  });

  it('retries a 5xx then succeeds', async () => {
    const transport = new MockTransport([
      resp(503, { detail: 'unavailable' }),
      resp(200, { task_id: 't-1', status: 'completed' }),
    ]);
    const client = makeClient(transport, { maxRetries: 1 });

    const status = await client.getStatus('t-1');

    assert.equal(status.status, 'completed');
    assert.equal(transport.calls.length, 2);
  });

  it('exhausts retries then raises', async () => {
    const transport = new MockTransport(
      Array.from({ length: 5 }, () => resp(503, { detail: 'down' })),
    );
    const client = makeClient(transport, { maxRetries: 2 });

    await assert.rejects(() => client.getStatus('t-1'), APIError);
    assert.equal(transport.calls.length, 3);
  });

  it('retries a network error then raises APIConnectionError', async () => {
    const transport = new MockTransport(
      Array.from({ length: 5 }, () => new APIConnectionError('connection refused')),
    );
    const client = makeClient(transport, { maxRetries: 1 });

    await assert.rejects(() => client.getStatus('t-1'), APIConnectionError);
    assert.equal(transport.calls.length, 2);
  });

  it('recovers when a network error clears', async () => {
    const transport = new MockTransport([
      new APIConnectionError('flaky'),
      resp(200, { task_id: 't-1', status: 'completed' }),
    ]);
    const client = makeClient(transport, { maxRetries: 1 });

    const status = await client.getStatus('t-1');

    assert.equal(status.status, 'completed');
  });

  it('does not retry a 401', async () => {
    const transport = new MockTransport(
      Array.from({ length: 3 }, () => resp(401, { detail: 'nope' })),
    );
    const client = makeClient(transport, { maxRetries: 2 });

    await assert.rejects(() => client.getStatus('t-1'), AuthenticationError);
    assert.equal(transport.calls.length, 1);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Key management
// ══════════════════════════════════════════════════════════════════════════════
describe('key management', () => {
  it('creates a key and returns the raw value once', async () => {
    const transport = new MockTransport([
      resp(200, {
        api_key: 'sk-new-raw',
        key: {
          key_id: 'k-1',
          name: 'ci',
          owner_id: 'u-1',
          scopes: ['agent:run'],
          active: true,
          rate_limit_requests: 60,
          rate_limit_window_seconds: 60,
        },
        warning: 'Store this key now.',
      }),
    ]);
    const client = makeClient(transport);

    const created = await client.createKey('ci', { ownerId: 'u-1', scopes: ['agent:run'] });

    assert.equal(created.api_key, 'sk-new-raw');
    assert.equal(created.key.key_id, 'k-1');
    assert.deepEqual(created.key.scopes, ['agent:run']);
    assert.match(created.warning, /Store this key/);
  });

  it('lists key metadata', async () => {
    const transport = new MockTransport([
      resp(200, {
        keys: [
          { key_id: 'k-1', name: 'ci', active: true },
          { key_id: 'k-2', name: 'old', active: false },
        ],
      }),
    ]);
    const client = makeClient(transport);

    const keys = await client.listKeys();

    assert.deepEqual(
      keys.map((k) => k.key_id),
      ['k-1', 'k-2'],
    );
    assert.equal(keys[1].active, false);
  });

  it('revokes a key', async () => {
    const transport = new MockTransport([
      resp(200, { revoked: true, key: { key_id: 'k-1', name: 'ci', active: false } }),
    ]);
    const client = makeClient(transport);

    const key = await client.revokeKey('k-1');

    assert.equal(key.active, false);
    assert.equal(transport.calls[0].method, 'DELETE');
    assert.equal(transport.calls[0].url, 'http://api.test/v1/keys/k-1');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Streaming
// ══════════════════════════════════════════════════════════════════════════════
describe('streamProgress', () => {
  it('yields updates until terminal', async () => {
    const transport = new MockTransport([
      resp(200, { task_id: 's-1', status: 'running', progress: { percent: 10 } }),
      resp(200, { task_id: 's-1', status: 'running', progress: { percent: 60 } }),
      resp(200, { task_id: 's-1', status: 'completed', progress: { percent: 100 } }),
    ]);
    const client = makeClient(transport);

    const percents: number[] = [];
    for await (const status of client.streamProgress('s-1', { pollInterval: 0, timeout: 5 })) {
      percents.push(status.progress.percent);
    }

    assert.deepEqual(percents, [10, 60, 100]);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════════
describe('isTerminalStatus', () => {
  it('recognises terminal statuses', () => {
    assert.ok(isTerminalStatus('completed'));
    assert.ok(isTerminalStatus('failed'));
    assert.ok(isTerminalStatus('pending_approval'));
    assert.ok(!isTerminalStatus('running'));
  });
});
