/**
 * Error handling: retries, rate limits, and typed errors.
 *
 * Run with:
 *   export AQL1_API_KEY=sk-...
 *   npx tsx examples/error-handling.ts
 */

import {
  AQL1,
  APIError,
  APIConnectionError,
  AuthenticationError,
  NotFoundError,
  RateLimitError,
  TimeoutError,
  ValidationError,
} from '../src/index.js';

async function main(): Promise<number> {
  const client = new AQL1({
    apiKey: process.env['AQL1_API_KEY'] ?? 'sk-invalid',
    baseUrl: process.env['AQL1_BASE_URL'] ?? 'http://localhost:8000',
    timeout: 10,
    maxRetries: 3, // 429/5xx/network failures are retried automatically
  });

  try {
    const status = await client.getStatus('does-not-exist');
    console.log(`OK: ${status.status}`);
  } catch (error) {
    if (error instanceof AuthenticationError) {
      // 401 — the key is missing, invalid, or revoked.
      console.error(`Auth failed (${error.code}): ${error.message}`);
    } else if (error instanceof RateLimitError) {
      // 429 — back off using the server's own numbers.
      console.error(
        `Rate limited. retryAfter=${error.retryAfter}s limit=${error.limit} ` +
          `remaining=${error.remaining} reset=${error.reset}`,
      );
    } else if (error instanceof NotFoundError) {
      // 404 — the task id is unknown.
      console.error(`Not found: ${error.message}`);
    } else if (error instanceof ValidationError) {
      // 422 — the request body was rejected.
      console.error(`Invalid request: ${error.message}`);
    } else if (error instanceof TimeoutError) {
      // The request exceeded the configured timeout.
      console.error(`Timed out: ${error.message}`);
    } else if (error instanceof APIConnectionError) {
      // The request never reached the server (DNS, refused, reset...).
      console.error(`Connection problem: ${error.message}`);
    } else if (error instanceof APIError) {
      // Any other non-2xx response, with the status code and parsed body.
      console.error(`API error ${error.statusCode}: ${error.message}`, error.body);
    } else {
      throw error;
    }
    return 1;
  }

  return 0;
}

main().then((code) => process.exit(code));
