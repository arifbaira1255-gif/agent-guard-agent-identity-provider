/**
 * Streaming quickstart: run an agent and iterate progress updates.
 *
 * Run with:
 *   export AQL1_API_KEY=sk-...
 *   npx tsx examples/async-quickstart.ts
 */

import { AQL1, AQL1Error } from '../src/index.js';

async function main(): Promise<number> {
  const apiKey = process.env['AQL1_API_KEY'];
  if (!apiKey) {
    console.log('Set AQL1_API_KEY first.');
    return 1;
  }

  const client = new AQL1({
    apiKey,
    baseUrl: process.env['AQL1_BASE_URL'] ?? 'http://localhost:8000',
  });

  try {
    const started = await client.runAgent({
      prompt: 'Draft a 3-bullet launch plan for a new feature.',
      allowHumanApproval: true,
    });
    console.log(`started task ${started.task_id}`);

    // Async-iterate status updates as they arrive.
    for await (const status of client.streamProgress(started.task_id, {
      pollInterval: 1,
      timeout: 120,
    })) {
      console.log(
        `  ${status.status.padEnd(18)} ${status.progress.percent.toFixed(1).padStart(5)}%  ` +
          `$${status.cost_usd.toFixed(4)}`,
      );
      if (status.status === 'completed') {
        console.log('\nAnswer:', status.result?.['answer']);
      } else if (status.status === 'pending_approval') {
        console.log(`\nPaused for approval: ${status.approval_id}`);
      }
    }
  } catch (error) {
    if (error instanceof AQL1Error) {
      console.error(`AQL-1 error: ${error.message}`);
      return 1;
    }
    throw error;
  }

  return 0;
}

main().then((code) => process.exit(code));
