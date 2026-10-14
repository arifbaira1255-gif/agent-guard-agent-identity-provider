/**
 * Quickstart: start a run, poll it, and print the result.
 *
 * Run with:
 *   export AQL1_API_KEY=sk-...
 *   npx tsx examples/quickstart.ts
 */

import { AQL1, AQL1Error } from '../src/index.js';

async function main(): Promise<number> {
  const apiKey = process.env['AQL1_API_KEY'];
  if (!apiKey) {
    console.log('Set AQL1_API_KEY first (mint one with examples/manage-keys.ts).');
    return 1;
  }

  const client = new AQL1({
    apiKey,
    baseUrl: process.env['AQL1_BASE_URL'] ?? 'http://localhost:8000',
  });

  try {
    // 1. Start the run (async by default — returns a task handle).
    const started = await client.runAgent({
      prompt: 'Summarise the top 3 AI news stories from today.',
      allowHumanApproval: true,
    });
    console.log(`started task ${started.task_id} (status=${started.status})`);

    // 2. Poll until it settles, printing progress as it goes.
    const status = await client.waitForCompletion(started.task_id, {
      pollInterval: 1,
      timeout: 120,
      onProgress: (s) =>
        console.log(
          `  ${s.status.padEnd(18)} ${s.progress.percent.toFixed(1).padStart(5)}%  ` +
            `$${s.cost_usd.toFixed(4)}  ${s.tokens} tokens`,
        ),
    });

    // 3. Report the outcome.
    if (status.status === 'pending_approval') {
      console.log(`\nPaused for human approval: ${status.approval_id}`);
      console.log('Approve it with examples/approvals.ts');
    } else if (status.status === 'completed') {
      console.log('\nCompleted.');
      console.log('Answer:', status.result?.['answer']);
    } else {
      console.log(`\nRun ended with status=${status.status} error=${status.error}`);
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
