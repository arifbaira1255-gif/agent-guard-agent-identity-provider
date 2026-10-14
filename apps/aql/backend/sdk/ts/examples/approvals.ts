/**
 * Human-in-the-loop: run a high-risk action, then approve or reject it.
 *
 * Run with:
 *   export AQL1_API_KEY=sk-...
 *   npx tsx examples/approvals.ts
 */

import { AQL1, AQL1Error, ApprovalRequiredError } from '../src/index.js';

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
    // A high-risk action (sending an external email) pauses for approval.
    const started = await client.runAgent({
      prompt: 'Email the Q3 report to the client.',
      actionType: 'email.send',
      payload: { to: 'client@example.com', subject: 'Q3 report' },
      allowHumanApproval: true,
    });

    if (started.status !== 'pending_approval') {
      console.log(`Run did not pause (status=${started.status}).`);
      return 0;
    }

    console.log(`Paused for approval: ${started.approval_id}`);
    console.log('A human reviewer would now approve or reject this in the dashboard.');

    // Approve it (use decision: 'reject' to reject instead).
    const result = await client.approve(started.approval_id ?? '', {
      decision: 'approve',
      approver: 'arif',
      note: 'Verified the recipient and attachment.',
    });
    console.log(`Decision recorded: ${String(result['status'])}`);

    // Poll the run to completion after the resume.
    const status = await client.waitForCompletion(started.task_id, {
      pollInterval: 1,
      timeout: 120,
    });
    console.log(`Final status: ${status.status}`);
    if (status.status === 'completed') {
      console.log('Answer:', status.result?.['answer']);
    }
  } catch (error) {
    if (error instanceof ApprovalRequiredError) {
      // Thrown when allowHumanApproval=false but the action was high-risk.
      console.log(`Approval required (id=${error.approvalId}); approve it out of band.`);
    } else if (error instanceof AQL1Error) {
      console.error(`AQL-1 error: ${error.message}`);
      return 1;
    } else {
      throw error;
    }
  }

  return 0;
}

main().then((code) => process.exit(code));
