/**
 * Key management: mint, list, and revoke API keys.
 *
 * Run with:
 *   export AQL1_API_KEY=sk-...        # an existing key with key-management scope
 *   npx tsx examples/manage-keys.ts
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
    // 1. Mint a new key. The raw key is returned exactly once.
    const created = await client.createKey('ci-pipeline', {
      ownerId: 'team-platform',
      scopes: ['agent:run', 'agent:read'],
      rateLimitRequests: 120,
      rateLimitWindowSeconds: 60,
    });
    console.log(`created key_id=${created.key.key_id}`);
    console.log(`RAW KEY (store it now): ${created.api_key}`);
    console.log(`warning: ${created.warning}`);

    // 2. List key metadata (never the raw key or its hash).
    console.log('\nkeys:');
    for (const key of await client.listKeys()) {
      const state = key.active ? 'active' : 'revoked';
      console.log(
        `  ${key.key_id}  ${key.name.padEnd(16)} ${state.padEnd(8)} scopes=${key.scopes.join(',')}`,
      );
    }

    // 3. Revoke the key we just made.
    const revoked = await client.revokeKey(created.key.key_id);
    console.log(`\nrevoked ${revoked.key_id} (active=${revoked.active})`);
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
