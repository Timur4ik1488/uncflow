import assert from 'assert';
import * as path from 'path';
import * as fs from 'fs';
import { NodeRegistry } from '../src/nodes/registry.ts';
import { WorkflowEngine } from '../src/engine/workflow-engine.ts';
import { TemplateCatalog } from '../src/templates/catalog.ts';
import { db } from '../src/storage/db.ts';

async function runTests() {
  console.log('===============================================================');
  console.log('🧪 TESTING UN-HARDCODED NODES & MULTI-USER TEMPLATES');
  console.log('===============================================================');

  const registry = new NodeRegistry();
  const engine = new WorkflowEngine(registry);
  const catalog = new TemplateCatalog();

  // Test 1: source.local un-hardcoded path resolution
  console.log('\n1. Testing source.local with dynamic path...');
  const localNode = registry.getNode('source.local')!;
  const localRes = await localNode.run({}, { path: 'test-dataset/training-project' });
  assert.ok(localRes.codePath, 'codePath must be returned');
  assert.ok(fs.existsSync(localRes.codePath), 'codePath must exist on disk');
  console.log('  ✅ [PASS] source.local correctly resolved codePath:', localRes.codePath);

  // Test 2: source.git with TBagirov/training fast-path and custom URL handling
  console.log('\n2. Testing source.git parameters and handling...');
  const gitNode = registry.getNode('source.git')!;
  const gitRes = await gitNode.run({}, {
    repoUrl: 'https://github.com/TBagirov/training',
    branch: 'main',
    subDir: 'training-project'
  });
  assert.ok(gitRes.codePath, 'codePath must be returned from git node');
  assert.strictEqual(gitRes.branch, 'main', 'branch must be preserved');
  console.log('  ✅ [PASS] source.git handled repoUrl and branch correctly:', gitRes.repoUrl);

  // Test 3: notify.telegram parameterization and error handling without crashing
  console.log('\n3. Testing notify.telegram un-hardcoded settings...');
  const tgNode = registry.getNode('notify.telegram')!;
  const tgDummyRes = await tgNode.run(
    { findings: [{ category: 'SECRET', path: 'Test.kt', line: 10, severity: 'HIGH' }] },
    { botToken: '123456:FAKE_TOKEN_FOR_TEST', chatId: '123456789' }
  );
  // It attempted the Telegram API fetch, handled network/API error cleanly without throwing:
  assert.ok(tgDummyRes.sent === false, 'Invalid token returns sent: false');
  assert.ok(tgDummyRes.error, 'Error message was captured properly');
  console.log('  ✅ [PASS] notify.telegram handled token parameters cleanly:', tgDummyRes.error);

  // Test 4: notify.telegram with onlyOnCritical skipping
  const tgSkipRes = await tgNode.run(
    { findings: [{ category: 'SCA', path: 'build.gradle.kts', severity: 'LOW' }] },
    { botToken: '123456:FAKE', chatId: '123456', onlyOnCritical: true }
  );
  assert.strictEqual(tgSkipRes.skipped, true, 'onlyOnCritical must skip when 0 critical');
  console.log('  ✅ [PASS] notify.telegram onlyOnCritical skipped properly:', tgSkipRes.reason);

  // Test 5: Multi-User Templates Storage & Filtering
  console.log('\n4. Testing Multi-User Templates (Tenancy & Permissions)...');
  const user1 = 'analyst_alice';
  const user2 = 'analyst_bob';

  const templateAlice = {
    id: 'tpl_alice_1',
    title: 'Alice Special CI/CD Scan',
    description: 'Custom pipeline created by Alice',
    category: 'CI/CD',
    tags: ['Alice', 'Kotlin'],
    author: 'Alice',
    userId: user1,
    isPublic: false,
    graph: { id: 'wf_alice', name: 'Alice Workflow', nodes: [], edges: [] }
  };

  const templateBobPublic = {
    id: 'tpl_bob_public',
    title: 'Bob Shared Template',
    description: 'Public template created by Bob',
    category: 'Full Audit',
    tags: ['Bob', 'Public'],
    author: 'Bob',
    userId: user2,
    isPublic: true,
    graph: { id: 'wf_bob', name: 'Bob Workflow', nodes: [], edges: [] }
  };

  catalog.publish(templateAlice, false);
  catalog.publish(templateBobPublic, false);

  const aliceTemplates = await catalog.getAllAsync(user1);
  assert.ok(aliceTemplates.some(t => t.id === 'tpl_alice_1'), 'Alice can see her own private template');
  assert.ok(aliceTemplates.some(t => t.id === 'tpl_bob_public'), 'Alice can see Bob public template');
  assert.ok(aliceTemplates.some(t => t.isBuiltin), 'Alice can see system builtin templates');

  const bobTemplates = await catalog.getAllAsync(user2);
  assert.ok(bobTemplates.some(t => t.id === 'tpl_bob_public'), 'Bob can see his public template');
  assert.ok(!bobTemplates.some(t => t.id === 'tpl_alice_1'), 'Bob CANNOT see Alice private template');
  console.log('  ✅ [PASS] Multi-user template tenancy verified: Alice private template hidden from Bob!');

  // Test 6: Delete user template
  const deleted = await db.deleteTemplate('tpl_alice_1', user1);
  assert.strictEqual(deleted, true, 'Alice successfully deleted her template');
  const postDeleteAlice = await catalog.getAllAsync(user1);
  assert.ok(!postDeleteAlice.some(t => t.id === 'tpl_alice_1'), 'Template no longer exists for Alice');
  console.log('  ✅ [PASS] Custom template deleted cleanly by owner!');

  console.log('\n===============================================================');
  console.log('🎉 ALL NODE UN-HARDCODING & MULTI-USER TEMPLATES TESTS PASSED!');
  console.log('===============================================================');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
