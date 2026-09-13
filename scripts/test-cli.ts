import { runSelfVerificationTests } from '../src/crypto/testVectors.ts';

async function run() {
  console.log('Running test vectors with SIMD optimizations...');
  let passed = 0;
  const results = await runSelfVerificationTests((r) => {
    console.log(`[${r.passed ? 'PASS' : 'FAIL'}] ${r.suite} - ${r.name} (${r.executionTimeMs}ms)`);
    if (r.passed) passed++;
    else {
      console.log(`   Expected: ${r.expectedHex}`);
      console.log(`   Actual:   ${r.actualHex}`);
    }
  });
  console.log(`\nResults: ${passed} / ${results.length} passed.`);
  if (passed !== results.length) {
    process.exit(1);
  }
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
