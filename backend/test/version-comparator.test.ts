import { VersionComparator } from '../src/analyzers/sca/version-comparator.ts';

function runVersionComparatorTests() {
  console.log('--- Testing VersionComparator ---');

  // Test 1: 1.5.3 against <= 1.5.3 (vulnerable)
  const t1 = VersionComparator.isInRange('1.5.3', null, false, '1.5.3', true);
  if (!t1) throw new Error('Expected 1.5.3 to be in range <= 1.5.3');
  console.log('✅ 1.5.3 in range <= 1.5.3: true');

  // Test 2: 1.5.3 against < 1.5.3 (safe)
  const t2 = VersionComparator.isInRange('1.5.3', null, false, '1.5.3', false);
  if (t2) throw new Error('Expected 1.5.3 NOT to be in range < 1.5.3');
  console.log('✅ 1.5.3 in range < 1.5.3: false');

  // Test 3: 2.0.0-rc1 against < 2.0.0 (vulnerable)
  const t3 = VersionComparator.isInRange('2.0.0-rc1', null, false, '2.0.0', false);
  if (!t3) throw new Error('Expected 2.0.0-rc1 to be in range < 2.0.0');
  console.log('✅ 2.0.0-rc1 in range < 2.0.0: true');

  // Test 4: 1.2.3.RELEASE against <= 1.2.3 (vulnerable)
  const t4 = VersionComparator.isInRange('1.2.3.RELEASE', null, false, '1.2.3', true);
  if (!t4) throw new Error('Expected 1.2.3.RELEASE to be in range <= 1.2.3');
  console.log('✅ 1.2.3.RELEASE in range <= 1.2.3: true');

  // Test 5: Equality 1.9 vs 1.9.0
  const t5 = VersionComparator.compare('1.9', '1.9.0') === 0;
  if (!t5) throw new Error('Expected 1.9 == 1.9.0');
  console.log('✅ 1.9 == 1.9.0: true');

  // Test 6: Safe higher version 3.20.0 against <= 3.18.0
  const t6 = VersionComparator.isInRange('3.20.0', null, false, '3.18.0', true);
  if (t6) throw new Error('Expected 3.20.0 NOT in range <= 3.18.0');
  console.log('✅ 3.20.0 in range <= 3.18.0: false');

  console.log('🎉 All VersionComparator tests passed successfully!\n');
}

runVersionComparatorTests();
