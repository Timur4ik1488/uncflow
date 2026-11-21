/**
 * Comprehensive Maven and SemVer version comparator.
 */
export class VersionComparator {
  private static readonly PRERELEASE_WEIGHTS: Record<string, number> = {
    snapshot: -100,
    dev: -90,
    alpha: -50,
    a: -50,
    preview: -45,
    beta: -40,
    b: -40,
    milestone: -30,
    m: -30,
    cr: -20,
    rc: -20
  };

  private static readonly RELEASE_ALIASES = new Set(['final', 'ga', 'release', 'sp']);

  /**
   * Compares two version strings according to Maven & SemVer rules:
   * Returns:
   *   -1 if v1 < v2
   *    0 if v1 == v2
   *    1 if v1 > v2
   */
  public static compare(v1: string, v2: string): number {
    const p1 = this.parseVersion(v1);
    const p2 = this.parseVersion(v2);

    const maxNumeric = Math.max(p1.numbers.length, p2.numbers.length);
    for (let i = 0; i < maxNumeric; i++) {
      const n1 = i < p1.numbers.length ? p1.numbers[i] : 0;
      const n2 = i < p2.numbers.length ? p2.numbers[i] : 0;
      if (n1 < n2) return -1;
      if (n1 > n2) return 1;
    }

    // Numbers are equal, compare qualifiers / prerelease tags
    // e.g. 2.0.0-rc1 vs 2.0.0: 2.0.0 has weight 0, 2.0.0-rc1 has weight -20 -> rc1 < release
    const w1 = p1.qualifierWeight;
    const w2 = p2.qualifierWeight;
    if (w1 < w2) return -1;
    if (w1 > w2) return 1;

    // If both have same qualifier weight (e.g. rc1 vs rc2)
    if (p1.qualifierNum < p2.qualifierNum) return -1;
    if (p1.qualifierNum > p2.qualifierNum) return 1;

    return 0;
  }

  private static parseVersion(version: string): {
    numbers: number[];
    qualifierWeight: number;
    qualifierNum: number;
  } {
    const clean = (version || '').trim().replace(/^v\.?/i, '');
    const tokens = clean.split(/[.-]/);

    const numbers: number[] = [];
    let qualifierWeight = 0; // 0 means regular release
    let qualifierNum = 0;

    for (const t of tokens) {
      if (!t) continue;
      const num = parseInt(t, 10);
      if (!isNaN(num) && /^\d+$/.test(t)) {
        numbers.push(num);
      } else {
        // String token, check for prerelease / release qualifier
        // e.g. "rc1" -> "rc", 1
        const match = t.toLowerCase().match(/^([a-z]+)(\d+)?$/);
        if (match) {
          const tag = match[1];
          const tagNum = match[2] ? parseInt(match[2], 10) : 0;

          if (this.RELEASE_ALIASES.has(tag)) {
            // Equivalent to standard release
            qualifierWeight = 0;
          } else if (this.PRERELEASE_WEIGHTS[tag] !== undefined) {
            qualifierWeight = this.PRERELEASE_WEIGHTS[tag];
            qualifierNum = tagNum;
          }
        }
      }
    }

    // Trim trailing zeros for comparison (e.g. [1, 9, 0] -> [1, 9])
    while (numbers.length > 0 && numbers[numbers.length - 1] === 0) {
      numbers.pop();
    }

    return { numbers, qualifierWeight, qualifierNum };
  }

  /**
   * Check if a version falls within [lower, upper] with inclusive flags
   */
  public static isInRange(
    version: string,
    lower: string | null,
    lowerInclusive: boolean,
    upper: string | null,
    upperInclusive: boolean
  ): boolean {
    if (lower !== null && lower !== undefined) {
      const cmpLower = this.compare(version, lower);
      if (lowerInclusive) {
        if (cmpLower < 0) return false;
      } else {
        if (cmpLower <= 0) return false;
      }
    }

    if (upper !== null && upper !== undefined) {
      const cmpUpper = this.compare(version, upper);
      if (upperInclusive) {
        if (cmpUpper > 0) return false;
      } else {
        if (cmpUpper >= 0) return false;
      }
    }

    return true;
  }
}
