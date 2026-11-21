export class VersionComparator {
  /**
   * Compares two version strings according to Cyber Garden 2026 specs:
   * - Split into numeric components.
   * - 1.9 is equal to 1.9.0.
   * - 20230227 is treated as a single numeric component.
   * Returns:
   *   -1 if v1 < v2
   *    0 if v1 == v2
   *    1 if v1 > v2
   */
  public static compare(v1: string, v2: string): number {
    const parts1 = this.normalize(v1);
    const parts2 = this.normalize(v2);

    const maxLen = Math.max(parts1.length, parts2.length);
    for (let i = 0; i < maxLen; i++) {
      const p1 = i < parts1.length ? parts1[i] : 0;
      const p2 = i < parts2.length ? parts2[i] : 0;

      if (p1 < p2) return -1;
      if (p1 > p2) return 1;
    }

    return 0;
  }

  private static normalize(version: string): number[] {
    // Strip leading 'v' or 'v.'
    const clean = version.trim().replace(/^v\.?/i, '');
    const tokens = clean.split(/[.-]/);
    const result: number[] = [];

    for (const t of tokens) {
      const num = parseInt(t, 10);
      if (!isNaN(num)) {
        result.push(num);
      }
    }

    // Trim trailing zeros for comparison (e.g. [1, 9, 0] -> [1, 9])
    while (result.length > 0 && result[result.length - 1] === 0) {
      result.pop();
    }

    return result;
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
    if (lower !== null) {
      const cmpLower = this.compare(version, lower);
      if (lowerInclusive) {
        if (cmpLower < 0) return false;
      } else {
        if (cmpLower <= 0) return false;
      }
    }

    if (upper !== null) {
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
