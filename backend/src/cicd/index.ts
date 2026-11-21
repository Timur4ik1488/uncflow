import type { Finding } from '../types/findings.ts';

export interface CiCdRunResult {
  status: 'passed' | 'failed';
  exitCode: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  summaryMarkdown: string;
  findings: Finding[];
}

export class CiCdManager {
  /**
   * Generates GitHub Actions workflow YAML configuration
   */
  public static generateGitHubWorkflow(serverUrl: string = 'http://localhost:3001', apiKey: string = 'SECRET_CI_KEY'): string {
    return `name: uncflow Gatekeeper

on:
  push:
    branches: [ "main", "master", "develop" ]
  pull_request:
    branches: [ "main", "master" ]

jobs:
  security-audit:
    name: Run uncflow Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run uncflow Audit via Platform API
        id: security_step
        run: |
          echo "Starting security scan on commit \${{ github.sha }}..."
          
          # Call the uncflow API
          RESPONSE=\$(curl -s -X POST "${serverUrl}/api/ci/run" \\
            -H "Content-Type: application/json" \\
            -H "Authorization: Bearer ${apiKey}" \\
            -d '{
              "repo": "\${{ github.repository }}",
              "commitSha": "\${{ github.sha }}",
              "branch": "\${{ github.ref_name }}",
              "failOnCritical": true
            }')
          
          echo "\$RESPONSE" > audit-result.json
          
          # Extract status and exit code
          EXIT_CODE=\$(node -e 'console.log(JSON.parse(require("fs").readFileSync("audit-result.json", "utf-8")).exitCode || 0)')
          TOTAL=\$(node -e 'console.log(JSON.parse(require("fs").readFileSync("audit-result.json", "utf-8")).totalFindings || 0)')
          CRITICAL=\$(node -e 'console.log(JSON.parse(require("fs").readFileSync("audit-result.json", "utf-8")).criticalCount || 0)')
          
          echo "Total findings: \$TOTAL, Critical/High: \$CRITICAL"
          
          if [ "\$EXIT_CODE" -ne 0 ]; then
            echo "::error::uncflow detected critical vulnerabilities! Blocking build."
            exit \$EXIT_CODE
          fi
          
          echo "Security check passed successfully."
`;
  }

  /**
   * Generates GitLab CI configuration YAML
   */
  public static generateGitLabCi(serverUrl: string = 'http://localhost:3001', apiKey: string = 'SECRET_CI_KEY'): string {
    return `stages:
  - test
  - security

ai-security-audit:
  stage: security
  image: node:20-alpine
  script:
    - apk add --no-cache curl
    - |
      RESPONSE=\$(curl -s -X POST "${serverUrl}/api/ci/run" \\
        -H "Content-Type: application/json" \\
        -H "Authorization: Bearer ${apiKey}" \\
        -d '{
          "repo": "\$CI_PROJECT_PATH",
          "commitSha": "\$CI_COMMIT_SHA",
          "branch": "\$CI_COMMIT_REF_NAME",
          "failOnCritical": true
        }')
      echo "\$RESPONSE" > audit-result.json
      node -e '
        const res = JSON.parse(require("fs").readFileSync("audit-result.json", "utf-8"));
        console.log("Findings:", res.totalFindings, "Critical:", res.criticalCount);
        if (res.exitCode !== 0) {
          console.error("Critical security risks detected! Build failed.");
          process.exit(res.exitCode);
        }
      '
  artifacts:
    when: always
    paths:
      - audit-result.json
`;
  }

  /**
   * Formats CI PR comment markdown
   */
  public static formatPrComment(result: CiCdRunResult, commitSha: string): string {
    const icon = result.exitCode === 0 ? '✅' : '🚨';
    const statusText = result.exitCode === 0 ? 'Security Check Passed' : 'Security Vulnerabilities Detected';

    let md = `### ${icon} uncflow: ${statusText}\n\n`;
    md += `**Commit:** \`${commitSha.substring(0, 8)}\` | **Total findings:** **${result.totalFindings}** (Critical: **${result.criticalCount}**, High: **${result.highCount}**)\n\n`;

    if (result.findings.length > 0) {
      md += `| Category | Issue | Location | Severity |\n`;
      md += `| :--- | :--- | :--- | :--- |\n`;
      for (const f of result.findings.slice(0, 10)) {
        const loc = f.category === 'SCA' ? (f as any).artifact : `${f.path}:${(f as any).line}`;
        const id = f.category === 'SCA' ? (f as any).advisoryId : (f as any).class;
        md += `| **${f.category}** | \`${id}\` | \`${loc}\` | **${f.severity || 'MEDIUM'}** |\n`;
      }
      if (result.findings.length > 10) {
        md += `\n*...and ${result.findings.length - 10} more findings in full report.*`;
      }
    } else {
      md += `No security vulnerabilities found in this pull request.\n`;
    }

    return md;
  }
}
