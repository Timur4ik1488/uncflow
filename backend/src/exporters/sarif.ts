import type { Finding } from '../types/findings.ts';

/**
 * Exports findings in OASIS SARIF v2.1.0 format
 * Compliant with GitHub Code Scanning & GitLab SAST.
 */
export function exportToSarif(findings: Finding[]): any {
  const rulesMap = new Map<string, any>();
  const results: any[] = [];

  for (const f of findings) {
    const fAny = f as any;
    const ruleId = fAny.class || fAny.advisoryId || `${f.category}-ISSUE`;

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        shortDescription: { text: f.description || ruleId },
        fullDescription: { text: f.description || ruleId },
        defaultConfiguration: {
          level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : (f.severity === 'MEDIUM' ? 'warning' : 'note')
        },
        help: {
          text: f.remediation || 'Refer to security best practices to remediate this issue.'
        },
        properties: {
          category: f.category,
          precision: 'high'
        }
      });
    }

    const startLine = Math.max(1, fAny.line || 1);
    const endLine = Math.max(startLine, fAny.endLine || startLine);

    results.push({
      ruleId,
      level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : (f.severity === 'MEDIUM' ? 'warning' : 'note'),
      message: {
        text: f.description || `Detected ${f.category} issue: ${ruleId}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: (f.path || '').replace(/\\/g, '/').replace(/^\/+/, '')
            },
            region: {
              startLine,
              endLine: endLine > startLine ? endLine : undefined
            }
          }
        }
      ]
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'uncflow',
            version: '1.0.0',
            informationUri: 'https://github.com/gavney/uncflow',
            rules: Array.from(rulesMap.values())
          }
        },
        results
      }
    ]
  };
}
