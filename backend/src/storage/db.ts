import pg from 'pg';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import type { Finding } from '../types/findings.ts';
import type { WorkflowTemplate } from '../templates/catalog.ts';
import { SecretVault } from './crypto.ts';

const { Pool } = pg;

export interface UserProfile {
  id: string;
  email: string;
  passwordHash?: string;
  name: string;
  avatarUrl?: string;
  githubId?: string;
  githubUsername?: string;
  githubToken?: string;
  gitverseUsername?: string;
  gitverseToken?: string;
  createdAt: string;
  updatedAt: string;
}

export interface UserSession {
  token: string;
  userId: string;
  createdAt: string;
  expiresAt: string;
}

export interface WorkflowRunRecord {
  id: string;
  workflowId: string;
  workflowName: string;
  success: boolean;
  durationMs: number;
  startTime: string;
  endTime?: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  result?: any;
  createdAt?: string;
}

export interface ReportRecord {
  id?: number;
  runId?: string;
  totalVulnerabilities: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  jsonContent: any;
  markdownContent: string;
  createdAt?: string;
}

export interface FindingFilter {
  runId?: string;
  category?: string;
  severity?: string;
  class?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface FindingStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  byCategory: {
    SECRET: number;
    SAST: number;
    SCA: number;
  };
}

export interface DbHealthStatus {
  connected: boolean;
  driver: 'postgres' | 'memory-fallback';
  database?: string;
  host?: string;
  port?: number;
  counts?: {
    runs: number;
    findings: number;
    templates: number;
    reports: number;
  };
  error?: string;
}

export class DatabaseService {
  private pool: pg.Pool | null = null;
  private isConnected = false;
  private memoryRuns: WorkflowRunRecord[] = [];
  private memoryFindings: { runId: string; finding: Finding }[] = [];
  private memoryReports: ReportRecord[] = [];
  private memoryTemplates: Map<string, WorkflowTemplate> = new Map();
  private memorySecrets: Map<string, { value: string; description?: string }> = new Map();
  private memoryUsers: Map<string, UserProfile> = new Map();
  private memorySessions: Map<string, UserSession> = new Map();
  private initPromise: Promise<boolean> | null = null;

  constructor() {
    this.createPool();
    this.seedMemoryDemoUser();
  }

  private seedMemoryDemoUser() {
    const demoHash = SecretVault.hashPassword('demopassword');
    this.memoryUsers.set('user_demo_1', {
      id: 'user_demo_1',
      email: 'demo@uncflow.io',
      passwordHash: demoHash,
      name: 'Демо Инженер',
      avatarUrl: 'https://api.dicebear.com/7.x/bottts/svg?seed=uncflow',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
  }

  private createPool() {
    const connectionString =
      process.env.DATABASE_URL ||
      `postgres://${process.env.PGUSER || 'postgres'}:${process.env.PGPASSWORD || 'postgrespassword'}@${process.env.PGHOST || 'localhost'}:${process.env.PGPORT || 5432}/${process.env.PGDATABASE || 'security_workflow'}`;

    try {
      this.pool = new Pool({
        connectionString,
        connectionTimeoutMillis: 3000,
        idleTimeoutMillis: 10000,
        max: 10
      });

      this.pool.on('error', (err) => {
        console.warn('⚠️ [PostgreSQL Pool Error]:', err.message);
        this.isConnected = false;
      });
    } catch (err: any) {
      console.warn('⚠️ [PostgreSQL Init Warning]: Failed to create Pool, falling back to in-memory:', err.message);
      this.pool = null;
    }
  }

  /**
   * Initializes PostgreSQL connection, schema, and initial seed data.
   */
  public async init(): Promise<boolean> {
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      if (!this.pool) {
        console.log('ℹ️ [PostgreSQL]: Using in-memory fallback mode.');
        return false;
      }

      try {
        const client = await this.pool.connect();
        try {
          // Check connection
          await client.query('SELECT 1');
          this.isConnected = true;
          console.log('🐘 [PostgreSQL]: Connected successfully to database!');

          // Initialize Schema
          await this.initSchema(client);

          // Seed default data if empty
          await this.seedVulnerabilitiesIfEmpty(client);

          return true;
        } finally {
          client.release();
        }
      } catch (err: any) {
        console.warn(`⚠️ [PostgreSQL]: Could not connect to PostgreSQL (${err.message}). Operating in resilient in-memory mode.`);
        this.isConnected = false;
        return false;
      }
    })();

    return this.initPromise;
  }

  private async initSchema(client: pg.PoolClient) {
    const schemaSql = `
      CREATE TABLE IF NOT EXISTS workflow_runs (
          id VARCHAR(64) PRIMARY KEY,
          workflow_id VARCHAR(64) NOT NULL,
          workflow_name VARCHAR(255) NOT NULL,
          success BOOLEAN NOT NULL DEFAULT true,
          duration_ms INTEGER NOT NULL DEFAULT 0,
          start_time TIMESTAMPTZ NOT NULL,
          end_time TIMESTAMPTZ,
          findings_count INTEGER NOT NULL DEFAULT 0,
          critical_count INTEGER NOT NULL DEFAULT 0,
          high_count INTEGER NOT NULL DEFAULT 0,
          medium_count INTEGER NOT NULL DEFAULT 0,
          low_count INTEGER NOT NULL DEFAULT 0,
          result JSONB,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_workflow_runs_created_at ON workflow_runs(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_workflow_runs_workflow_id ON workflow_runs(workflow_id);

      CREATE TABLE IF NOT EXISTS findings (
          id SERIAL PRIMARY KEY,
          run_id VARCHAR(64) REFERENCES workflow_runs(id) ON DELETE CASCADE,
          category VARCHAR(32) NOT NULL,
          path TEXT NOT NULL,
          line INTEGER,
          end_line INTEGER,
          class VARCHAR(128),
          group_name VARCHAR(255),
          artifact VARCHAR(255),
          version VARCHAR(64),
          advisory_id VARCHAR(64),
          severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
          description TEXT,
          remediation TEXT,
          raw_data JSONB,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
      CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_findings_class ON findings(class);

      CREATE TABLE IF NOT EXISTS workflow_templates (
          id VARCHAR(64) PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          category VARCHAR(64) NOT NULL,
          tags TEXT[] NOT NULL DEFAULT '{}',
          author VARCHAR(128) DEFAULT 'Anonymous',
          user_id VARCHAR(64) NOT NULL DEFAULT 'default_user',
          is_public BOOLEAN NOT NULL DEFAULT FALSE,
          is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
          graph JSONB NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      -- Schema migrations for existing tables
      ALTER TABLE workflow_templates ADD COLUMN IF NOT EXISTS user_id VARCHAR(64) NOT NULL DEFAULT 'default_user';
      ALTER TABLE workflow_templates ADD COLUMN IF NOT EXISTS is_public BOOLEAN NOT NULL DEFAULT FALSE;

      CREATE INDEX IF NOT EXISTS idx_workflow_templates_category ON workflow_templates(category);
      CREATE INDEX IF NOT EXISTS idx_workflow_templates_is_builtin ON workflow_templates(is_builtin);
      CREATE INDEX IF NOT EXISTS idx_workflow_templates_user_id ON workflow_templates(user_id);
      CREATE INDEX IF NOT EXISTS idx_workflow_templates_is_public ON workflow_templates(is_public);

      CREATE TABLE IF NOT EXISTS reports (
          id SERIAL PRIMARY KEY,
          run_id VARCHAR(64) REFERENCES workflow_runs(id) ON DELETE SET NULL,
          total_vulnerabilities INTEGER NOT NULL DEFAULT 0,
          summary JSONB NOT NULL,
          json_content JSONB NOT NULL,
          markdown_content TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_reports_run_id ON reports(run_id);

      CREATE TABLE IF NOT EXISTS vulnerabilities (
          id VARCHAR(64) PRIMARY KEY,
          aliases TEXT[] DEFAULT '{}',
          group_name VARCHAR(255) NOT NULL,
          artifact VARCHAR(255) NOT NULL,
          affected_ranges JSONB,
          fixed_versions TEXT[] DEFAULT '{}',
          severity VARCHAR(32),
          details TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_vulnerabilities_group_artifact ON vulnerabilities(group_name, artifact);

      CREATE TABLE IF NOT EXISTS vault_secrets (
          key VARCHAR(128) PRIMARY KEY,
          encrypted_value TEXT NOT NULL,
          description TEXT,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      -- 7. User Accounts & Multi-Tenant Profiles (GitHub & GitVerse Integration)
      CREATE TABLE IF NOT EXISTS users (
          id VARCHAR(64) PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255),
          name VARCHAR(255) NOT NULL,
          avatar_url TEXT,
          github_id VARCHAR(64),
          github_username VARCHAR(128),
          github_token TEXT,
          gitverse_username VARCHAR(128),
          gitverse_token TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);

      -- 8. User Auth Sessions
      CREATE TABLE IF NOT EXISTS user_sessions (
          token VARCHAR(128) PRIMARY KEY,
          user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          expires_at TIMESTAMPTZ NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
    `;

    await client.query(schemaSql);

    // Seed demo user in PostgreSQL if empty
    try {
      const demoUserRes = await client.query('SELECT COUNT(*) as count FROM users');
      if (parseInt(demoUserRes.rows[0].count, 10) === 0) {
        const demoHash = SecretVault.hashPassword('demopassword');
        await client.query(`
          INSERT INTO users (id, email, password_hash, name, avatar_url, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
          ON CONFLICT (email) DO NOTHING
        `, ['user_demo_1', 'demo@uncflow.io', demoHash, 'Демо Инженер', 'https://api.dicebear.com/7.x/bottts/svg?seed=uncflow']);
      }
    } catch (e: any) {
      console.warn('⚠️ [PostgreSQL]: Note on demo user seeding:', e.message);
    }
  }

  private async seedVulnerabilitiesIfEmpty(client: pg.PoolClient) {
    try {
      const res = await client.query('SELECT COUNT(*) as count FROM vulnerabilities');
      if (parseInt(res.rows[0].count, 10) === 0) {
        const candidatePaths = [
          path.resolve(process.cwd(), 'test-dataset', 'vulnerability-database', 'vulnerabilities.json'),
          path.resolve(process.cwd(), '..', 'test-dataset', 'vulnerability-database', 'vulnerabilities.json')
        ];

        for (const p of candidatePaths) {
          if (fs.existsSync(p)) {
            const raw = JSON.parse(fs.readFileSync(p, 'utf-8'));
            const list = raw.vulnerabilities || [];
            if (list.length > 0) {
              for (const v of list) {
                await client.query(
                  `INSERT INTO vulnerabilities (id, aliases, group_name, artifact, affected_ranges, fixed_versions, severity, details)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   ON CONFLICT (id) DO NOTHING`,
                  [
                    v.id,
                    v.aliases || [],
                    v.group,
                    v.artifact,
                    JSON.stringify(v.ranges || []),
                    v.fixedVersions || [],
                    v.severity || 'MEDIUM',
                    v.details || ''
                  ]
                );
              }
              console.log(`✅ [PostgreSQL]: Seeded ${list.length} vulnerability records into 'vulnerabilities' table.`);
            }
            break;
          }
        }
      }
    } catch (err: any) {
      console.warn('⚠️ [PostgreSQL]: Failed to seed vulnerabilities:', err.message);
    }
  }

  // ===========================================================================
  // WORKFLOW RUNS
  // ===========================================================================

  public async saveWorkflowRun(run: WorkflowRunRecord): Promise<void> {
    // Always keep memory copy
    this.memoryRuns.unshift(run);
    if (this.memoryRuns.length > 100) this.memoryRuns.pop();

    if (!this.isConnected || !this.pool) return;

    try {
      await this.pool.query(
        `INSERT INTO workflow_runs (
          id, workflow_id, workflow_name, success, duration_ms, start_time, end_time,
          findings_count, critical_count, high_count, medium_count, low_count, result
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (id) DO UPDATE SET
          success = EXCLUDED.success,
          duration_ms = EXCLUDED.duration_ms,
          end_time = EXCLUDED.end_time,
          findings_count = EXCLUDED.findings_count,
          critical_count = EXCLUDED.critical_count,
          high_count = EXCLUDED.high_count,
          medium_count = EXCLUDED.medium_count,
          low_count = EXCLUDED.low_count,
          result = EXCLUDED.result`,
        [
          run.id,
          run.workflowId,
          run.workflowName,
          run.success,
          run.durationMs,
          run.startTime,
          run.endTime || null,
          run.findingsCount,
          run.criticalCount,
          run.highCount,
          run.mediumCount,
          run.lowCount,
          JSON.stringify(run.result || {})
        ]
      );
    } catch (err: any) {
      console.warn('⚠️ [PostgreSQL saveWorkflowRun error]:', err.message);
    }
  }

  public async getWorkflowRuns(limit = 50, offset = 0): Promise<WorkflowRunRecord[]> {
    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(
          `SELECT
            id, workflow_id as "workflowId", workflow_name as "workflowName",
            success, duration_ms as "durationMs", start_time as "startTime",
            end_time as "endTime", findings_count as "findingsCount",
            critical_count as "criticalCount", high_count as "highCount",
            medium_count as "mediumCount", low_count as "lowCount",
            result, created_at as "createdAt"
           FROM workflow_runs
           ORDER BY created_at DESC
           LIMIT $1 OFFSET $2`,
          [limit, offset]
        );
        return res.rows.map(r => ({
          ...r,
          startTime: r.startTime ? new Date(r.startTime).toISOString() : '',
          endTime: r.endTime ? new Date(r.endTime).toISOString() : undefined,
          createdAt: r.createdAt ? new Date(r.createdAt).toISOString() : undefined
        }));
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getWorkflowRuns error]:', err.message);
      }
    }
    return this.memoryRuns.slice(offset, offset + limit);
  }

  public async getWorkflowRunById(id: string): Promise<WorkflowRunRecord | null> {
    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(
          `SELECT
            id, workflow_id as "workflowId", workflow_name as "workflowName",
            success, duration_ms as "durationMs", start_time as "startTime",
            end_time as "endTime", findings_count as "findingsCount",
            critical_count as "criticalCount", high_count as "highCount",
            medium_count as "mediumCount", low_count as "lowCount",
            result, created_at as "createdAt"
           FROM workflow_runs
           WHERE id = $1`,
          [id]
        );
        if (res.rows.length > 0) {
          const r = res.rows[0];
          return {
            ...r,
            startTime: r.startTime ? new Date(r.startTime).toISOString() : '',
            endTime: r.endTime ? new Date(r.endTime).toISOString() : undefined,
            createdAt: r.createdAt ? new Date(r.createdAt).toISOString() : undefined
          };
        }
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getWorkflowRunById error]:', err.message);
      }
    }
    return this.memoryRuns.find(r => r.id === id) || null;
  }

  // ===========================================================================
  // FINDINGS
  // ===========================================================================

  public async saveFindings(runId: string, findings: Finding[]): Promise<void> {
    // Memory copy
    for (const f of findings) {
      this.memoryFindings.push({ runId, finding: f });
    }
    if (this.memoryFindings.length > 500) {
      this.memoryFindings = this.memoryFindings.slice(-500);
    }

    if (!this.isConnected || !this.pool || findings.length === 0) return;

    try {
      const client = await this.pool.connect();
      try {
        await client.query('BEGIN');
        for (const f of findings) {
          const sca = f.category === 'SCA' ? (f as any) : {};
          const secOrSast = f.category !== 'SCA' ? (f as any) : {};

          await client.query(
            `INSERT INTO findings (
              run_id, category, path, line, end_line, class,
              group_name, artifact, version, advisory_id,
              severity, description, remediation, raw_data
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
            [
              runId,
              f.category,
              f.path,
              secOrSast.line || null,
              secOrSast.endLine || null,
              secOrSast.class || null,
              sca.group || null,
              sca.artifact || null,
              sca.version || null,
              sca.advisoryId || null,
              f.severity || 'MEDIUM',
              f.description || '',
              f.remediation || '',
              JSON.stringify(f)
            ]
          );
        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
    } catch (err: any) {
      console.warn('⚠️ [PostgreSQL saveFindings error]:', err.message);
    }
  }

  public async getFindings(filters: FindingFilter = {}): Promise<Finding[]> {
    if (this.isConnected && this.pool) {
      try {
        const conditions: string[] = [];
        const params: any[] = [];
        let idx = 1;

        if (filters.runId) {
          conditions.push(`run_id = $${idx++}`);
          params.push(filters.runId);
        }
        if (filters.category) {
          conditions.push(`category = $${idx++}`);
          params.push(filters.category.toUpperCase());
        }
        if (filters.severity) {
          conditions.push(`severity = $${idx++}`);
          params.push(filters.severity.toUpperCase());
        }
        if (filters.class) {
          conditions.push(`class = $${idx++}`);
          params.push(filters.class);
        }
        if (filters.search) {
          conditions.push(`(description ILIKE $${idx} OR path ILIKE $${idx} OR class ILIKE $${idx} OR advisory_id ILIKE $${idx})`);
          params.push(`%${filters.search}%`);
          idx++;
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
        const limitClause = filters.limit ? `LIMIT ${filters.limit}` : 'LIMIT 100';
        const offsetClause = filters.offset ? `OFFSET ${filters.offset}` : '';

        const sql = `
          SELECT category, path, line, end_line as "endLine", class,
                 group_name as "group", artifact, version, advisory_id as "advisoryId",
                 severity, description, remediation
          FROM findings
          ${whereClause}
          ORDER BY id ASC
          ${limitClause} ${offsetClause}
        `;

        const res = await this.pool.query(sql, params);
        return res.rows.map(r => {
          const item: any = {
            category: r.category,
            path: r.path,
            severity: r.severity,
            description: r.description,
            remediation: r.remediation
          };
          if (r.category === 'SCA') {
            item.group = r.group;
            item.artifact = r.artifact;
            item.version = r.version;
            item.advisoryId = r.advisoryId;
          } else {
            item.class = r.class;
            item.line = r.line;
            if (r.endLine) item.endLine = r.endLine;
          }
          return item as Finding;
        });
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getFindings error]:', err.message);
      }
    }

    // Memory fallback
    let list = this.memoryFindings.map(mf => mf.finding);
    if (filters.runId) {
      list = this.memoryFindings.filter(mf => mf.runId === filters.runId).map(mf => mf.finding);
    }
    if (filters.category) {
      list = list.filter(f => f.category === filters.category);
    }
    if (filters.severity) {
      list = list.filter(f => f.severity === filters.severity);
    }
    return list.slice(filters.offset || 0, (filters.offset || 0) + (filters.limit || 100));
  }

  public async getFindingsStats(): Promise<FindingStats> {
    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(`
          SELECT
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
            COUNT(*) FILTER (WHERE severity = 'HIGH') as high,
            COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium,
            COUNT(*) FILTER (WHERE severity = 'LOW') as low,
            COUNT(*) FILTER (WHERE category = 'SECRET') as secret_cnt,
            COUNT(*) FILTER (WHERE category = 'SAST') as sast_cnt,
            COUNT(*) FILTER (WHERE category = 'SCA') as sca_cnt
          FROM findings
        `);
        const r = res.rows[0];
        return {
          total: parseInt(r.total, 10) || 0,
          critical: parseInt(r.critical, 10) || 0,
          high: parseInt(r.high, 10) || 0,
          medium: parseInt(r.medium, 10) || 0,
          low: parseInt(r.low, 10) || 0,
          byCategory: {
            SECRET: parseInt(r.secret_cnt, 10) || 0,
            SAST: parseInt(r.sast_cnt, 10) || 0,
            SCA: parseInt(r.sca_cnt, 10) || 0
          }
        };
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getFindingsStats error]:', err.message);
      }
    }

    const all = this.memoryFindings.map(mf => mf.finding);
    return {
      total: all.length,
      critical: all.filter(f => f.severity === 'CRITICAL').length,
      high: all.filter(f => f.severity === 'HIGH').length,
      medium: all.filter(f => f.severity === 'MEDIUM').length,
      low: all.filter(f => f.severity === 'LOW').length,
      byCategory: {
        SECRET: all.filter(f => f.category === 'SECRET').length,
        SAST: all.filter(f => f.category === 'SAST').length,
        SCA: all.filter(f => f.category === 'SCA').length
      }
    };
  }

  // ===========================================================================
  // REPORTS
  // ===========================================================================

  public async saveReport(report: ReportRecord): Promise<number> {
    this.memoryReports.unshift(report);
    if (this.memoryReports.length > 50) this.memoryReports.pop();

    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(
          `INSERT INTO reports (run_id, total_vulnerabilities, summary, json_content, markdown_content)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id`,
          [
            report.runId || null,
            report.totalVulnerabilities,
            JSON.stringify(report.summary),
            JSON.stringify(report.jsonContent),
            report.markdownContent
          ]
        );
        return res.rows[0]?.id || 0;
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL saveReport error]:', err.message);
      }
    }
    return this.memoryReports.length;
  }

  public async getLatestReport(): Promise<ReportRecord | null> {
    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(`
          SELECT id, run_id as "runId", total_vulnerabilities as "totalVulnerabilities",
                 summary, json_content as "jsonContent", markdown_content as "markdownContent",
                 created_at as "createdAt"
          FROM reports
          ORDER BY created_at DESC
          LIMIT 1
        `);
        if (res.rows.length > 0) {
          const r = res.rows[0];
          return {
            id: r.id,
            runId: r.runId,
            totalVulnerabilities: r.totalVulnerabilities,
            summary: r.summary,
            jsonContent: r.jsonContent,
            markdownContent: r.markdownContent,
            createdAt: r.createdAt ? new Date(r.createdAt).toISOString() : undefined
          };
        }
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getLatestReport error]:', err.message);
      }
    }
    return this.memoryReports[0] || null;
  }

  // ===========================================================================
  // TEMPLATES
  // ===========================================================================

  public async saveTemplate(template: WorkflowTemplate, isBuiltin = false, userId = 'default_user', isPublic = false): Promise<void> {
    template.isBuiltin = isBuiltin;
    template.userId = template.userId || userId;
    template.isPublic = template.isPublic !== undefined ? template.isPublic : isPublic;
    this.memoryTemplates.set(template.id, template);

    if (this.isConnected && this.pool) {
      try {
        await this.pool.query(
          `INSERT INTO workflow_templates (id, title, description, category, tags, author, user_id, is_public, is_builtin, graph, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
           ON CONFLICT (id) DO UPDATE SET
             title = EXCLUDED.title,
             description = EXCLUDED.description,
             category = EXCLUDED.category,
             tags = EXCLUDED.tags,
             author = EXCLUDED.author,
             user_id = EXCLUDED.user_id,
             is_public = EXCLUDED.is_public,
             is_builtin = EXCLUDED.is_builtin,
             graph = EXCLUDED.graph,
             updated_at = NOW()`,
          [
            template.id,
            template.title,
            template.description,
            template.category,
            template.tags || [],
            template.author || 'Anonymous',
            template.userId,
            template.isPublic,
            isBuiltin,
            JSON.stringify(template.graph)
          ]
        );
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL saveTemplate error]:', err.message);
      }
    }
  }

  public async getTemplates(userId?: string): Promise<WorkflowTemplate[]> {
    if (this.isConnected && this.pool) {
      try {
        const query = userId
          ? `SELECT id, title, description, category, tags, author, is_builtin, user_id, is_public, graph, created_at, updated_at
             FROM workflow_templates
             WHERE is_builtin = true OR is_public = true OR user_id = $1
             ORDER BY is_builtin DESC, updated_at DESC`
          : `SELECT id, title, description, category, tags, author, is_builtin, user_id, is_public, graph, created_at, updated_at
             FROM workflow_templates
             ORDER BY is_builtin DESC, updated_at DESC`;
        
        const params = userId ? [userId] : [];
        const res = await this.pool.query(query, params);
        if (res.rows.length > 0) {
          return res.rows.map(r => ({
            id: r.id,
            title: r.title,
            description: r.description,
            category: r.category,
            tags: r.tags || [],
            author: r.author || '',
            userId: r.user_id || 'default_user',
            isPublic: Boolean(r.is_public),
            isBuiltin: Boolean(r.is_builtin),
            graph: r.graph,
            createdAt: r.created_at,
            updatedAt: r.updated_at
          }));
        }
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getTemplates error]:', err.message);
      }
    }

    const all = Array.from(this.memoryTemplates.values());
    if (userId) {
      return all.filter(t => t.isBuiltin || t.isPublic || t.userId === userId || t.userId === 'default_user');
    }
    return all;
  }

  public async getTemplateById(id: string): Promise<WorkflowTemplate | null> {
    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(
          `SELECT id, title, description, category, tags, author, is_builtin, user_id, is_public, graph, created_at, updated_at
           FROM workflow_templates
           WHERE id = $1`,
          [id]
        );
        if (res.rows.length > 0) {
          const r = res.rows[0];
          return {
            id: r.id,
            title: r.title,
            description: r.description,
            category: r.category,
            tags: r.tags || [],
            author: r.author,
            userId: r.user_id || 'default_user',
            isPublic: Boolean(r.is_public),
            isBuiltin: Boolean(r.is_builtin),
            graph: r.graph,
            createdAt: r.created_at,
            updatedAt: r.updated_at
          };
        }
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getTemplateById error]:', err.message);
      }
    }
    return this.memoryTemplates.get(id) || null;
  }

  public async deleteTemplate(id: string, userId?: string): Promise<boolean> {
    this.memoryTemplates.delete(id);

    if (this.isConnected && this.pool) {
      try {
        let res;
        if (userId && userId !== 'admin') {
          res = await this.pool.query(
            `DELETE FROM workflow_templates WHERE id = $1 AND is_builtin = false AND (user_id = $2 OR user_id = 'default_user')`,
            [id, userId]
          );
        } else {
          res = await this.pool.query(
            `DELETE FROM workflow_templates WHERE id = $1 AND is_builtin = false`,
            [id]
          );
        }
        return (res.rowCount || 0) > 0;
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL deleteTemplate error]:', err.message);
        return false;
      }
    }
    return true;
  }

  // ===========================================================================
  // SECRETS & VAULT
  // ===========================================================================

  public async saveSecret(key: string, encryptedValue: string, description?: string): Promise<void> {
    this.memorySecrets.set(key, { value: encryptedValue, description });

    if (this.isConnected && this.pool) {
      try {
        await this.pool.query(
          `INSERT INTO vault_secrets (key, encrypted_value, description, updated_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (key) DO UPDATE SET
             encrypted_value = EXCLUDED.encrypted_value,
             description = EXCLUDED.description,
             updated_at = NOW()`,
          [key, encryptedValue, description || null]
        );
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL saveSecret error]:', err.message);
      }
    }
  }

  public async getSecret(key: string): Promise<string | null> {
    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(
          `SELECT encrypted_value FROM vault_secrets WHERE key = $1`,
          [key]
        );
        if (res.rows.length > 0) {
          return res.rows[0].encrypted_value;
        }
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getSecret error]:', err.message);
      }
    }
    return this.memorySecrets.get(key)?.value || null;
  }

  // ===========================================================================
  // HEALTH & DIAGNOSTICS
  // ===========================================================================

  public async getHealth(): Promise<DbHealthStatus> {
    if (!this.isConnected || !this.pool) {
      return {
        connected: false,
        driver: 'memory-fallback',
        counts: {
          runs: this.memoryRuns.length,
          findings: this.memoryFindings.length,
          templates: this.memoryTemplates.size,
          reports: this.memoryReports.length
        }
      };
    }

    try {
      const countsRes = await this.pool.query(`
        SELECT
          (SELECT COUNT(*) FROM workflow_runs) as runs,
          (SELECT COUNT(*) FROM findings) as findings,
          (SELECT COUNT(*) FROM workflow_templates) as templates,
          (SELECT COUNT(*) FROM reports) as reports
      `);
      const counts = countsRes.rows[0];

      return {
        connected: true,
        driver: 'postgres',
        database: process.env.PGDATABASE || 'security_workflow',
        host: process.env.PGHOST || 'localhost',
        port: parseInt(process.env.PGPORT || '5432', 10),
        counts: {
          runs: parseInt(counts.runs, 10),
          findings: parseInt(counts.findings, 10),
          templates: parseInt(counts.templates, 10),
          reports: parseInt(counts.reports, 10)
        }
      };
    } catch (err: any) {
      return {
        connected: false,
        driver: 'postgres',
        error: err.message
      };
    }
  }

  // ===========================================================================
  // USERS & PROFILES (Multi-Tenant, GitHub & GitVerse)
  // ===========================================================================

  public async createUser(data: Omit<UserProfile, 'createdAt' | 'updatedAt'>): Promise<UserProfile> {
    const now = new Date().toISOString();
    const user: UserProfile = {
      ...data,
      createdAt: now,
      updatedAt: now
    };

    if (this.isConnected && this.pool) {
      try {
        await this.pool.query(
          `INSERT INTO users (id, email, password_hash, name, avatar_url, github_id, github_username, github_token, gitverse_username, gitverse_token, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
          [
            user.id,
            user.email,
            user.passwordHash || null,
            user.name,
            user.avatarUrl || null,
            user.githubId || null,
            user.githubUsername || null,
            user.githubToken || null,
            user.gitverseUsername || null,
            user.gitverseToken || null,
            user.createdAt,
            user.updatedAt
          ]
        );
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL createUser error]:', err.message);
      }
    }

    this.memoryUsers.set(user.id, user);
    return user;
  }

  public async getUserById(id: string): Promise<UserProfile | null> {
    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
        if (res.rows.length > 0) {
          return this.mapUserRow(res.rows[0]);
        }
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getUserById error]:', err.message);
      }
    }
    return this.memoryUsers.get(id) || null;
  }

  public async getUserByEmail(email: string): Promise<UserProfile | null> {
    const cleanEmail = email.trim().toLowerCase();
    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(`SELECT * FROM users WHERE LOWER(email) = $1`, [cleanEmail]);
        if (res.rows.length > 0) {
          return this.mapUserRow(res.rows[0]);
        }
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getUserByEmail error]:', err.message);
      }
    }
    for (const u of this.memoryUsers.values()) {
      if (u.email.toLowerCase() === cleanEmail) return u;
    }
    return null;
  }

  public async getUserByGithubId(githubId: string): Promise<UserProfile | null> {
    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(`SELECT * FROM users WHERE github_id = $1`, [String(githubId)]);
        if (res.rows.length > 0) {
          return this.mapUserRow(res.rows[0]);
        }
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getUserByGithubId error]:', err.message);
      }
    }
    for (const u of this.memoryUsers.values()) {
      if (u.githubId === String(githubId)) return u;
    }
    return null;
  }

  public async updateUserProfile(id: string, updates: Partial<UserProfile>): Promise<UserProfile | null> {
    const existing = await this.getUserById(id);
    if (!existing) return null;

    const updated: UserProfile = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString()
    };

    if (this.isConnected && this.pool) {
      try {
        await this.pool.query(
          `UPDATE users SET
             name = COALESCE($1, name),
             email = COALESCE($2, email),
             password_hash = COALESCE($3, password_hash),
             avatar_url = COALESCE($4, avatar_url),
             github_id = COALESCE($5, github_id),
             github_username = COALESCE($6, github_username),
             github_token = COALESCE($7, github_token),
             gitverse_username = COALESCE($8, gitverse_username),
             gitverse_token = COALESCE($9, gitverse_token),
             updated_at = NOW()
           WHERE id = $10`,
          [
            updates.name !== undefined ? updates.name : null,
            updates.email !== undefined ? updates.email.trim().toLowerCase() : null,
            updates.passwordHash !== undefined ? updates.passwordHash : null,
            updates.avatarUrl !== undefined ? updates.avatarUrl : null,
            updates.githubId !== undefined ? updates.githubId : null,
            updates.githubUsername !== undefined ? updates.githubUsername : null,
            updates.githubToken !== undefined ? updates.githubToken : null,
            updates.gitverseUsername !== undefined ? updates.gitverseUsername : null,
            updates.gitverseToken !== undefined ? updates.gitverseToken : null,
            id
          ]
        );
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL updateUserProfile error]:', err.message);
      }
    }

    this.memoryUsers.set(id, updated);
    return updated;
  }

  public async createSession(userId: string): Promise<string> {
    const token = 'sess_' + crypto.randomBytes(32).toString('hex');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();

    const session: UserSession = {
      token,
      userId,
      createdAt: now.toISOString(),
      expiresAt
    };

    if (this.isConnected && this.pool) {
      try {
        await this.pool.query(
          `INSERT INTO user_sessions (token, user_id, created_at, expires_at)
           VALUES ($1, $2, $3, $4)`,
          [session.token, session.userId, session.createdAt, session.expiresAt]
        );
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL createSession error]:', err.message);
      }
    }

    this.memorySessions.set(token, session);
    return token;
  }

  public async getUserBySessionToken(token: string): Promise<UserProfile | null> {
    if (!token) return null;

    if (this.isConnected && this.pool) {
      try {
        const res = await this.pool.query(
          `SELECT u.* FROM users u
           JOIN user_sessions s ON u.id = s.user_id
           WHERE s.token = $1 AND s.expires_at > NOW()`,
          [token]
        );
        if (res.rows.length > 0) {
          return this.mapUserRow(res.rows[0]);
        }
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL getUserBySessionToken error]:', err.message);
      }
    }

    const memSession = this.memorySessions.get(token);
    if (memSession && new Date(memSession.expiresAt) > new Date()) {
      return this.memoryUsers.get(memSession.userId) || null;
    }
    return null;
  }

  public async deleteSession(token: string): Promise<void> {
    if (this.isConnected && this.pool) {
      try {
        await this.pool.query(`DELETE FROM user_sessions WHERE token = $1`, [token]);
      } catch (err: any) {
        console.warn('⚠️ [PostgreSQL deleteSession error]:', err.message);
      }
    }
    this.memorySessions.delete(token);
  }

  private mapUserRow(row: any): UserProfile {
    return {
      id: row.id,
      email: row.email,
      passwordHash: row.password_hash,
      name: row.name,
      avatarUrl: row.avatar_url,
      githubId: row.github_id,
      githubUsername: row.github_username,
      githubToken: row.github_token,
      gitverseUsername: row.gitverse_username,
      gitverseToken: row.gitverse_token,
      createdAt: row.created_at?.toISOString ? row.created_at.toISOString() : String(row.created_at),
      updatedAt: row.updated_at?.toISOString ? row.updated_at.toISOString() : String(row.updated_at)
    };
  }

  public async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
      this.isConnected = false;
    }
  }
}

// Singleton database service instance
export const db = new DatabaseService();
