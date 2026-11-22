"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.WorkspaceState = void 0;
const vscode = __importStar(require("vscode"));
class WorkspaceState {
    static _instance;
    _context;
    _findings = [];
    _summary = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    _selectedFinding;
    _lastScenarioId = 'template-full-audit';
    _lastScenarioTitle = 'Комплексный аудит безопасности';
    _templates = [];
    _onFindingsUpdated = new vscode.EventEmitter();
    onFindingsUpdated = this._onFindingsUpdated.event;
    _onSelectedFindingChanged = new vscode.EventEmitter();
    onSelectedFindingChanged = this._onSelectedFindingChanged.event;
    static getInstance() {
        if (!WorkspaceState._instance) {
            WorkspaceState._instance = new WorkspaceState();
        }
        return WorkspaceState._instance;
    }
    init(context) {
        this._context = context;
        this._lastScenarioId = context.workspaceState.get('uncflow.lastScenarioId', 'template-full-audit');
        this._lastScenarioTitle = context.workspaceState.get('uncflow.lastScenarioTitle', 'Комплексный аудит безопасности');
    }
    get lastScenarioId() {
        return this._lastScenarioId;
    }
    get lastScenarioTitle() {
        return this._lastScenarioTitle;
    }
    async setLastScenario(id, title) {
        this._lastScenarioId = id;
        if (title)
            this._lastScenarioTitle = title;
        if (this._context) {
            await this._context.workspaceState.update('uncflow.lastScenarioId', id);
            if (title) {
                await this._context.workspaceState.update('uncflow.lastScenarioTitle', title);
            }
        }
    }
    get findings() {
        return this._findings;
    }
    get summary() {
        return this._summary;
    }
    setFindings(findings, summary) {
        this._findings = findings;
        if (summary) {
            this._summary = summary;
        }
        else {
            const crit = findings.filter(f => f.severity === 'CRITICAL').length;
            const high = findings.filter(f => f.severity === 'HIGH').length;
            const med = findings.filter(f => f.severity === 'MEDIUM').length;
            const low = findings.filter(f => f.severity === 'LOW' || f.severity === 'INFO').length;
            this._summary = {
                critical: crit,
                high: high,
                medium: med,
                low: low,
                total: findings.length
            };
        }
        this._selectedFinding = findings.length > 0 ? findings[0] : undefined;
        this._onFindingsUpdated.fire(this._findings);
        this._onSelectedFindingChanged.fire(this._selectedFinding);
    }
    clearFindings() {
        this._findings = [];
        this._summary = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
        this._selectedFinding = undefined;
        this._onFindingsUpdated.fire([]);
        this._onSelectedFindingChanged.fire(undefined);
    }
    get selectedFinding() {
        return this._selectedFinding;
    }
    setSelectedFinding(finding) {
        this._selectedFinding = finding;
        this._onSelectedFindingChanged.fire(finding);
    }
    get templates() {
        return this._templates;
    }
    setTemplates(templates) {
        this._templates = templates;
    }
}
exports.WorkspaceState = WorkspaceState;
//# sourceMappingURL=workspace.js.map