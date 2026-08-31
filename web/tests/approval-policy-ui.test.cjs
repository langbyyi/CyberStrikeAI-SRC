const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

const hitl = fs.readFileSync('web/static/js/hitl.js', 'utf8');
const approvalUI = fs.existsSync('web/static/js/approval-ui.js')
    ? fs.readFileSync('web/static/js/approval-ui.js', 'utf8')
    : '';
const template = fs.readFileSync('web/templates/index.html', 'utf8');
const styles = fs.readFileSync('web/static/css/style.css', 'utf8');
const rbac = fs.readFileSync('web/static/js/rbac-guards.js', 'utf8');
const approvalHandler = fs.readFileSync('internal/handler/approval.go', 'utf8');
const appRoutes = fs.readFileSync('internal/app/app.go', 'utf8');
const zh = JSON.parse(fs.readFileSync('web/static/i18n/zh-CN.json', 'utf8'));
const en = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8'));
const auth = fs.readFileSync('web/static/js/auth.js', 'utf8');

test('统一审批脚本完成 DOM 初始化且不调用已删除的作用域逻辑', () => {
    let ready;
    const document = {
        addEventListener(name, callback) {
            if (name === 'DOMContentLoaded') ready = callback;
        },
        getElementById() { return null; }
    };
    const window = {
        ApprovalUIModel: {
            createLatestRequestGate() { return {}; }
        },
        addEventListener() {}
    };
    const context = vm.createContext({ window, document, localStorage: { getItem() { return null; } }, console });

    vm.runInContext(approvalUI, context);
    assert.equal(typeof ready, 'function');
    assert.doesNotThrow(() => ready());
});

test('统一审批裁决入口只接受 approval decide 权限且不保留旧守卫', () => {
    assert.doesNotMatch(approvalUI, /data-require-permission-any="approval:decide hitl:write"/);
    assert.match(approvalUI, /data-require-permission="approval:decide"/);
    assert.match(rbac, /submitHitlDecision:\s*'approval:decide'/);
    assert.match(rbac, /submitHitlDecisionWithPayload:\s*'approval:decide'/);
    assert.doesNotMatch(rbac, /saveHitlPageWhitelist|saveHitlAuditStrategy|dismissHitlItem/);
});

test('人机协同页面只以统一审批读取权限作为入口权限', () => {
    assert.match(auth, /hitl:\s*'approval:read'/);
    assert.doesNotMatch(auth, /hitl:\s*\[[^\]]*hitl:read/);
});

test('统一审批配置控件与说明全部使用中英文资源', () => {
    const keys = [
        'policyReviewerLabel', 'reviewerHuman', 'reviewerAgent', 'policyTimeoutLabel',
        'toolWhitelistLabel', 'dangerSharedReviewerNotice', 'ruleGlobalNotice'
    ];
    keys.forEach((key) => {
        assert.equal(typeof zh.hitl[key], 'string', `missing zh hitl.${key}`);
        assert.equal(typeof en.hitl[key], 'string', `missing en hitl.${key}`);
        assert.ok(en.hitl[key].trim(), `empty en hitl.${key}`);
        assert.match(template, new RegExp(`data-i18n="hitl\\.${key}"`));
    });
    assert.equal(zh.hitl.policyIntro, '普通工具审批与危险操作审批相互独立；关闭普通工具审批不会关闭危险操作审批。');
    assert.doesNotMatch(template, /关闭人工审批不会关闭危险操作拦截/);
});

test('审批运行时不再包含旧作用域、策略或参数编辑概念', () => {
    const files = [
        'internal/approval/config.go', 'internal/approval/types.go', 'internal/approval/rules.go',
        'internal/approval/global_runtime.go', 'internal/approval/sqlite_store.go',
        'internal/handler/approval.go', 'internal/handler/hitl_audit_agent.go',
        'web/static/js/approval-ui.js', 'web/static/js/hitl.js', 'web/static/js/monitor.js',
        'web/static/js/settings.js', 'web/templates/index.html', 'config.example.yaml'
    ];
    const removed = /ScopeProject|ScopeConversation|RuntimePolicy|ScopedRule|scopeType|scopeId|review_edit|agent_first|agent_edit|agent_then_human|risk_strategies|shadow_mode|ApprovalEnvelope/;
    files.forEach((file) => assert.doesNotMatch(fs.readFileSync(file, 'utf8'), removed, file));
});

test('全局审批配置仅提供一个审计方式、两个触发开关和共享参数', () => {
	assert.match(template, /id="approval-reviewer"/);
	assert.match(template, /id="approval-reviewer"[^>]+onchange="updateReviewerHint\(this\.value\)"/);
    assert.match(template, /id="approval-tool-enabled"/);
    assert.match(template, /id="approval-danger-enabled"/);
    assert.match(template, /id="approval-tool-whitelist"/);
    assert.match(template, /id="approval-timeout-seconds"/);
    assert.doesNotMatch(template, /id="approval-policy-scope-/);
    assert.doesNotMatch(template, /id="approval-rule-scope-/);
    assert.doesNotMatch(template, /id="approval-(?:tool|danger)-strategy"/);
    assert.doesNotMatch(template, /id="hitl-default-reviewer"/);
    assert.doesNotMatch(template, /id="approval-rule-strategy"/);
    assert.doesNotMatch(template, /id="approval-danger-shadow"/);
    assert.doesNotMatch(template, /id="hitl-(?:tab|panel)-(?:strategy|whitelist)"/);
    assert.doesNotMatch(template, /review_edit|editedArguments/);
    assert.match(approvalUI, /['"]\/api\/approval-config['"]/);
    assert.doesNotMatch(approvalUI, /\/api\/approval-policies/);
    assert.doesNotMatch(hitl, /\/api\/hitl\/(?:tool-whitelist|audit-strategy|decision|dismiss)/);
    assert.doesNotMatch(appRoutes, /protected\.(?:GET|PUT|POST)\("\/hitl\/(?:pending|decision|dismiss|tool-whitelist|audit-strategy)"/);
});

test('危险规则草案使用真实工具名，且不携带已废弃的规则级审批方式', () => {
    assert.match(template, /"tools": \["exec"\]/);
    assert.doesNotMatch(template, /execute_command/);
    assert.doesNotMatch(approvalUI, /execute_command/);
    const publishSource = functionSource(approvalUI, 'publishApprovalRule', 'disableApprovalRule');
    assert.doesNotMatch(publishSource, /reviewer:\s*['"]human['"]/);
});

function functionSource(source, name, nextName) {
    const start = source.indexOf(`function ${name}(`);
    const end = source.indexOf(`function ${nextName}(`, start);
    assert.notEqual(start, -1, `${name} should exist`);
    assert.notEqual(end, -1, `${nextName} should follow ${name}`);
    return source.slice(start, end);
}

test('统一审批模块在模型之后、旧 HITL 之前加载且独占页面处理器', () => {
    const modelIndex = template.indexOf('/static/js/approval-ui-model.js');
    const uiIndex = template.indexOf('/static/js/approval-ui.js');
    const hitlIndex = template.indexOf('/static/js/hitl.js');
    assert.ok(modelIndex >= 0, 'template should load approval-ui-model.js');
    assert.ok(uiIndex > modelIndex, 'approval-ui.js should load after its model');
    assert.ok(hitlIndex > uiIndex, 'hitl.js should load after approval-ui.js');

    [
        'loadApprovalPolicies', 'saveApprovalPolicies', 'loadApprovalRules',
        'publishApprovalRule', 'disableApprovalRule', 'refreshHitlPending',
        'renderHitlPendingList', 'refreshHitlLogs', 'renderHitlLogsTable',
        'openHitlLogModal', 'submitHitlDecision', 'submitHitlDecisionWithPayload'
    ].forEach((name) => {
        assert.doesNotMatch(hitl, new RegExp(`function\\s+${name}\\s*\\(`), `${name} should leave hitl.js`);
    });
    [
        'refreshHitlPending', 'refreshHitlLogs', 'saveApprovalPolicies',
        'publishApprovalRule', 'disableApprovalRule', 'submitHitlDecision'
    ].forEach((name) => {
        assert.match(approvalUI, new RegExp(`window\\.${name}\\s*=\\s*${name}`), `${name} should be exported by approval-ui.js`);
    });
});

test('待审批页使用模型构建统一队列的服务器搜索和分页', () => {
    const querySource = functionSource(approvalUI, 'pendingQueryKey', 'submitHitlDecision');
    const refreshSource = functionSource(approvalUI, 'refreshHitlPending', 'filterHitlPending');
    assert.match(querySource, /ApprovalUIModel\.buildApprovalQuery/);
    assert.match(querySource, /status:\s*'pending_human'/);
    assert.match(querySource, /q:\s*pendingSearchValue\(\)/);
    assert.match(querySource, /limit:\s*hitlPendingPageSize/);
    assert.match(querySource, /offset:\s*\(hitlPendingPage\s*-\s*1\)\s*\*\s*hitlPendingPageSize/);
    assert.match(refreshSource, /hitlPendingTotal\s*=\s*Number\.isFinite\(data\.total\)\s*\?\s*data\.total/);
    assert.doesNotMatch(refreshSource, /\.filter\s*\(/);
    assert.doesNotMatch(refreshSource, /\.slice\s*\(/);
    assert.doesNotMatch(refreshSource, /\/api\/hitl\/pending|\/api\/workflows\/runs\/pending/);
});

test('待审批和审计仅应用仍是当前查询的最新响应', () => {
    const pendingSource = functionSource(approvalUI, 'refreshHitlPending', 'filterHitlPending');
    const auditSource = functionSource(approvalUI, 'refreshHitlLogs', 'filterHitlLogs');
    [pendingSource, auditSource].forEach((source) => {
        assert.match(source, /RequestGate\.begin\(query\)/);
        assert.match(source, /RequestGate\.isCurrent\(requestToken\)/);
        assert.equal((source.match(/RequestGate\.isCurrent\(requestToken\)/g) || []).length, 2, 'success and failure paths must both be gated');
    });
    assert.match(pendingSource, /const query = pendingQueryKey\(\)/);
    assert.match(auditSource, /const query = auditQueryKey\(\)/);
    assert.match(approvalUI, /ApprovalUIModel\.createLatestRequestGate\(\)/);
});

test('统一审批卡片展示已国际化的触发源、风险和审批阶段', () => {
    const source = functionSource(approvalUI, 'renderHitlPendingList', 'refreshHitlPending');
    assert.match(source, /triggerSources/);
    assert.match(source, /riskLevel/);
    assert.match(source, /reviewer/);
    assert.match(source, /approval-custody-rail/);
    assert.match(source, /hitlT\('custodyPolicy'/);
    assert.match(source, /hitlT\('custodyAgent'/);
    assert.match(source, /hitlT\('custodyHuman'/);
    assert.match(source, /hitlT\('custodyExecute'/);
    assert.doesNotMatch(source, /aria-label="审批链路"|>Policy<|>Agent<|>Human<|>Execute</);
});

test('全局策略加载防止旧响应覆盖新响应', () => {
    const source = functionSource(approvalUI, 'loadApprovalPolicies', 'saveApprovalPolicies');
    assert.match(source, /\/api\/approval-config/);
    assert.match(source, /\+\+approvalPolicyLoadSequence/);
    assert.match(source, /sequence\s*!==\s*approvalPolicyLoadSequence/);
    assert.match(source, /setApprovalPolicySaveEnabled\(false\)/);
    assert.match(source, /setApprovalPolicySaveEnabled\(true\)/);
});
test('全局策略一次保存共享审计方式和两个触发开关', () => {
    const source = functionSource(approvalUI, 'saveApprovalPolicies', 'renderApprovalRules').split('function approvalScopeLabel')[0];
    assert.match(source, /\/api\/approval-config/);
    assert.match(source, /method:\s*'PUT'/);
    assert.match(source, /reviewer:/);
    assert.match(source, /toolApproval:/);
    assert.match(source, /dangerousAction:/);
    assert.match(source, /toolWhitelist:/);
    assert.doesNotMatch(source, /scope|shadowMode|defaultStrategy|agent_edit/);
});

test('策略开关有可访问名称且所有统一策略与规则写操作只要求 policy write', () => {
    assert.match(template, /id="approval-tool-enabled"[^>]+aria-label="[^"]+"/);
    assert.match(template, /id="approval-danger-enabled"[^>]+aria-label="[^"]+"/);
    assert.match(template, /id="approval-policy-save"[^>]+data-require-permission="approval:policy:write"/);
    assert.match(template, /id="approval-rule-publish"[^>]+data-require-permission="approval:policy:write"/);
    assert.doesNotMatch(template, /id="approval-(?:policy-save|rule-publish)"[^>]+data-require-permission-any/);
    assert.match(rbac, /saveApprovalPolicies:\s*'approval:policy:write'/);
    assert.match(rbac, /publishApprovalRule:\s*'approval:policy:write'/);
    assert.match(rbac, /disableApprovalRule:\s*'approval:policy:write'/);
    assert.match(rbac, /deleteApprovalRule:\s*'approval:policy:write'/);
    assert.doesNotMatch(rbac, /viewApprovalRule:\s*'/);
});

test('全局规则卡不再携带作用域，停用确认仅标识规则', () => {
    const renderSource = functionSource(approvalUI, 'renderApprovalRules', 'loadApprovalRules');
    const disableSource = functionSource(approvalUI, 'disableApprovalRule', 'renderHitlPendingList');
    assert.doesNotMatch(renderSource, /scopeType|scopeId|approvalScopeLabel/);
    assert.match(renderSource, /rule\.enabled/);
    assert.match(renderSource, /hitlT\('ruleEnabled'/);
    assert.match(renderSource, /hitlT\('ruleDisabled'/);
    assert.match(disableSource, /confirm\(/);
    assert.match(disableSource, /rule\.id/);
    assert.doesNotMatch(disableSource, /scopeType|scopeId|approvalScopeLabel/);
});

test('审计列表将评审决策和执行状态作为独立列并完全由服务器分页', () => {
    const querySource = functionSource(approvalUI, 'auditQueryKey', 'hitlFormatPayloadForDisplay');
    const refreshSource = functionSource(approvalUI, 'refreshHitlLogs', 'filterHitlLogs');
    const renderSource = functionSource(approvalUI, 'renderHitlLogsTable', 'refreshHitlLogs');
    assert.match(querySource, /ApprovalUIModel\.buildApprovalQuery/);
    assert.match(querySource, /terminal:\s*true/);
    assert.match(querySource, /q:\s*auditSearchValue\(\)/);
    assert.match(querySource, /decision:\s*auditDecisionValue\(\)/);
    assert.match(querySource, /actorType:\s*auditActorTypeValue\(\)/);
    assert.match(querySource, /limit:\s*hitlLogsPageSize/);
    assert.match(querySource, /offset:\s*\(hitlLogsPage\s*-\s*1\)\s*\*\s*hitlLogsPageSize/);
    assert.match(refreshSource, /hitlLogsTotal\s*=\s*Number\.isFinite\(data\.total\)\s*\?\s*data\.total/);
    assert.doesNotMatch(refreshSource, /\.filter\s*\(|\.slice\s*\(/);
    assert.match(renderSource, /ApprovalUIModel\.toAuditView/);
    assert.match(renderSource, /hitlT\('colReviewDecision'/);
    assert.match(renderSource, /hitlT\('colExecutionStatus'/);
});

test('审计 actorType 选项与后端允许的 human、agent、system 枚举一致', () => {
    const actorFilterStart = template.indexOf('id="hitl-logs-decidedby-filter"');
    const actorFilterEnd = template.indexOf('</select>', actorFilterStart);
    const actorFilter = template.slice(actorFilterStart, actorFilterEnd);
    assert.ok(actorFilterStart >= 0 && actorFilterEnd > actorFilterStart, 'actor filter should exist');
    assert.match(actorFilter, /value="human"/);
    assert.match(actorFilter, /value="agent"/);
    assert.match(actorFilter, /value="system"/);
    assert.doesNotMatch(actorFilter, /value="manual"/);
    assert.doesNotMatch(approvalUI, /manual:\s*'reviewerManual'/);
    assert.match(approvalHandler, /filter\.ActorType != "" && filter\.ActorType != "human" && filter\.ActorType != "agent" && filter\.ActorType != "system"/);
});

test('审计详情展示按时序排列的决定链、命中策略、风险触发和执行摘要', () => {
    assert.match(template, /id="hitl-log-decision-chain"/);
    assert.match(template, /data-i18n="hitl\.decisionChain"/);
    const source = functionSource(approvalUI, 'openHitlLogModal', 'closeHitlLogModal');
    assert.match(source, /ApprovalUIModel\.toAuditView/);
    assert.match(source, /view\.decisions/);
    assert.match(source, /decision\.stage/);
    assert.match(source, /decision\.actorType/);
    assert.match(source, /decision\.actorId/);
    assert.match(source, /decision\.decision/);
    assert.match(source, /decision\.comment/);
    assert.match(source, /decision\.createdAt/);
    assert.match(source, /view\.matchedPolicies/);
    assert.match(source, /request\.riskLevel/);
    assert.match(source, /request\.triggerSources/);
    assert.match(source, /view\.executionStatus/);
    assert.match(source, /view\.executionSummary/);
});

test('没有评审决定时显示空态，失败过期取消不会伪造成拒绝', () => {
    assert.match(approvalUI, /hitlT\('noReviewDecision'/);
    assert.doesNotMatch(approvalUI, /\['rejected',\s*'expired',\s*'cancelled',\s*'failed'\][\s\S]{0,160}reject/);
    assert.doesNotMatch(approvalUI, /status\s*===?\s*['"]failed['"][\s\S]{0,100}reject/);
    assert.doesNotMatch(approvalUI, /status\s*===?\s*['"]expired['"][\s\S]{0,100}reject/);
    assert.doesNotMatch(approvalUI, /status\s*===?\s*['"]cancelled['"][\s\S]{0,100}reject/);
});

test('工作流待审批和统一日志删除死流程从模板、脚本与权限映射中移除', () => {
    const deadNames = [
        'renderWorkflowHitlPendingList', 'submitWorkflowHitlDecisionFromPage',
        'batchDeleteHitlLogs', 'clearHitlLogs', 'selectAllHitlLogs',
        'deselectAllHitlLogs', 'toggleHitlLogSelection', 'toggleHitlLogsSelectAll'
    ];
    deadNames.forEach((name) => {
        assert.doesNotMatch(hitl, new RegExp(name));
        assert.doesNotMatch(approvalUI, new RegExp(name));
        assert.doesNotMatch(rbac, new RegExp(name));
    });
    assert.doesNotMatch(template, /workflow-hitl-pending|hitl-logs-select-all|hitl-logs-batch-actions|hitl-logs-selected-count/);
});

test('统一审批新增文案在中英文资源中完整对应', () => {
    const keys = [
        'policyLoadFailed', 'policySaveFailed',
        'ruleMatcherRequired', 'ruleMatcherInvalid',
        'ruleLoadFailed', 'rulePublishFailed', 'ruleDisableFailed',
        'ruleDisableConfirm', 'ruleEnabled', 'ruleDisabled', 'rulesEmpty',
        'custodyLabel', 'custodyPolicy', 'custodyAgent', 'custodyHuman', 'custodyExecute',
        'colReviewDecision', 'colExecutionStatus', 'noReviewDecision',
        'decisionChain', 'decisionPhase', 'decisionActor', 'matchedRules',
        'riskLevel', 'triggerSources', 'executionSummary', 'notAvailable'
    ];
    keys.forEach((key) => {
        assert.equal(typeof zh.hitl[key], 'string', `missing zh hitl.${key}`);
        assert.equal(typeof en.hitl[key], 'string', `missing en hitl.${key}`);
        assert.ok(en.hitl[key].trim(), `empty en hitl.${key}`);
    });
    assert.match(styles, /\.approval-decision-chain/);
});

test('保存成功提示必须以重新加载成功为前提，重载失败不得显示成功', () => {
    const source = functionSource(approvalUI, 'saveApprovalPolicies', 'renderApprovalRules');
    assert.match(source, /const\s+reloaded\s*=\s*await\s+loadApprovalPolicies\(\)/);
    assert.match(source, /if\s*\(reloaded\)/);
    assert.doesNotMatch(source, /if\s*\(!reloaded\)[\s\S]*policySaved/);
});

test('409 对账按状态码分支，不依赖后端错误文案', () => {
    const source = functionSource(approvalUI, 'submitHitlDecision', 'hitlParsePayloadObject');
    assert.match(source, /response\.status\s*===\s*409/);
    assert.doesNotMatch(source, /already\s+resolved/);
    assert.doesNotMatch(source, /indexOf\('not\s+found'\)/);
});

test('规则卡为所有规则提供查看/编辑入口，删除不再有内置限制', () => {
    const renderSource = functionSource(approvalUI, 'renderApprovalRules', 'viewApprovalRule');
    assert.match(renderSource, /onclick="viewApprovalRule\(/);
    assert.match(renderSource, /onclick="editApprovalRule\(/);
    assert.match(renderSource, /onclick="deleteApprovalRule\(/);
    assert.doesNotMatch(renderSource, /locked/);
    assert.doesNotMatch(renderSource, /builtin/);
    assert.match(approvalUI, /window\.viewApprovalRule\s*=\s*viewApprovalRule/);
    assert.match(approvalUI, /window\.deleteApprovalRule\s*=\s*deleteApprovalRule/);
});

test('内置与版本概念已退役：卡片无内置/锁定/修订标识，删除守卫被移除', () => {
    const renderSource = functionSource(approvalUI, 'renderApprovalRules', 'viewApprovalRule');
    const deleteSource = functionSource(approvalUI, 'deleteApprovalRule', 'approvalRiskLabel');
    assert.doesNotMatch(renderSource, /builtinRuleTag|ruleOverrideTag|builtinLocked|approval-rule-revision|is-locked/);
    assert.doesNotMatch(deleteSource, /ruleBuiltinDeleteDenied|rule\.builtin|rule\.locked/);
});

test('规则查看详情走模型只读视图并渲染匹配器 JSON', () => {
    const viewSource = functionSource(approvalUI, 'viewApprovalRule', 'loadApprovalRules');
    assert.match(viewSource, /ApprovalUIModel\.toRuleView/);
    assert.match(viewSource, /approval-rule-view-modal/);
    assert.match(viewSource, /view\.matcherJson/);
    assert.match(template, /id="approval-rule-view-modal"/);
    assert.match(approvalUI, /window\.closeApprovalRuleViewModal\s*=\s*closeApprovalRuleViewModal/);
});

test('删除规则带确认并调用 DELETE 端点后重载', () => {
    const deleteSource = functionSource(approvalUI, 'deleteApprovalRule', 'approvalRiskLabel');
    assert.match(deleteSource, /confirm\(/);
    assert.match(deleteSource, /method:\s*'DELETE'/);
    assert.match(deleteSource, /\/api\/approval-rules/);
    assert.match(deleteSource, /await\s+loadApprovalRules\(\)/);
    assert.match(deleteSource, /ruleDeleteConfirm/);
    assert.match(deleteSource, /ruleDeleteFailed/);
});

test('规则查看与删除文案在中英文资源中完整对应', () => {
    const keys = ['ruleView', 'ruleViewTitle', 'ruleViewStatus', 'ruleDelete', 'ruleDeleteConfirm', 'ruleDeleteFailed'];
    keys.forEach((key) => {
        assert.equal(typeof zh.hitl[key], 'string', `missing zh hitl.${key}`);
        assert.equal(typeof en.hitl[key], 'string', `missing en hitl.${key}`);
        assert.ok(en.hitl[key].trim(), `empty en hitl.${key}`);
    });
});

test('审批策略页提供审计方式动态说明、规则计数与保存 loading 态', () => {
    // policySaving 与 ruleCountLine 由 JS 动态设置，仅需 i18n 资源存在
    for (const key of ['reviewerHintHuman', 'reviewerHintAgent', 'gotoRulesTab', 'policySaving', 'ruleCountLine']) {
        assert.equal(typeof zh.hitl[key], 'string', `missing zh hitl.${key}`);
        assert.equal(typeof en.hitl[key], 'string', `missing en hitl.${key}`);
    }
    for (const key of ['reviewerHintHuman', 'reviewerHintAgent', 'gotoRulesTab']) {
        assert.match(template, new RegExp(`data-i18n="hitl\\.${key}"`));
    }
    // ruleCountLine 由 JS 带参数插值设置，不走 data-i18n
    assert.match(approvalUI, /ruleCountLine/);
    assert.doesNotMatch(template, /toolWhitelistHint/);
    assert.match(template, /id="approval-reviewer-hint-human"/);
    assert.match(template, /id="approval-reviewer-hint-agent"/);
    assert.match(template, /id="approval-danger-rule-count"/);
    const ui = approvalUI;
    assert.match(ui, /function updateReviewerHint/);
    assert.match(ui, /function refreshDangerRuleCount/);
    assert.match(ui, /refreshDangerRuleCount\(\)/);
    assert.match(ui, /policySaving/);
    const loadSource = functionSource(ui, 'loadApprovalPolicies', 'saveApprovalPolicies');
    assert.match(loadSource, /refreshDangerRuleCount\(\)/);
});

test('审计日志摘要列有界且不再展示执行输出原文', () => {
    const summarySource = functionSource(approvalUI, 'buildApprovalSummary', 'approvalDecisionLabel');
    assert.match(summarySource, /args\.command/);
    assert.match(summarySource, /args\.url/);
    assert.match(summarySource, /slice\(0, 140\)/);
    const renderSource = functionSource(approvalUI, 'renderHitlLogsTable', 'refreshHitlLogs');
    assert.match(renderSource, /buildApprovalSummary\(request\)/);
    assert.match(renderSource, /title=/);
    assert.doesNotMatch(renderSource, /view\.executionSummary \|\| payloadSummary/);
    assert.match(approvalUI, /ensureHitlPendingAutoRefresh/);
});

test('保存与修改操作成功失败均有弹窗提示（效仿系统设置页 alert 模式）', () => {
    const saveSource = functionSource(approvalUI, 'saveApprovalPolicies', 'renderApprovalRules');
    assert.match(saveSource, /if\s*\(reloaded\)\s*\{[\s\S]*?alert\(savedMsg\)/);
    assert.match(saveSource, /alert\(failMsg\)/);
    const publishSource = functionSource(approvalUI, 'publishApprovalRule', 'disableApprovalRule');
    assert.match(publishSource, /alert\(publishedMsg\)/);
    const disableSource = functionSource(approvalUI, 'disableApprovalRule', 'approvalRiskLabel');
    assert.match(disableSource, /alert\(disabledMsg\)/);
    const deleteSource = functionSource(approvalUI, 'deleteApprovalRule', 'approvalRiskLabel');
    assert.match(deleteSource, /alert\(deletedMsg\)/);
    const decisionSource = functionSource(approvalUI, 'submitHitlDecisionWithPayload', 'hitlParsePayloadObject');
    assert.match(decisionSource, /decisionConflict/);
    assert.match(approvalUI, /ensureHitlPendingAutoRefresh\(\)/);
    assert.match(approvalUI, /setInterval/);
    assert.match(approvalUI, /document\.hidden/);
});

test('点击规则卡片直接载入右侧编辑器，卡片按钮点击不重复触发', () => {
    const renderSource = functionSource(approvalUI, 'renderApprovalRules', 'viewApprovalRule');
    assert.match(renderSource, /onclick="ruleCardClick\(event, '/);
    const clickSource = functionSource(approvalUI, 'ruleCardClick', 'resetApprovalRuleEditor');
    assert.match(clickSource, /closest\('button'\)/);
    assert.match(clickSource, /editApprovalRule\(index\)/);
    const editSource = functionSource(approvalUI, 'editApprovalRule', 'postApprovalRule');
    assert.match(editSource, /is-selected/);
    assert.match(approvalUI, /window\.ruleCardClick\s*=\s*ruleCardClick/);
});
