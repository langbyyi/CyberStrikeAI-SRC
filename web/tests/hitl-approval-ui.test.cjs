const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const ApprovalUIModel = require('../static/js/approval-ui-model.js');

const monitor = fs.readFileSync('web/static/js/monitor.js', 'utf8');
const chatScroll = fs.readFileSync('web/static/js/chat-scroll.js', 'utf8');
const projects = fs.readFileSync('web/static/js/projects.js', 'utf8');
const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');
const approvalUI = fs.readFileSync('web/static/js/approval-ui.js', 'utf8');
const settings = fs.readFileSync('web/static/js/settings.js', 'utf8');
const approvalAdapters = fs.readFileSync('internal/handler/approval_adapters.go', 'utf8');
const approvalHandler = fs.readFileSync('internal/handler/approval.go', 'utf8');
const styles = fs.readFileSync('web/static/css/style.css', 'utf8');
const template = fs.readFileSync('web/templates/index.html', 'utf8');
const handler = fs.existsSync('internal/handler/hitl.go') ? fs.readFileSync('internal/handler/hitl.go', 'utf8') : '';
const zh = JSON.parse(fs.readFileSync('web/static/i18n/zh-CN.json', 'utf8'));
const en = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8'));

test('超长人工审批内容在限高区域内滚动且操作按钮始终可见', () => {
    assert.match(styles, /\.chat-hitl-approval-dock \{[\s\S]*?max-height: min\(62dvh, 560px\);[\s\S]*?padding: 18px 20px 74px;[\s\S]*?overflow: hidden;/);
    assert.match(styles, /\.chat-hitl-approval-scroll-region \{[\s\S]*?max-height: max\(76px, calc\(min\(62dvh, 560px\) - 94px\)\);[\s\S]*?overflow-y: auto;[\s\S]*?overscroll-behavior: contain;/);
    assert.match(styles, /\.chat-hitl-approval-dock \.hitl-edit-args \{[\s\S]*?max-height: min\(28dvh, 220px\);[\s\S]*?overflow: auto;/);
    assert.match(styles, /\.chat-hitl-approval-dock \.hitl-inline-actions \{[\s\S]*?position: absolute;[\s\S]*?bottom: 16px;[\s\S]*?box-shadow: none;/);
    assert.match(styles, /\.chat-hitl-approval-dock \.hitl-approval-heading h3 \{[\s\S]*?-webkit-line-clamp: 3;/);
    assert.match(monitor, /function wrapChatHitlApprovalScrollRegion\(dock\)/);
    assert.match(monitor, /while \(dock\.firstChild && dock\.firstChild !== actions\)/);
    assert.match(monitor, /wrapChatHitlApprovalScrollRegion\(dock\);/);
    assert.match(monitor, /url\.length > 160[\s\S]*?requestVisitLongUrl/);
    assert.equal(zh.hitl.requestVisitLongUrl, '允许 CyberStrikeAI 访问此地址？');
    assert.equal(en.hitl.requestVisitLongUrl, 'Allow CyberStrikeAI to visit this address?');
});

test('输入框可按会话通道获取模型并双向同步会话推理且审批模型只出现在审计 Agent 入口', () => {
    assert.match(chat, /function currentSystemModelLabel\(\)/);
    assert.match(chat, /chatDefaultAIChannel \? chatAIChannels\[chatDefaultAIChannel\]/);
    assert.match(chat, /const label = currentChatModelLabel\(\)/);
    assert.doesNotMatch(chat, /const label = data\.model \|\| currentChatModelLabel\(\)/);
    assert.match(template, /id="chat-model-shortcut"[^>]+onclick="openChatSystemModelPicker\(event\)"/);
    assert.match(template, /id="chat-system-model-menu"[^>]+hidden/);
    assert.doesNotMatch(template, /id="chat-reasoning-shortcut"/);
    assert.doesNotMatch(template, /session-settings-group-ai/);
    assert.match(template, /class="chat-ai-session-state" hidden[\s\S]{0,500}id="chat-ai-channel-select"/);
    assert.match(template, /openChatSystemModelView\('channel', event\)[\s\S]{0,1200}openChatSystemModelView\('model', event\)[\s\S]{0,1200}openChatSystemModelView\('mode', event\)[\s\S]{0,1200}openChatSystemModelView\('effort', event\)/);
    assert.match(chat, /function renderChatReasoningEffortOptions\(\)/);
    assert.match(chat, /function renderChatReasoningModeOptions\(\)/);
    assert.match(chat, /case 'low': return 'low'[\s\S]{0,300}case 'max': return 'max'/);
    assert.match(chat, /chatTranslate\('chat\.reasoningEffortUnset', '不指定'\)/);
    assert.match(chat, /\['default', 'off', 'on', 'auto'\]/);
    assert.match(chat, /\['', 'low', 'medium', 'high', 'xhigh', 'max'\]/);
    assert.match(chat, /function selectChatReasoningMode\(mode\)[\s\S]{0,700}modeControl\.value = chosen[\s\S]{0,200}finishChatReasoningPickerUpdate\(\)/);
    assert.match(chat, /function selectChatReasoningEffort\(effort\)[\s\S]{0,700}effortControl\.value = chosen[\s\S]{0,200}finishChatReasoningPickerUpdate\(\)/);
    assert.match(chat, /function fetchChatSystemModelsForChannel\(channelId, options\)[\s\S]{0,4200}apiFetch\('\/api\/config\/list-models'/);
    assert.match(chat, /function selectChatAIChannel\(channelId\)[\s\S]{0,900}fetchChatSystemModelsForChannel\(resolveChatPickerChannelId\(\), \{ force: true \}\)/);
    assert.match(chat, /const chatSystemModelCache = new Map\(\)/);
    assert.match(chat, /Date\.now\(\) - cached\.fetchedAt < CHAT_SYSTEM_MODEL_CACHE_TTL_MS/);
    assert.match(chat, /function selectChatSystemModel\(model\)[\s\S]{0,2600}method: 'PUT'[\s\S]{0,900}apiFetch\('\/api\/config\/apply'/);
    assert.match(chat, /body: JSON\.stringify\(\{ ai: state\.ai \}\)/);
    assert.equal(zh.chat.modelSettingsAria, '选择 AI 通道、模型与推理设置');
    assert.equal(en.chat.modelSettingsAria, 'Choose AI channel, model, and reasoning settings');
    assert.equal(zh.chat.reasoningSessionUpdated, '会话推理设置已更新');
    assert.equal(en.chat.reasoningSessionUpdated, 'Session reasoning updated');
});

test('审批请求按浏览器、命令、文件和通用工具动态描述', () => {
    assert.match(monitor, /function hitlApprovalTemplate/);
    assert.match(monitor, /hitlApprovalTranslate\(key, fallback\)/);
    assert.match(monitor, /replaceAll\('\{\{' \+ name \+ '\}\}'/);
    assert.match(monitor, /function describeHitlApprovalRequest/);
    assert.match(monitor, /requestVisitUrl/);
    assert.match(monitor, /requestCommand/);
    assert.match(monitor, /requestFile/);
    assert.match(monitor, /requestGeneric/);
    assert.match(monitor, /let displayTool = rawToolName/);
    assert.doesNotMatch(monitor, /displayTool = 'Browser'/);
    assert.doesNotMatch(monitor, /displayTool = hitlApprovalTranslate\('hitl\.toolTerminal'/);
    assert.doesNotMatch(monitor, /displayTool = hitlApprovalTranslate\('hitl\.toolFiles'/);
});

test('统一审批不再创建旧 HITL 运行时待审批记录', () => {
    assert.equal(handler, '');
    assert.doesNotMatch(approvalUI, /\/api\/hitl\/pending|\/api\/hitl\/decision/);
    assert.match(projects, /filter\(isHumanProjectPendingApproval\)/);
    assert.match(projects, /if \(!isHumanProjectPendingApproval\(details\)\) return/);
    assert.match(approvalUI, /status: 'pending_human'/);
});

test('人工批准不要求输入备注且不提供参数改写', () => {
    assert.match(monitor, /if \(!approveBtn \|\| !rejectBtn \|\| !statusEl\) return/);
    assert.doesNotMatch(monitor, /!commentInput \|\| !statusEl/);
    assert.doesNotMatch(approvalUI, /editedArguments|hitl-edit-/);
});

test('长历史对话的回到最新按钮不会把滚动点击穿透到审批操作', () => {
    assert.match(chatScroll, /function isolateReturnLatestPointerEvent\(event\)/);
    assert.match(chatScroll, /returnLatestButton\.addEventListener\('pointerdown', isolateReturnLatestPointerEvent\)/);
    assert.match(chatScroll, /function onReturnLatestClick\(event\)[\s\S]{0,260}event\.preventDefault\(\)[\s\S]{0,180}event\.stopPropagation\(\)/);
    assert.match(monitor, /const bindExplicitHitlAction = function \(button, decision\)/);
    assert.match(monitor, /button\.addEventListener\('pointerdown'[\s\S]{0,900}pointerClick && !explicitlyPressed/);
    assert.match(monitor, /bindExplicitHitlAction\(approveBtn, 'approve'\)/);
    assert.match(monitor, /bindExplicitHitlAction\(rejectBtn, 'reject'\)/);
});

test('轮次导航使用连续大热区并允许鼠标平滑进入 Codex 风格预览卡', () => {
    const styles = fs.readFileSync('web/static/css/style.css', 'utf8');
    assert.match(styles, /\.chat-turn-rail-markers \{[\s\S]{0,260}gap: 0;/);
    assert.match(styles, /\.chat-turn-rail-markers \{[\s\S]{0,420}overflow-x: hidden;/);
    assert.match(styles, /\.chat-turn-rail-markers \{[\s\S]{0,520}touch-action: pan-y;/);
    assert.match(styles, /\.chat-turn-rail-marker \{[\s\S]{0,260}width: 36px;[\s\S]{0,160}height: 11px;/);
    assert.match(styles, /\.chat-turn-rail-marker::before \{[\s\S]{0,420}width: 12px;[\s\S]{0,120}height: 3px;/);
    assert.match(styles, /\.chat-turn-rail-marker:hover::before \{[\s\S]{0,100}width: 22px;/);
    assert.match(styles, /\.chat-turn-rail-preview \{[\s\S]{0,520}pointer-events: auto;/);
    assert.match(chatScroll, /function scheduleHideTurnPreview\(\)/);
    assert.match(chatScroll, /window\.setTimeout\(hideTurnPreview, 160\)/);
    assert.match(chatScroll, /turnPreview\.addEventListener\('mouseenter'/);
    assert.match(chatScroll, /marker\.addEventListener\('mouseleave', scheduleHideTurnPreview\)/);
});

test('倒计时由服务端时间驱动，到期时只锁定界面并等待服务端拒绝', () => {
    // Phase 2b 旧 HITL 运行时退役：服务端倒计时字段随 waitHITLApproval 删除，
    // 旧卡片仅在历史记录渲染时出现；统一审批的倒计时由 approval-ui 承接。
    assert.doesNotMatch(handler, /waitHITLApproval/);
    assert.match(monitor, /function bindHitlApprovalCountdown/);
    assert.match(monitor, /setInterval\(update, 250\)/);
    assert.match(monitor, /expiredAutoRejected/);
    assert.doesNotMatch(monitor, /remaining <= 0[\s\S]{0,240}submitHitlDecisionWithPayload/);
});

test('项目对话列表能同时显示等待批准与运行状态', () => {
    assert.match(projects, /pendingApprovalByConversation: new Map/);
    assert.match(projects, /statusKinds\.push\('approval'\)/);
    assert.match(projects, /statusKinds\.push\('running'\)/);
    assert.match(projects, /window\.setProjectConversationApprovalStatus/);
    assert.match(projects, /window\.fetchAllPendingApprovals\(apiFetch\)/);
    assert.match(projects, /function bindProjectApprovalProgress/);
    assert.match(projects, /project-approval-progress-value/);
    assert.match(projects, /PROJECT_APPROVAL_TICK_INTERVAL_MS = 1000/);
    assert.match(projects, /function registerProjectApprovalTicker/);
    assert.match(monitor, /function renderDirectHitlSidebarApproval/);
    assert.match(monitor, /hitlSidebarApprovalSyncTimer = window\.setInterval/);
});

test('项目文件夹汇总始终为绿色且只有具体对话按剩余时间变色', () => {
    assert.match(projects, /waitingApprovalCount/);
    assert.match(projects, /aggregate: true, count: folderApprovals\.length/);
    assert.match(projects, /project-task-status--approval-summary', 'is-urgency-normal'/);
    assert.match(projects, /status\.dataset\.approvalUrgency = 'normal'/);
    assert.match(projects, /if \(isApprovalSummary\)[\s\S]{0,520}else \{[\s\S]{0,160}bindProjectApprovalUrgency\(status, details, label\)/);
    assert.doesNotMatch(projects, /currentExpiry < earliestExpiry/);
    assert.match(projects, /PROJECT_APPROVAL_URGENCY_CLASSES/);
    assert.match(projects, /remaining <= 60 \* 1000/);
    assert.match(projects, /remaining <= 3 \* 60 \* 1000/);
    assert.doesNotMatch(projects, /remaining <= 5 \* 60 \* 1000/);
    assert.match(projects, /project-task-status--approval-summary/);
    assert.equal(zh.hitl.waitingApprovalCount, '等待批准 {{count}}');
    assert.equal(zh.hitl.approvalUrgencyMoreThanThree, '最早审批将在 3 分钟后到期');
    assert.equal(typeof en.hitl.waitingApprovalCount, 'string');
    const urgencyFunctionSource = projects.match(
        /function projectApprovalUrgencyLevel\(remainingMilliseconds, hasDeadline\) \{[\s\S]*?\n\}/
    );
    assert.ok(urgencyFunctionSource, '应提供可测试的审批紧急程度函数');
    const urgencyLevel = vm.runInNewContext(`(${urgencyFunctionSource[0]})`);
    assert.equal(urgencyLevel(6 * 60 * 1000, true), 'normal');
    assert.equal(urgencyLevel(4 * 60 * 1000, true), 'normal');
    assert.equal(urgencyLevel(3 * 60 * 1000 + 1, true), 'normal');
    assert.equal(urgencyLevel(3 * 60 * 1000, true), 'warning');
    assert.equal(urgencyLevel(2 * 60 * 1000, true), 'warning');
    assert.equal(urgencyLevel(30 * 1000, true), 'critical');
    assert.equal(urgencyLevel(0, false), 'normal');
});

test('工具详情延迟 payload 使用实时事件中的 processDetailId 回补参数', () => {
    assert.match(chat, /const processDetailId = detail\.id \|\| data\.processDetailId \|\| ''/);
    assert.match(chat, /processDetailId: processDetailId/);
    assert.match(monitor, /resultDetailId: data\._mergedResultDetailId \|\| \(merged && merged\.processDetailId\) \|\| ''/);
    assert.match(monitor, /if \(state\.payloadDeferred && !state\.payloadLoaded && \(state\.processDetailId \|\| state\.resultDetailId\)\)/);
    assert.match(monitor, /const fullCall = await fetchFullProcessDetailData\(state\.processDetailId\)/);
    assert.match(monitor, /state\.args = parseToolCallArgsFromData\(fullCall\)/);
});

test('切换对话后主按钮只读取当前可见对话的运行状态', () => {
    assert.match(chat, /function getVisibleChatConversationId\(\)/);
    assert.match(chat, /function shouldTreatLiveChatTaskAsCurrent\(/);
    assert.match(chat, /function isLiveChatTaskVisible\(/);
    assert.match(chat, /if \(visibleConversationId\) return visibleConversationId/);
    assert.match(chat, /isConversationTaskRunning\(visibleConversationId\)/);
    assert.doesNotMatch(
        chat,
        /function getCurrentChatTaskConversationId\(\) \{[\s\S]{0,220}if \(live && live\.active && live\.conversationId\) \{[\s\S]{0,100}return String\(live\.conversationId\)/
    );
    const visibilityFunctionSource = chat.match(
        /function shouldTreatLiveChatTaskAsCurrent\(liveConversationId, visibleConversationId, hasVisibleProgress\) \{[\s\S]*?\n\}/
    );
    assert.ok(visibilityFunctionSource, '应提供可测试的当前任务隔离函数');
    const isCurrent = vm.runInNewContext(`(${visibilityFunctionSource[0]})`);
    assert.equal(isCurrent('running-conversation', '', true), false);
    assert.equal(isCurrent('running-conversation', 'new-conversation', true), false);
    assert.equal(isCurrent('running-conversation', 'running-conversation', false), true);
    assert.equal(isCurrent('', '', true), true);
    assert.equal(isCurrent('', '', false), false);
});

test('无项目使用独立虚拟文件夹且顶部新任务继承当前项目', () => {
    assert.match(projects, /CHAT_UNASSIGNED_PROJECT_FOLDER_ID/);
    assert.match(projects, /_isUnassigned: true/);
    assert.match(projects, /\[\.\.\.pinnedProjects, unassignedProject, \.\.\.regularProjects\]/);
    assert.match(projects, /window\.startNewConversation\(\{ projectId: isUnassigned \? '' : project\.id \}\)/);
    assert.match(chat, /Object\.prototype\.hasOwnProperty\.call\(options, 'projectId'\)/);
    assert.match(chat, /typeof resolveChatProjectSelection === 'function'/);
    assert.match(chat, /String\(inheritedProjectId \|\| ''\)\.trim\(\)/);
    assert.match(chat, /typeof setActiveProjectId === 'function'\) setActiveProjectId\(requestedProjectId\)/);
    assert.equal(zh.chat.newUnassignedConversation, '新建无项目对话');
    assert.equal(typeof en.chat.newUnassignedConversation, 'string');
});

test('单个对话的审批徽标随倒计时同步切换紧急颜色', () => {
    assert.match(projects, /bindProjectApprovalProgress\(status, details\);\s*bindProjectApprovalUrgency\(status, details, label\);/);
    assert.match(fs.readFileSync('web/static/css/style.css', 'utf8'), /\.project-task-status--approval\.is-urgency-critical/);
});

test('项目状态刷新复用单一计时器且切换对话不重复请求完整项目上下文', () => {
    assert.match(projects, /const projectApprovalTickerEntries = new Set\(\)/);
    assert.match(projects, /if \(!changed && !approvalChanged\) return/);
    assert.match(projects, /options\.reloadFolders !== false/);
    assert.match(chat, /refreshChatProjectSelector\(\{ reloadFolders: false, renderFolders: false \}\)/);
    assert.match(projects, /function selectChatProjectConversationItem/);
    assert.match(projects, /options\.renderFolders !== false/);
    assert.match(projects, /projectConversationPreviewSuppressedUntil = Date\.now\(\) \+ 700/);
    assert.match(projects, /project-task-status-group--folder/);
    assert.doesNotMatch(fs.readFileSync('web/static/css/style.css', 'utf8'), /project-task-status-group--folder \.project-task-status--running/);
    assert.match(fs.readFileSync('web/static/css/style.css', 'utf8'), /\.active-tasks-bar \{[\s\S]*?padding: 13px 24px 14px;/);
});

test('运行中对话切换会取消旧事件流并仅恢复最新一页过程详情', () => {
    assert.match(chat, /window\.cancelRunningTaskEventStream\(conversationId\)/);
    assert.match(monitor, /function cancelRunningTaskEventStream/);
    assert.match(monitor, /abortController\.abort\(\)/);
    assert.match(monitor, /signal: abortController\.signal/);
    assert.match(monitor, /initialLatest: true/);
    assert.match(monitor, /autoLoadAll: false/);
});

test('多对话并发时释放隐藏主流且旧请求不能覆盖新对话状态', () => {
    assert.match(chat, /function ownsLiveChatStream\(liveStream\)/);
    assert.match(chat, /function clearLiveChatStreamIfOwned\(liveStream\)/);
    assert.match(chat, /function detachLiveChatStreamForNavigation\(nextConversationId, force = false\)/);
    assert.match(chat, /liveStream\.detached = true;[\s\S]{0,240}controller\.abort\(\)/);
    assert.match(chat, /const requestAbortController = new AbortController\(\)/);
    assert.match(chat, /signal: requestAbortController\.signal/);
    assert.match(chat, /shouldIgnoreLiveChatStreamEvent\(liveStreamState\)/);
    assert.match(chat, /const clearedOwnedStream = clearLiveChatStreamIfOwned\(liveStreamState\)/);
    assert.match(chat, /detachLiveChatStreamForNavigation\(conversationId\)/);
    assert.match(chat, /detachLiveChatStreamForNavigation\('', true\)/);
    assert.match(chat, /window\.clearChatHitlApprovalDock\(\)/);
    assert.match(monitor, /if \(conversationId && conversationId !== currentId\) return false/);
    assert.match(monitor, /function scrollProcessDetailsToLatest\(assistantMessageId, smooth = true\)/);
    assert.match(monitor, /timeline\.scrollTop = targetTop/);
    assert.match(chat, /let loadConversationAbortController = null/);
    assert.match(chat, /cancelPendingConversationLoad\(\);[\s\S]{0,900}const conversationLoadController = new AbortController\(\)/);
    assert.match(chat, /signal: conversationLoadController\.signal/);
    assert.match(template, /monitor\.js\?v=20260907-blocked-1/);
    assert.match(template, /chat-scroll\.js\?v=20260815-1/);
    assert.match(template, /chat\.js\?v=20260907-blocked-1/);
    assert.match(template, /style\.css\?v=\d{8}-[\w-]+/);
});

test('彻底停止始终使用弹窗锁定的会话且状态刷新后仍会取消', () => {
    const start = monitor.indexOf("async function performHardCancelProgressTask(progressId, conversationId = '')");
    const end = monitor.indexOf('function progressElapsedText(', start);
    assert.notEqual(start, -1);
    assert.notEqual(end, -1);
    const hardCancelSource = monitor.slice(start, end);
    assert.match(monitor, /performHardCancelProgressTask\(progressId, conversationId\)/);
    assert.match(hardCancelSource, /const targetConversationId = String\(conversationId \|\| \(state && state\.conversationId\) \|\| ''\)\.trim\(\)/);
    assert.match(hardCancelSource, /await requestCancel\(targetConversationId\)/);
    assert.doesNotMatch(hardCancelSource, /if \(!state \|\| !state\.conversationId\)/);
});

test('任务结束后对话内审批按钮会变灰并禁止继续操作', () => {
    assert.match(monitor, /ready: false/);
    assert.match(monitor, /function setHitlApprovalTaskAvailability/);
    assert.match(monitor, /conversationExecutionTracker\.ready && !conversationExecutionTracker\.isRunning\(id\)/);
    assert.match(monitor, /hitlPendingInterruptTracker\.ready/);
    assert.match(monitor, /!hitlPendingInterruptTracker\.has\(interruptId\)/);
    assert.match(monitor, /button\.disabled = true/);
    assert.match(monitor, /function setHitlApprovalInterruptedVisualState/);
    assert.match(monitor, /stopHitlApprovalCountdown\(panel\)/);
    assert.match(monitor, /removeAttribute\('data-hitl-expires-at'\)/);
    assert.match(monitor, /hitl\.interruptedApprovalCancelled/);
    assert.match(monitor, /reconcileHitlApprovalStateWithActiveTasks\(normalizedTasks\)/);
    assert.match(monitor, /syncHitlApprovalTaskAvailability\(\)/);
    assert.match(fs.readFileSync('web/static/css/style.css', 'utf8'), /hitl-approval-task-closed/);
    assert.equal(zh.hitl.taskClosedApprovalUnavailable, '任务已结束，审批不可用');
    assert.equal(zh.hitl.interruptedApprovalCancelled, '任务已中断，审批已取消');
    assert.equal(typeof en.hitl.taskClosedApprovalUnavailable, 'string');
    assert.equal(typeof en.hitl.interruptedApprovalCancelled, 'string');
});

test('项目树只保留当前进程仍在运行任务的审批状态', () => {
    assert.match(projects, /chatProjectFolderContext\.runningIds\.has\(conversationId\)/);
    assert.match(projects, /pendingApprovalByConversation\.delete\(conversationId\)/);
    assert.match(monitor, /conversationExecutionTracker\.ready && !conversationExecutionTracker\.isRunning\(conversationId\)/);
});

test('审批状态主动轮询并在服务不可用时立即关闭旧审批', () => {
    assert.match(monitor, /ACTIVE_TASK_REFRESH_INTERVAL = 2000/);
    assert.match(monitor, /window\.fetchAllPendingApprovals\(apiFetch\)/);
    assert.match(monitor, /function reconcilePendingHitlState\(rawItems\)/);
    assert.match(monitor, /renderChatHitlApprovalDock\(currentPending\)/);
    assert.match(monitor, /restoreHitlInlineForConversation\(currentId\)/);
    assert.match(monitor, /case 'conversation':[\s\S]{0,1800}window\.refreshChatProjectFolders\(\)/);
    assert.match(monitor, /renderActiveTasks\(\[\]\);[\s\S]{0,260}hitlPendingInterruptTracker\.update\(\[\]\)/);
    assert.match(projects, /function syncProjectConversationApprovalStatuses\(items\)/);
    assert.match(projects, /window\.syncProjectConversationApprovalStatuses/);
    assert.match(template, /projects\.js\?v=20260819-1/);
});

test('人机协同页与审计日志展示 Jev / OpenAI 审批引擎', () => {
    assert.match(template, /id="hitl-page-audit-engine"/);
    assert.match(template, /id="hitl-log-detail-engine"/);
    assert.match(template, /id="hitl-audit-backend"/);
    assert.match(approvalUI, /function hitlAuditEngineLabel\(backend, model\)/);
    assert.match(approvalUI, /function renderHitlPageAuditEngine\(\)/);
    assert.match(approvalUI, /function applyAuditEngineFromApprovalConfig\(data\)/);
    // 首屏任意页签都要能显示当前引擎：一次性懒加载挂在 refreshHitlActivePanel 上
    assert.match(approvalUI, /function loadAuditEngineInfo\(\)/);
    assert.match(approvalUI, /function refreshHitlActivePanel\(+\) {\s*loadAuditEngineInfo\(\);/);
    assert.match(approvalUI, /applyAuditEngineFromApprovalConfig\(data\);/);
    assert.match(approvalUI, /ApprovalUIModel\.auditEngineFromDecision/);
    assert.match(approvalUI, /hitl-log-engine/);
    assert.equal(zh.hitl.auditEngineJev, 'TypeSafe Jev');
    assert.equal(en.hitl.auditEngineJev, 'TypeSafe Jev');
    assert.equal(zh.hitl.auditEngineOpenAI, 'OpenAI 协议');
    assert.equal(en.hitl.auditEngineOpenAI, 'OpenAI protocol');
    assert.match(styles, /\.hitl-page-audit-engine \{/);
    assert.match(styles, /\.hitl-log-engine \{/);
});

test('审批引擎可切换 TypeSafe Jev 并标注裁决来源', () => {
    assert.match(template, /id="hitl-audit-openai-provider-group"/);
    assert.match(template, /id="hitl-audit-model-typesafe-hint"/);
    assert.match(template, /id="hitl-audit-prompt-typesafe-hint"/);
    assert.match(settings, /function syncHitlAuditBackendUI\(\)/);
    assert.match(settings, /function isHitlAuditTypeSafe\(\)/);
    assert.match(settings, /\/api\/config\/test-typesafe/);
    assert.match(settings, /audit_backend: document\.getElementById\('hitl-audit-backend'\)/);
    assert.equal(zh.settings.hitl.auditBackendTypeSafe, 'TypeSafe Jev');
    assert.equal(en.settings.hitl.auditBackendTypeSafe, 'TypeSafe Jev');
    assert.equal(zh.settings.hitl.testTypeSafeFillRequired.includes('TypeSafe'), true);
    assert.equal(en.settings.hitl.testTypeSafeFillRequired.includes('TypeSafe'), true);
    assert.match(approvalAdapters, /auditBackend/);
    assert.match(approvalAdapters, /hitlAuditEngineInfo\(\)/);
    // 人机协同页在 approval:read 下即可拿到当前引擎（无需 config:read）
    assert.match(approvalHandler, /SetAuditEngineInfo/);
    assert.match(approvalHandler, /json:"auditBackend"/);
});
// 运行时渲染校验：日志行的引擎标注靠手写字符串拼接，必须真跑一遍确认列结构没被破坏。
test('审计日志行渲染按裁决方标注引擎且列数不变', () => {
    function extractFunction(name) {
        const start = approvalUI.indexOf('function ' + name + '(');
        assert.notEqual(start, -1, '应可找到 ' + name);
        const end = approvalUI.indexOf('\n}', start);
        assert.notEqual(end, -1, '应可闭合 ' + name);
        return approvalUI.slice(start, end + 2);
    }
    const wrap = { innerHTML: '' };
    const context = {
        document: { getElementById: (id) => (id === 'hitl-logs-table-wrap' ? wrap : null) },
        escapeHtml: (value) => String(value === null || value === undefined ? '' : value),
        hitlT: (key, fallback) => (fallback === undefined || fallback === null ? key : fallback),
        ApprovalUIModel,
        approvalDecisionTag: (decision) => '<span>' + decision + '</span>',
        approvalStatusLabel: (status) => status || '-',
        approvalActorLabel: (actor) => actor || '-',
        buildApprovalSummary: () => 'summary',
        approvalFormatTime: () => 'time',
        renderHitlLogsPagination: () => {},
        console
    };
    vm.createContext(context);
    vm.runInContext(extractFunction('hitlAuditEngineLabel') + '\n' + extractFunction('renderHitlLogsTable'), context);

    const agentDecision = {
        id: 'd1', approvalId: 'a1', stage: 'agent_review', actorType: 'agent', actorId: 'audit-model',
        decision: 'approve', comment: 'audit agent: 通过', createdAt: '2026-09-27T10:00:00Z',
        metadata: { auditBackend: 'typesafe', auditModel: 'jev-latest' }
    };
    const base = { id: 'a1', toolName: 'execute', conversationId: 'c1', status: 'approved', arguments: { command: 'id' } };
    context.renderHitlLogsTable([Object.assign({}, base, { decisions: [agentDecision] })]);
    const agentRow = wrap.innerHTML;
    assert.match(agentRow, /class="hitl-log-engine">TypeSafe Jev · jev-latest</);
    assert.equal((agentRow.match(/<td/g) || []).length, 9, '日志行仍是 9 列');

    // 旧记录没有 metadata：按备注特征识别为 OpenAI 协议
    context.renderHitlLogsTable([Object.assign({}, base, {
        decisions: [Object.assign({}, agentDecision, { metadata: undefined, comment: 'audit agent: 命中规则 A3' })]
    })]);
    assert.match(wrap.innerHTML, /class="hitl-log-engine">OpenAI protocol</);

    // 人工决定不标注引擎
    context.renderHitlLogsTable([Object.assign({}, base, {
        decisions: [Object.assign({}, agentDecision, { actorType: 'human', metadata: undefined, comment: '人工通过' })]
    })]);
    assert.doesNotMatch(wrap.innerHTML, /hitl-log-engine/);

    // 无决定（待审）时不标注，也不影响列数
    context.renderHitlLogsTable([Object.assign({}, base, { status: 'pending_human' })]);
    assert.doesNotMatch(wrap.innerHTML, /hitl-log-engine/);
    assert.equal((wrap.innerHTML.match(/<td/g) || []).length, 9);
});
test('审批体验文案具有完整中英文资源', () => {
    const hitlKeys = [
        'waitingApprovalShort',
        'requestVisitUrl',
        'requestCommand',
        'viewRequestDetails',
        'timeoutAutoReject',
        'expiredRejected',
    ];
    const chatKeys = [];
    hitlKeys.forEach((key) => {
        assert.equal(typeof zh.hitl[key], 'string');
        assert.equal(typeof en.hitl[key], 'string');
    });
    chatKeys.forEach((key) => {
        assert.equal(typeof zh.chat[key], 'string');
        assert.equal(typeof en.chat[key], 'string');
    });
});
