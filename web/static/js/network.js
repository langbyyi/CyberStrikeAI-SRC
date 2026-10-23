(function () {
    'use strict';
    let poolSequence = 0;
    let projectSequence = 0;
    let projectRefreshSequence = 0;
    let projectID = '';
    let projectPolicy = null;
    let projectDraftBaseline = null;
    let projectBusy = false;
    let poolData = [];
    let editingSourceID = '';
    let poolJob = null;
    let poolObservations = {};
    const selectedNodes = new Set();
    let sourceSaving = false;
    let sourceProviders = new Map();
    let sourceProvidersLoading = false;
    let sourceProvidersFailed = false;
    let sourceProvidersSequence = 0;
    let activeSourceKind = 'fofa';
    let sourceDrafts = {};
    let generatedQueries = {};
    const sourceNames = {fofa: 'FOFA', quake: 'Quake', hunter: 'Hunter', zoomeye: 'ZoomEye', shodan: 'Shodan'};
    let validationSequence = 0;
    let validationLoading = false;
    let validationReady = false;
    let poolPage = 0, poolPages = 1, poolFilteredCount = 0, poolPageSize = 20;
    let editingNodeID = '';
    let editSequence = 0;
    let poolMutationBusy = false;
    let projectOperation = null;
    let projectRefreshTimer;
    let bindingsSnapshot = '';
    const byId = id => document.getElementById(id);
    const copy = {
        bindingNeedsAssessment: '待 Agent 重新判断', bindingOutOfScope: '当前范围外',
        jobMissing: '任务已结束或服务已重启，已完成结果仍保留，请重新发起剩余操作。', jobReconnecting: '任务连接暂时中断，正在重连；已完成结果保留。', jobRefreshFailed: '结果刷新暂时失败，后台任务仍保留，稍后自动重试。', pauseJob: '暂停', resumeJob: '继续', pausingJob: '正在暂停…', pausedJob: '已暂停，已完成结果已保留。', jobDone: '任务完成',
        sourceProgress: '已读取 {{pages}} 页 · 新增 {{imported}} 个 · 跳过 {{skipped}} 个', validationProgress: '已验证 {{completed}} / {{total}} 个 · 通过 {{passed}} · 失败 {{failed}}', fetchingProgress: '正在请求下一页，单页最多等待 30 秒。',

        modeLabel: '访问方式', taskProgress: '任务进度', currentProxy: '当前代理', importHint: '每行一个 HTTP、HTTPS 或 SOCKS5 代理地址，支持用户名和密码。', detailsText: '完整验证结果', poolCount: '共 {{count}} 个节点',
        observationDetails: "验证详情", viewDetails: "点击查看完整验证详情", copyDetails: "复制详情", detailsCopied: "详情已复制。", detailsManualCopy: "已选中完整详情，请按 Ctrl+C 或手动复制。", checkType: "验证类型", checkResult: "验证结果", checkStage: "失败 / 响应阶段", httpStatus: "HTTP 状态", latency: "耗时", observedAt: "验证时间", expiresAt: "有效期至", errorReason: "错误原因", stageConnect: "建立代理或目标连接", stageDNS: "DNS 解析失败", stageAuth: "代理认证失败", stageTLS: "TLS 握手或证书验证失败", stageTimeout: "目标连接或响应超时", stageHTTP: "收到 HTTP 响应", stageHTTPError: "HTTP 请求被拒绝", stageRateLimit: "触发限流", stageContent: "响应内容检查",
        pageSize: '每页数量', deleteAll: '全部删除', deleteAllConfirm: '删除全局代理池中的全部 {{count}} 个代理？此操作不受筛选和分页限制，项目正在引用的节点将跳过。', poolEmpty: '代理池为空，无需删除。', editNode: '编辑代理', sourceManual: '手动添加', sourceSubscription: '订阅导入', sourceCollection: '自动爬取', mutationBusy: '批量操作正在进行，请稍候。',
        nav: '代理池', title: '全局代理池', target: '验证目标', refresh: '刷新', export: '导出代理', address: '地址',
        source: '来源', auth: '认证', status: '状态', reachability: '目标验证', actions: '操作', filter: '筛选节点', filterHint: '输入地址或来源', all: '全部状态',
        enabled: '已启用', disabled: '已停用', configured: '已配置', none: '无', available: '可用', reachable: '对目标可用', filterPassed: '验证通过', filterFailed: '验证失败',
        failed: '失败', untested: '未验证', stale: '结果已过期', diagnose: '验证', enable: '启用', disable: '停用', edit: '编辑',
        remove: '删除', save: '保存', cancel: '取消', editAddress: '新代理地址（留空保留地址和凭据）', removeNode: '删除代理 {{address}}？正在使用它的任务会断开。', empty: '还没有代理。点击「手动添加」或配置 FOFA / 订阅来源即可开始。', noMatches: '没有符合条件的节点。', importTitle: '手动 / 批量导入',
        importAddresses: '每行一个 HTTP / HTTPS / SOCKS5 地址，可带账号密码', import: '导入', imported: '已添加 {{imported}} 个，忽略 {{skipped}} 条无效地址。', sourcesTitle: '爬取代理', sourceName: '配置名称', sourceNameHint: '自有代理节点', subscription: '订阅 URL', fofaQuery: 'FOFA 查询',
        fofaHint: '填写自有或允许使用的代理资产查询', limit: '每次爬取上限', saveSource: '保存来源', sourceSaved: '来源已保存', sourceSummary: '{{name}} · 每次最多 {{limit}} 条',
        sync: '同步', syncing: '正在爬取代理…', synced: '爬取完成：新增 {{imported}} 个，忽略 {{skipped}} 个', loading: '正在加载网络配置…', requestFailed: '请求失败：HTTP {{status}}', jobFailed: '操作失败', timeout: '等待超时，稍后刷新看看', targetRequired: '请填写要验证的目标域名或 URL',
        diagnosing: '正在验证所选节点能否访问该目标…', reached: '对目标可用，HTTP {{status}}', unreachable: '对目标不可用', exportFailed: '导出失败', invalidScope: '范围 JSON 需要 targets 字符串数组', forbidden: '需要全局范围的配置写权限', projectTitle: '项目代理 / OpenVPN', projectIntro: '填好测试目标、VPN 配置和证书即可。连接与分流由系统处理，Agent 会自动接入范围内的后续资产。',
        modeAuto: '默认网络（Agent 按需使用全局代理池）', modeProxy: '使用项目提供的 HTTP / SOCKS5 代理', modeVPN: '使用项目提供的 OpenVPN', projectTargets: '测试目标 / VPN 范围', targetsHint: '默认沿用项目资产，每行一个域名、*.域名、IP 或网段', projectProxy: '指定代理', vpnConfig: 'OpenVPN 配置', certificates: '外置证书 / 私钥',
        advanced: '高级：DNS 与资产', dns: '项目 DNS（需要时填写）', dnsHint: '每行一个 DNS IP', asset: '关联范围内资产（可选）', assetHint: '域名、*.域名、URL、IP 或网段', bind: '关联资产', excludeAsset: '排除资产', userAssetEvidence: '用户关联项目网络资产',
        userAdjustEvidence: '用户调整项目 VPN 资产', excluded: '已排除', associated: '已关联', restore: '恢复', exclude: '排除', bindingSummary: '{{target}} · {{state}} · {{source}}', saveProject: '保存网络配置', connect: '连接 / 检查',
        disconnect: '断开', refreshStatus: '刷新状态', notLoaded: '项目网络配置尚未加载', saving: '正在保存…', saved: '已保存。测试时由系统自动准备项目网络。', savedRefreshFailed: '网络配置已保存，但读取最新状态失败。请点击「刷新状态」恢复显示，无需重复保存。', connecting: '正在连接 VPN…', profileLimit: '.ovpn 文件不能超过 2 MiB', certLimit: '单个证书不超过 1 MiB，总量不超过 4 MiB',
        assigned: '指定节点：{{address}}', linuxRequired: '实际隔离执行需要 Linux / Kali 运行节点', proxyConfigured: '项目代理已配置', defaultNetwork: '使用默认网络', vpnStopped: '已断开', vpnConnecting: '连接中', vpnReady: '已就绪', vpnReconnecting: '重连中',
        vpnJobCancelled: '已取消 VPN 连接，项目隧道已断开。', vpnFailed: '连接失败', sourceURLHint: '编辑订阅时留空，保留已保存的地址和凭据', sourceKind: '爬取方式', cancelJob: '取消', jobCancelled: '已取消。已经导入的节点和完成的验证结果都保留。',
        jobTimeout: '等待超时，已请求取消。刷新可查看已完成的结果。', profileSaved: 'VPN 配置已保存。留空则沿用现有配置；选择新的 .ovpn 会替换配置及证书。', profileMissing: '还没有 VPN 配置，请选择 .ovpn 后保存。', configRequiredForCerts: '替换外置证书时，请同时选择对应的 .ovpn 文件。', policyChanged: '配置已被其他操作修改，请重新打开项目设置后再保存。', vpnUsername: 'VPN 用户名', vpnPassword: 'VPN 密码', vpnAuthHint: '需要账号密码认证时填写；留空沿用已保存凭据。',
        vpnAuthConfigured: 'VPN 账号密码已配置，不会回显。要更新请把用户名和密码一起填上。', vpnAuthMissing: '未配置账号密码；仅客户端证书认证可直接连接。', vpnAuthPairRequired: '请同时填写 VPN 用户名和密码；两项都留空则保留原凭据。', manualAdd: '手动添加代理', subscriptionImport: '导入订阅', collection: '自动爬取', validationConfig: '验证设置', validateAll: '验证全部',
        validateSelected: '验证选中', selection: '选择', selectVisible: '全选本页', poolValidation: '最近全池验证', bulkManage: '批量操作', bulkExecute: '应用到选中', bulkConfirm: '删除选中的 {{count}} 个代理？', bulkNoSelection: '请先选中节点',
        bulkDone: '已更新 {{updated}} 个，跳过 {{skipped}} 个', close: '关闭', subscriptionInput: '订阅链接或节点内容', subscriptionContentMode: '粘贴节点 / Base64 / Clash YAML / V2Ray JSON', subscriptionURLMode: '订阅链接（每行一个，最多 20 个）', subscriptionFormatHint: '支持 HTTP、HTTPS、SOCKS5 节点。VMess、VLESS、SS、Hysteria2 等隧道协议暂未接入，只会统计数量；如需使用，请先在运行主机上用 Clash 等客户端加载，再添加该主机可访问的 HTTP / SOCKS 端口。', contains: '响应包含该字符串（可选）', failureAction: '连续失败后',
        failureThreshold: '连续失败次数', keep: '保留', delete: '删除', saveOnly: '仅保存', saveAndValidate: '保存并验证全部', saveAndSync: '保存并爬取', sourceKey: 'API Key（留空沿用）', sourceEndpoint: 'API 地址（可选，留空沿用）',
        validationSummary: '验证完成：检查 {{checked}} · 通过 {{passed}} · 失败 {{failed}} · 跳过 {{skipped}} · 停用 {{disabled}} · 删除 {{deleted}}', unsupportedProtocols: '暂未接入：{{protocols}}', collectionAll: '爬取全部来源',
        collectionSelected: '爬取选中来源', validationHint: '通过代理访问验证目标；返回成功响应并匹配可选字符串时通过。目标留空则跳过。目标拒绝访问或限流会记录原因，不会因此清理节点。', validationSaved: '验证配置已保存', jobBusy: '已有任务在跑，请等待完成或取消', importRequired: '请填写代理或订阅内容', validationSkipped: '已跳过验证，需要先设置验证目标', cleanupSuppressed: '全部节点都验证失败，已暂停清理，请检查验证目标', inputLimit: '内容过大，或订阅链接超过 20 个',
        sourceQuery: '查询语法', previousPage: '上一页', nextPage: '下一页', pageSummary: '{{total}} 个节点 · 第 {{page}} / {{pages}} 页 · 已选 {{selected}} 个', protocolSOCKS5: 'SOCKS5', protocolHTTP: 'HTTP', protocolHTTPS: 'HTTPS', queryProtocol: '代理协议',
        queryCountry: '国家 / 地区代码（留空不限）', queryNoAuth: '只看免认证的 SOCKS5', queryReset: '恢复默认', queryReplace: '用当前条件生成的默认语法替换自定义查询？', queryCountryInvalid: '国家 / 地区代码填两个英文字母，例如 CN、US；留空表示不限。', queryHint: '查询已预填，可直接修改。上面的协议、地区、免认证三项用来生成模板，实际爬取以查询框内容为准。', queryCustomHint: '该引擎用的是自定义查询；切换引擎时，各自未保存的查询和配置都会保留。', queryLabel: '{{engine}} 查询语法',
        sourceDefaultName: '{{engine}} 代理', crawl: '爬取', crawled: '爬取完成：新增 {{imported}} 个，忽略 {{skipped}} 个', importResult: '已添加 {{imported}} 个，忽略 {{skipped}} 个', crawlConfigFailed: '爬取配置保存失败，请重试。',
        providerLoading: '正在读取引擎配置…', providerConfigured: '{{engine}} API 凭据已配置，爬取时会校验其有效性。', providerMissing: '{{engine}} 尚未配置。请在系统设置中配置对应 API 凭据，再重新打开此窗口。', providerHunterMissing: 'Hunter 尚未配置。请在运行主机设置 HUNTER_API_KEY 并重启服务，再重新打开此窗口。', providerSubscription: '订阅链接不需要搜索引擎 API 凭据。', providerLoadFailed: '无法读取引擎配置，请重新打开此窗口重试。', crawlLimitInvalid: '每次爬取上限需为 1–10000 的整数。'
    };
    function t(key, values = {}) {
        // All network copy is assigned through textContent or text attributes.
        const translated = typeof window.t === 'function' ? window.t('network.' + key, {...values, interpolation: {escapeValue: false}}) : '';
        const text = translated && translated !== 'network.' + key ? translated : (copy[key] || key);
        return text.replace(/{{(\w+)}}/g, (_, name) => String(values[name] ?? ''));
    }
    const node = (tag, text, className) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (className) e.className = className; return e; };
    function label(tag, key, className) { const e = node(tag, t(key), className); e.setAttribute('data-i18n', 'network.' + key); return e; }
    function pill(key, variant) { return label('span', key, 'network-pill network-pill--' + variant); }
    function setMessage(id, text) { const e = byId(id); if (e) { delete e.dataset.networkMessage; delete e.dataset.networkVpn; e.textContent = text; e.title = text; } }
    const message = text => { setMessage('network-message', text); document.querySelectorAll('.network-dialog').forEach(e => { if (e.open) setMessage(e.id + '-message', text); }); };
    const projectMessage = text => setMessage('project-network-message', text);
    function translatedMessage(id, key) { const e = byId(id); if (e) { delete e.dataset.networkVpn; e.dataset.networkMessage = key; e.textContent = t(key); } if (id === 'network-message') document.querySelectorAll('.network-dialog').forEach(d => { if (d.open) setMessage(d.id + '-message', t(key)); }); }
    async function request(path, options) {
        const response = await window.apiFetch(path, options);
        if (!response.ok) { let error; try { error = await response.json(); } catch { error = {}; } throw Object.assign(new Error(error.message || error.error || t('requestFailed', {status: response.status})), {status: response.status}); }
        return response.json();
    }
    function json(method, value) { return {method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(value)}; }
    function parseTargets(raw) {
        const text = String(raw || '').trim();
        if (!text) return [];
        if (text.startsWith('{')) { const parsed = JSON.parse(text); if (!Array.isArray(parsed.targets) || parsed.targets.some(v => typeof v !== 'string')) throw new Error(t('invalidScope')); return parsed.targets; }
        return [...new Set(text.split(/[\n,]/).map(v => v.trim()).filter(Boolean))];
    }
    function button(key, action, report = message) {
        const e = label('button', key, 'btn btn-secondary'); e.type = 'button';
        let pending;
        e.addEventListener('click', async () => {
            if (e.disabled) return;
            const operation = {}; pending = operation;
            if (e.dataset.projectAction) e.dataset.busyProject = projectID;
            e.disabled = true; e.dataset.stateDisabled = 'true'; e.dataset.networkBusy = 'true';
            try { await action(); } catch (error) { report(error.message); }
            finally { if (pending === operation) { e.disabled = false; delete e.dataset.stateDisabled; delete e.dataset.networkBusy; delete e.dataset.busyProject; if (e.dataset.projectAction) updateProjectControls(); if (e.dataset.poolPage) updatePagerControls(); if (e.getAttribute('data-pool-job') || e.getAttribute('data-job-pause')) refreshPoolJobControls(); } }
        });
        return e;
    }
    function field(key, id, placeholder = '', type = 'text', placeholderKey = '') {
        const wrapper = node('label', undefined, 'network-field'); wrapper.append(label('span', key));
        const input = node(type === 'textarea' ? 'textarea' : 'input', undefined, 'form-input'); input.id = id; if (type !== 'textarea') input.type = type; input.placeholder = placeholderKey ? t(placeholderKey) : placeholder; input.setAttribute('aria-label', t(key));
        if (placeholderKey) { input.setAttribute('data-i18n', 'network.' + placeholderKey); input.setAttribute('data-i18n-attr', 'placeholder'); }
        wrapper.append(input); return wrapper;
    }
    function admin() { return typeof isTokenValid === 'function' && isTokenValid() && typeof window.hasPermission === 'function' && window.hasPermission('config:write') && typeof authScope !== 'undefined' && authScope === 'all'; }
    function adminControl(e) { e.setAttribute('data-require-permission', 'config:write'); e.className = (e.className || '') + ' network-admin'; e.hidden = true; return e; }
    function refreshPermissions() {
        document.querySelectorAll('.network-admin').forEach(e => { if (e.hidden === admin()) e.hidden = !admin(); });
        if (!admin()) document.querySelectorAll('.network-dialog').forEach(e => { if (e.open && (e.dataset.networkReadOnly !== 'true' || typeof isTokenValid !== 'function' || !isTokenValid())) e.close(); });
        updateProjectControls();
    }
    function requireAdmin() { if (!admin()) throw new Error(t('forbidden')); }
    function rememberPoolJob(id) { try { if (id) window.sessionStorage?.setItem('network-pool-job', id); else window.sessionStorage?.removeItem('network-pool-job'); } catch { /* Storage can be disabled. */ } }
    function jobMessage(text) { document.querySelectorAll('[data-job-progress]').forEach(e => { e.textContent = text; }); }
    function poolProgress(job, control) {
        control.state = job.state; control.pausable = job.pausable !== false; refreshPoolJobControls();
        const p = job.progress; if (!p?.kind) return false;
        const meter = byId('network-task-progress');
        if (meter) { meter.hidden = p.kind !== 'validation' || !(p.total > 0); meter.max = Math.max(1, p.total || 0); meter.value = Math.max(0, Math.min(p.completed || 0, meter.max)); }
        const text = t(p.kind === 'source' ? 'sourceProgress' : 'validationProgress', p);
        const prefix = job.state === 'paused' ? t('pausedJob') + ' ' : job.state === 'pausing' ? t('pausingJob') + ' ' : '';
        jobMessage(prefix + text + (p.stage === 'fetching' && job.state !== 'paused' ? ' '+t('fetchingProgress') : ''));
        const committed = [p.completed || 0, p.pages || 0, p.imported || 0].join('/');
        if (committed === '0/0/0' || committed === control.lastCompleted) return false;
        if (control.lastRefresh && Date.now() - control.lastRefresh < 1500) return false;
        control.lastCompleted = committed; control.lastRefresh = Date.now(); return true;
    }
    function pauseJobButton(id) {
        const e = button('pauseJob', async () => {
            const control = poolJob; if (!control?.id) return;
            const action = control.state === 'paused' ? 'resume' : 'pause';
            const job = await request(`/api/network/jobs/${encodeURIComponent(control.id)}/${action}`, json('POST', {}));
            if (poolJob === control) { control.state = job.state; refreshPoolJobControls(); }
        });
        if (id) e.id = id; e.setAttribute('data-job-pause', 'true'); e.hidden = true; return e;
    }
    async function restorePoolJob() {
        let storage, id; try { storage=window.sessionStorage; id=storage?.getItem('network-pool-job'); } catch { return; }
        if (!storage || poolJob) return;
        if (!id) { const listing=await request('/api/network/jobs'); id=listing.jobs?.[0]?.id; }
        if (!id || poolJob) return;
        rememberPoolJob(id);
        const control = {id, state:'running'}; poolJob=control; refreshPoolJobControls();
        try {
            const result = await waitJob(id, control);
            message(result && typeof result.imported === 'number' ? importSummary(result) : result && typeof result.checked === 'number' ? t('validationSummary',result) : t('jobDone'));
            await loadPool();
        } catch (error) { message(error.message); }
        finally { if (poolJob===control) {poolJob=null;if (!control.retain) rememberPoolJob('');refreshPoolJobControls();} }
    }
    async function waitJob(jobID, control) {
        for (let count = 0; count < 1300;) {
            if (control?.cancellation) await control.cancellation;
            if (control?.cancelled) throw new Error(t(control.cancelMessage || 'jobCancelled'));
            let job;
            try { job = await request(`/api/network/jobs/${encodeURIComponent(jobID)}`); }
            catch (error) {
                if ([401,403].includes(error.status)) { control.retain = true; throw error; }
                if (error.status === 404) throw new Error(t('jobMissing'));
                if (poolJob === control) jobMessage(t('jobReconnecting'));
                await new Promise(resolve => setTimeout(resolve, 2000)); continue;
            }
            if (control?.cancellation) await control.cancellation;
            if (control?.cancelled) throw new Error(t(control.cancelMessage || 'jobCancelled'));
            if (poolJob === control && poolProgress(job, control)) { try { await loadPool(); } catch { control.lastCompleted = undefined; jobMessage(t('jobRefreshFailed')); } }
            if (job.state !== 'paused' && job.state !== 'pausing') count++;
            if (job.state === 'completed') return job.result;
            if (job.state === 'failed') {
                const partial = job.result && typeof job.result.imported === 'number' ? importSummary(job.result) : job.result && typeof job.result.checked === 'number' ? t('validationSummary', job.result) : '';
                throw new Error((job.error || t('jobFailed')) + (partial ? '\n' + partial : ''));
            }
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
        await request(`/api/network/jobs/${encodeURIComponent(jobID)}/cancel`, json('POST', {}));
        throw new Error(t('jobTimeout'));
    }
    async function runPoolJob(path, value, pendingKey) {
        if (poolJob) throw new Error(t('jobBusy'));
        const control = {}; poolJob = control; refreshPoolJobControls(); message(''); jobMessage(t(pendingKey));
        try {
            const job = await request(path, json('POST', value)); control.id = job.job_id; control.state = "running"; rememberPoolJob(control.id); refreshPoolJobControls();
            return await waitJob(job.job_id, control);
        } catch (error) {
            if (control.id) { try { await loadPool(); } catch { /* Preserve the operation error when refreshing also fails. */ } }
            throw error;
        } finally { if (poolJob === control) { poolJob = null; if (!control.retain) rememberPoolJob(''); refreshPoolJobControls(); } }
    }
    function refreshPoolJobControls() {
        document.querySelectorAll('[data-pool-job]').forEach(e => { e.disabled = !!poolJob || sourceSaving; });
        const sourcePanel = byId('network-source-dialog');
        sourcePanel?.querySelectorAll('input, textarea, select').forEach(e => { e.disabled = !!poolJob || sourceSaving; });
        byId('network-source-rows')?.querySelectorAll('button').forEach(e => { e.disabled = !!poolJob || sourceSaving; });
        for (const id of ['network-source-query-reset', 'network-source-cancel']) { const e = byId(id); if (e) e.disabled = !!poolJob || sourceSaving; }
        const cancel = byId('network-job-cancel'); if (cancel) cancel.hidden = !poolJob?.id;
        document.querySelectorAll('[data-dialog-cancel]').forEach(e => { e.hidden = !poolJob?.id; });
        document.querySelectorAll('[data-job-pause]').forEach(e => {
            e.hidden = !poolJob?.id || poolJob.pausable === false;
            e.disabled = poolJob?.state === 'pausing' || !!e.dataset.networkBusy;
            const key = poolJob?.state === 'paused' ? 'resumeJob' : poolJob?.state === 'pausing' ? 'pausingJob' : 'pauseJob';
            e.textContent = t(key); e.setAttribute('data-i18n', 'network.' + key);
        });
        document.querySelectorAll('[data-job-progress]').forEach(e => { e.hidden = !poolJob; });
        document.querySelectorAll('[data-job-container]').forEach(e => { e.hidden = !poolJob; e.dataset.state = poolJob?.state || 'running'; });
        if (!poolJob && byId('network-task-progress')) byId('network-task-progress').hidden = true;
        refreshValidationControls();
        updateSourceProviderStatus();
    }
    function poolJobButton(key, run) {
        const e = button(key, run); e.setAttribute('data-pool-job', 'true'); e.disabled = !!poolJob || sourceSaving; return e;
    }
    async function diagnose(ids) {
        const target = byId('network-target')?.value.trim(); if (!target) throw new Error(t('targetRequired'));
        const results = await runPoolJob('/api/network/diagnose', {target, node_ids: ids}, 'diagnosing');
        if (!results) return;
        if (byId('network-target')?.value.trim() !== target) return;
        message(results.map(r => `${r.node_id.slice(0, 8)}: ${r.reachable ? t('reached', {status: r.http_status}) : (r.reason || t('unreachable'))}`).join('; '));
        await loadPool();
    }
    function observationText(o) { return o ? `${t(o.reachable ? 'reachable' : 'failed')} ${o.http_status || ''} · ${o.latency_ms} ms${o.expires_at && Date.parse(o.expires_at) < Date.now() ? ' · ' + t('stale') : ''}${o.reason ? ' · ' + o.reason : ''}` : t('untested'); }
    function showDetails(text) {
        if (!text.trim()) return;
        byId('network-observation-details').value = text;
        setMessage('network-observation-dialog-message', '');
        const panel = byId('network-observation-dialog'); if (!panel.open) panel.showModal();
    }
    function observationCell(value, observation, kind) {
        const text = observationText(observation), cell = node('td', undefined, 'network-observation');
        cell.dataset.networkState = observation ? (observation.reachable ? 'ok' : 'bad') : 'none';
        cell.title = text; cell.setAttribute('data-network-observation', JSON.stringify(observation || null));
        if (!observation) { cell.textContent = text; return cell; }
        const trigger = node('button', text, 'network-observation-trigger'); trigger.type = 'button';
        trigger.setAttribute('aria-haspopup', 'dialog'); trigger.setAttribute('aria-label', t('viewDetails') + ': ' + value.address + ' · ' + t(kind));
        trigger.addEventListener('click', () => {
            const stages = {connect: 'stageConnect', dns_failed: 'stageDNS', proxy_auth: 'stageAuth', tls_failed: 'stageTLS', target_unreachable: 'stageTimeout', http: 'stageHTTP', http_status: 'stageHTTPError', rate_limited: 'stageRateLimit', content: 'stageContent'};
            const stage = observation.stage ? (stages[observation.stage] ? t(stages[observation.stage]) + ' (' + observation.stage + ')' : observation.stage) : t('none');
            const fields = [
                ['address', value.address], ['checkType', t(kind)], ['checkResult', t(observation.reachable ? 'reachable' : 'failed') + (observation.expires_at && Date.parse(observation.expires_at) < Date.now() ? ' · ' + t('stale') : '')],
                ['target', observation.target || (kind === 'reachability' ? byId('network-target').value : '') || t('none')],
                ['checkStage', stage], ['httpStatus', observation.http_status || t('none')], ['latency', observation.latency_ms + ' ms'],
                ['observedAt', observation.observed_at || t('none')], ['expiresAt', observation.expires_at || t('none')], ['errorReason', observation.reason || t('none')]
            ];
            showDetails(fields.map(([key, detail]) => t(key) + ': ' + detail).join('\n\n'));
        });
        cell.append(trigger); return cell;
    }
    async function copyObservationDetails() {
        const details = byId('network-observation-details');
        try {
            if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(details.value);
                setMessage('network-observation-dialog-message', t('detailsCopied')); return;
            }
        } catch { /* Keep full text selectable when browser clipboard access is denied. */ }
        details.focus(); details.select();
        let copied = false;
        try { copied = typeof document.execCommand === 'function' && document.execCommand('copy'); } catch { /* Manual copy remains available. */ }
        setMessage('network-observation-dialog-message', t(copied ? 'detailsCopied' : 'detailsManualCopy'));
    }
    function bindingText(binding) {
        const key = binding.excluded || binding.scope_state === 'excluded' ? 'excluded' : binding.scope_state === 'needs_reassessment' ? 'bindingNeedsAssessment' : binding.scope_state === 'out_of_scope' ? 'bindingOutOfScope' : 'associated';
        return t('bindingSummary', {target: binding.target, state: t(key), source: binding.source});
    }
    function vpnText(data) {
        const keys = {stopped: 'vpnStopped', connecting: 'vpnConnecting', ready: 'vpnReady', reconnecting: 'vpnReconnecting', failed: 'vpnFailed'};
        const mode = data.policy?.mode || data.mode || 'auto';
        return [mode === 'fixed_vpn' ? t(keys[data.vpn.state] || 'vpnStopped') : t(mode === 'fixed_proxy' ? 'proxyConfigured' : 'defaultNetwork'), mode === 'fixed_vpn' ? data.vpn.reason : '', mode === 'fixed_proxy' && data.assigned_proxy?.address ? t('assigned', {address: data.assigned_proxy.address}) : '', mode !== 'auto' && data.platform !== 'linux' ? t('linuxRequired') : ''].filter(Boolean).join('; ');
    }
    function sourceText(source) {
        if (!source || source === 'manual') return t('sourceManual');
        if (source === 'subscription') return t('sourceSubscription');
        if (source.startsWith('source:')) return t('sourceCollection');
        return source;
    }
    async function saveNodeEdit() {
        requireAdmin(); const id = editingNodeID, sequence = editSequence;
        if (!id) return;
        await request(`/api/network/proxies/${encodeURIComponent(id)}`, json('PUT', {address: byId('network-edit-address').value.trim()}));
        if (sequence === editSequence) { byId('network-edit-dialog').close(); byId('network-edit-address').value = ''; editingNodeID = ''; }
        await loadPool();
    }
    function renderPool() {
        const body = byId('network-rows'); if (!body) return;
        const filter = (byId('network-filter')?.value || '').trim().toLowerCase();
        const state = byId('network-filter-state')?.value || 'all';
        const candidates = poolData.filter(({node: value}) => {
            if (filter && !`${value.address} ${value.source || 'manual'} ${sourceText(value.source)}`.toLowerCase().includes(filter)) return false;
            if (state === 'enabled') return value.enabled;
            if (state === 'disabled') return !value.enabled;
            if (state === 'passed' || state === 'failed') { const o = poolObservations[value.id]; return !!o && o.reachable === (state === 'passed'); }
            return true;
        });
        poolFilteredCount = candidates.length; poolPages = Math.max(1, Math.ceil(candidates.length / poolPageSize)); poolPage = Math.min(poolPage, poolPages - 1);
        const rows = candidates.slice(poolPage * poolPageSize, (poolPage + 1) * poolPageSize).map(candidate => {
            const value = candidate.node; const row = node('tr'); row.dataset.networkNode = value.id;
            const selection = node('td'); const check = node('input'); check.type = 'checkbox'; check.id = 'network-select-' + value.id; check.checked = selectedNodes.has(value.id); check.setAttribute('aria-label', t('selection') + ' ' + value.address);
            check.addEventListener('change', () => { if (check.checked) selectedNodes.add(value.id); else selectedNodes.delete(value.id); updatePagerControls(); });
            const selectionTarget = node('label', undefined, 'network-selection-control'); selectionTarget.append(adminControl(check)); selection.append(selectionTarget);
            const auth = node('td', undefined, 'network-auth'); auth.append(value.has_auth ? label('span', 'configured', 'network-auth-set') : label('span', 'none', 'network-muted'));
            const statusCell = node('td'); statusCell.append(pill(value.enabled ? 'enabled' : 'disabled', value.enabled ? 'ok' : 'off'));
            const addressCell = node('td', value.address, 'network-address'); addressCell.title = value.address;
            const sourceCell = node('td', sourceText(value.source), 'network-source-cell network-muted'); sourceCell.title = sourceCell.textContent;
            row.append(selection, addressCell, sourceCell, auth, statusCell);
            row.append(observationCell(value, candidate.observation, 'reachability'), observationCell(value, poolObservations[value.id], 'poolValidation'));
            const actions = node('td', undefined, 'network-action-cell');
            const rowActions = node('div', undefined, 'network-actions network-row-actions'); rowActions.append(poolJobButton('diagnose', () => diagnose([value.id])));
            const management = adminControl(node('div', undefined, 'network-actions'));
            const update = async changes => { requireAdmin(); await request(`/api/network/proxies/${encodeURIComponent(value.id)}`, json('PUT', changes)); await loadPool(); };
            management.append(button(value.enabled ? 'disable' : 'enable', () => update({enabled: !value.enabled})));
            const removeButton = button('remove', async () => { requireAdmin(); if (!window.confirm(t('removeNode', {address: value.address}))) return; await request(`/api/network/proxies/${encodeURIComponent(value.id)}`, {method: 'DELETE'}); await loadPool(); }); removeButton.className = 'btn btn-secondary network-danger';
            management.append(button('edit', () => {
                requireAdmin(); editSequence++; editingNodeID = value.id;
                byId('network-edit-current').textContent = value.address;
                byId('network-edit-address').value = ''; setMessage('network-edit-dialog-message', ''); openDialog('network-edit-dialog');
            }), removeButton);
            rowActions.append(management); actions.append(rowActions); row.append(actions); return row;
        });
        if (!rows.length) { const row = node('tr'); const cell = label('td', poolData.length ? 'noMatches' : 'empty'); cell.colSpan = 8; row.append(cell); rows.push(row); }
        body.replaceChildren(...rows); refreshPermissions(); updatePagerControls();
    }
    function updatePagerControls() {
        const previous = byId('network-page-previous'), next = byId('network-page-next'), summary = byId('network-page-summary');
        if (previous) previous.disabled = poolPage === 0; if (next) next.disabled = poolPage >= poolPages - 1;
        if (summary) summary.textContent = t('pageSummary', {total: poolFilteredCount, page: poolPage + 1, pages: poolPages, selected: selectedNodes.size});
        const count = byId('network-pool-count'); if (count) count.textContent = t('poolCount', {count: poolData.length});
        byId('network-rows')?.querySelectorAll('tr').forEach(row => { if (row.dataset.networkNode) row.dataset.networkSelected = String(selectedNodes.has(row.dataset.networkNode)); });
    }
    async function loadPool() {
        const sequence = ++poolSequence; const target = byId('network-target')?.value.trim() || '';
        const data = await request('/api/network/proxies' + (target ? `?target=${encodeURIComponent(target)}` : ''));
        if (sequence !== poolSequence || (byId('network-target')?.value.trim() || '') !== target) return false;
        poolData = data.candidates || (data.nodes || []).map(value => ({node: value}));
        // Candidate health ranking is for Agent selection; the table uses a stable node order.
        poolData.sort((a, b) => a.node.id < b.node.id ? -1 : a.node.id > b.node.id ? 1 : 0);
        poolObservations = data.pool_observations || {};
        const ids = new Set(poolData.map(v => v.node.id)); selectedNodes.forEach(id => { if (!ids.has(id)) selectedNodes.delete(id); }); renderPool(); return true;
    }
    async function importNodes() {
        requireAdmin(); const input = byId('network-import'); const addresses = input.value;
        if (!addresses.trim()) throw new Error(t('importRequired'));
        if (new TextEncoder().encode(addresses).length > 2 * 1024 * 1024) throw new Error(t('inputLimit'));
        const result = await request('/api/network/proxies', json('POST', {addresses}));
        if (input.value === addresses) input.value = ''; message(importSummary(result)); await loadPool();
    }
    function updateSourceFields() {
        const subscription = byId('network-source-kind').value === 'subscription';
        byId('network-source-query').closest('label').hidden = subscription;
        byId('network-source-url').closest('label').hidden = !subscription;
        const kind = byId('network-source-kind').value;
        const preset = ['fofa', 'quake', 'hunter'].includes(kind);
        byId('network-source-presets').hidden = !preset;
        byId('network-source-query-hint').textContent = subscription ? '' : t(preset ? 'queryHint' : 'queryCustomHint');
        byId('network-source-query').closest('label').querySelector('span').textContent = t('queryLabel', {engine: sourceNames[kind] || ''});
        byId('network-source-no-auth').closest('label').hidden = byId('network-source-protocol').value !== 'socks5';
        updateSourceProviderStatus();
    }

    function updateSourceProviderStatus() {
        const notice = byId('network-source-provider-status'), crawl = byId('network-source-crawl');
        if (!notice || !crawl) return;
        const kind = byId('network-source-kind').value, engine = sourceNames[kind] || kind;
        const missing = kind !== 'subscription' && sourceProviders.get(kind) === false;
        const key = kind === 'subscription' ? 'providerSubscription' : sourceProvidersLoading ? 'providerLoading' : sourceProvidersFailed ? 'providerLoadFailed' : missing ? (kind === 'hunter' ? 'providerHunterMissing' : 'providerMissing') : sourceProviders.get(kind) === true ? 'providerConfigured' : '';
        notice.textContent = key ? t(key, {engine}) : ''; notice.dataset.state = sourceProvidersFailed || missing ? 'warning' : sourceProvidersLoading ? 'loading' : 'ready';
        const engineBlocked = kind !== 'subscription' && (sourceProvidersLoading || sourceProvidersFailed || missing);
        crawl.disabled = !!poolJob || sourceSaving || engineBlocked;
        crawl.setAttribute('aria-disabled', String(crawl.disabled));
    }

    async function loadSourceProviders() {
        const sequence = ++sourceProvidersSequence;
        sourceProvidersLoading = true; sourceProvidersFailed = false; updateSourceProviderStatus();
        try {
            const data = await request('/api/network/sources');
            if (sequence !== sourceProvidersSequence) return;
            sourceProviders = new Map((data.providers || []).map(provider => [provider.kind, provider.configured === true]));
        } catch (error) {
            if (sequence === sourceProvidersSequence) sourceProvidersFailed = true;
            throw error;
        } finally {
            if (sequence === sourceProvidersSequence) { sourceProvidersLoading = false; updateSourceProviderStatus(); }
        }
    }
    function resetSourceForm() {
        sourceDrafts = {}; generatedQueries = {}; activeSourceKind = 'fofa';
        byId('network-source-kind').value = 'fofa'; byId('network-source-protocol').value = 'socks5'; byId('network-source-country').value = 'CN'; byId('network-source-no-auth').checked = true;
        setSourceDraft('fofa'); updateSourceFields();
    }
    function sourceQueryPreset(kind) {
        if (!['fofa', 'quake', 'hunter'].includes(kind)) return '';
        const protocol = byId('network-source-protocol').value;
        if (!['socks5', 'http', 'https'].includes(protocol)) return '';
        const country = byId('network-source-country').value.trim().toUpperCase();
        if (country && !/^[A-Z]{2}$/.test(country)) throw new Error(t('queryCountryInvalid'));
        const noAuth = protocol === 'socks5' && byId('network-source-no-auth').checked;
        if (kind === 'fofa') return `protocol="${protocol}"` + (country ? ` && country="${country}"` : '') + (noAuth ? ' && banner="Method:No Authentication"' : '');
        if (kind === 'quake') return `service:${protocol}` + (country ? ` AND country: "${country}"` : '') + (noAuth ? ' AND response:"No authentication"' : '');
        if (kind === 'hunter') return `protocol="${protocol}"` + (country ? ` && ip.country="${country}"` : '') + (noAuth ? ' && protocol.banner="No authentication"' : '');
        return '';
    }
    function applySourcePreset() {
        requireAdmin(); const kind = byId('network-source-kind').value, query = byId('network-source-query');
        const preset = sourceQueryPreset(kind); if (!preset) return;
        if (query.value.trim() && query.value !== generatedQueries[kind] && !window.confirm(t('queryReplace'))) return;
        query.value = preset; generatedQueries[kind] = preset; updateSourceFields();
    }
    function rememberSourceDraft() {
        const draft = {id: editingSourceID};
        for (const key of ['name', 'query', 'limit', 'url']) draft[key] = byId('network-source-' + key).value;
        sourceDrafts[activeSourceKind] = draft;
    }
    function setSourceDraft(kind) {
        const draft = sourceDrafts[kind];
        editingSourceID = draft?.id || '';
        for (const key of ['name', 'query', 'limit', 'url']) byId('network-source-' + key).value = draft?.[key] || '';

        if (!draft) {
            byId('network-source-name').value = kind === 'subscription' ? '' : t('sourceDefaultName', {engine: sourceNames[kind]});
            byId('network-source-limit').value = String({fofa: 5000, quake: 300, hunter: 200}[kind] || 100);
            const preset = sourceQueryPreset(kind); byId('network-source-query').value = preset; generatedQueries[kind] = preset;
        }
    }
    function changeSourceKind() {
        const next = byId('network-source-kind').value;
        try { if (!sourceDrafts[next]) sourceQueryPreset(next); } catch (error) { byId('network-source-kind').value = activeSourceKind; message(error.message); return; }
        rememberSourceDraft(); activeSourceKind = next; setSourceDraft(activeSourceKind); updateSourceFields();
    }
    async function crawlSource() {
        requireAdmin(); if (poolJob || sourceSaving) throw new Error(t('jobBusy'));
        const kind = byId('network-source-kind').value;
        if (kind !== 'subscription' && (sourceProvidersLoading || sourceProvidersFailed || sourceProviders.get(kind) === false)) throw new Error(byId('network-source-provider-status').textContent || t('providerLoadFailed'));
        const limit = Number(byId('network-source-limit').value);
        if (!Number.isInteger(limit) || limit < 1 || limit > 10000) throw new Error(t('crawlLimitInvalid'));
        const value = {id: editingSourceID, name: byId('network-source-name').value.trim(), kind: byId('network-source-kind').value, query: byId('network-source-query').value.trim(), url: byId('network-source-url').value.trim(), limit};
        sourceSaving = true; refreshPoolJobControls(); translatedMessage('network-message', 'syncing');
        try {
            const saved = await request('/api/network/sources', json('POST', value));
            if (!saved.id) throw new Error(t('crawlConfigFailed'));
            editingSourceID = saved.id; activeSourceKind = value.kind;
            byId('network-source-url').value = '';
            rememberSourceDraft(); updateSourceFields();
            await syncSource(saved.id);
        } finally { sourceSaving = false; refreshPoolJobControls(); }
    }
    function importSummary(result, key = 'importResult') {
        const unsupported = Object.entries(result.unsupported || {}).map(([kind, count]) => `${kind}: ${count}`).join(', ');
        return t(key, result) + (unsupported ? '\n' + t('unsupportedProtocols', {protocols: unsupported}) : '');
    }
    async function syncSource(id) {
        requireAdmin(); const result = await runPoolJob(`/api/network/sources/${encodeURIComponent(id)}/sync`, {}, 'syncing');
        if (result) { message(importSummary(result, 'crawled')); await loadPool(); }
    }
    function selectionField(key, id, options) {
        const wrapper = node('label', undefined, 'network-field'); wrapper.append(label('span', key)); const select = node('select', undefined, 'form-input'); select.id = id; select.setAttribute('aria-label', t(key));
        options.forEach(([value, key]) => { const option = /^\d+$/.test(key) ? node('option', key) : label('option', key); option.value = value; select.append(option); }); select.value = options[0][0]; wrapper.append(select); return wrapper;
    }
    function dialog(id, key) {
        const panel = node('dialog', undefined, 'network-dialog network-card'); panel.id = id; panel.setAttribute('aria-labelledby', id + '-title');
        const header = node('div', undefined, 'network-dialog-header'); const title = label('h2', key); title.id = id + '-title'; header.append(title, button('close', () => panel.close()));
        const notice = node('p', '', 'network-message'); notice.id = id + '-message'; notice.setAttribute('role', 'status'); panel.append(header, notice);
        panel.addEventListener('click', e => {
            if (e.target !== panel) return;
            const rect = panel.getBoundingClientRect();
            if (e.clientX < rect.left || e.clientX > rect.right || e.clientY < rect.top || e.clientY > rect.bottom) panel.close();
        }); return panel;
    }
    function finishDialog(panel, fields, actions, pausable = false) {
        const header = panel.querySelector('.network-dialog-header');
        const notice = panel.querySelector('#' + panel.id + '-message');
        const body = node('div', undefined, 'network-dialog-body'); body.append(...fields);
        const footer = node('div', undefined, 'network-dialog-footer'); footer.append(notice);
        if (pausable) {
            const progress = node('div', '', 'network-job-status'); progress.setAttribute('data-job-progress', 'true'); progress.setAttribute('role', 'status'); progress.hidden = true; footer.append(progress);
        }
        const controls = node('div', undefined, 'network-actions network-dialog-actions'); controls.append(...actions);
        if (pausable) {
            const cancel = button('cancelJob', async () => { await byId('network-job-cancel').click(); }); cancel.setAttribute('data-dialog-cancel', 'true'); cancel.hidden = true;
            controls.append(pauseJobButton(), cancel);
        }
        footer.append(controls); panel.replaceChildren(header, body, footer);
    }
    function primaryControl(control) { control.className += ' network-primary'; return control; }
    function openDialog(id) { requireAdmin(); const panel = byId(id); if (!panel.open) panel.showModal(); }
    function openDialogButton(key, id, dialogID, action) { const e = adminControl(button(key, async () => { openDialog(dialogID); if (action) await action(); })); e.id = id; return e; }
    async function importSubscription() {
        requireAdmin(); const input = byId('network-subscription-input'); const content = input.value.trim(); if (!content) throw new Error(t('importRequired'));
        if (new TextEncoder().encode(content).length > 2 * 1024 * 1024) throw new Error(t('inputLimit'));
        const value = {};
        if (byId('network-subscription-kind').value === 'urls') { value.urls = content.split(/\r?\n/).map(v => v.trim()).filter(Boolean); if (value.urls.length > 20) throw new Error(t('inputLimit')); } else value.content = content;
        const result = await runPoolJob('/api/network/subscriptions/import', value, 'syncing');
        if (result) { if (input.value.trim() === content) input.value = ''; message(importSummary(result)); await loadPool(); }
    }
    async function loadValidation() {
        const sequence = ++validationSequence; validationLoading = true; validationReady = false; refreshValidationControls();
        try {
            const value = await request('/api/network/validation'); if (sequence !== validationSequence) return;
            byId('network-validation-target').value = value.target || '';
            if (!byId('network-target').value.trim()) byId('network-target').value = value.target || '';
            byId('network-validation-contains').value = value.contains || ''; byId('network-validation-action').value = value.failure_action || 'keep'; byId('network-validation-threshold').value = String(value.failure_threshold || 3); validationReady = true;
        } finally { if (sequence === validationSequence) { validationLoading = false; refreshValidationControls(); } }
    }
    function refreshValidationControls() {
        for (const key of ['target', 'contains', 'action', 'threshold', 'save', 'save-run']) { const e = byId('network-validation-' + key); if (e) e.disabled = validationLoading || !validationReady || key === 'save-run' && !!poolJob || !!e.dataset.networkBusy; }
    }
    async function saveValidation(andValidate = false) {
        if (validationLoading || !validationReady) return;
        requireAdmin(); const value = {target: byId('network-validation-target').value.trim(), contains: byId('network-validation-contains').value, failure_action: byId('network-validation-action').value, failure_threshold: Number(byId('network-validation-threshold').value)};
        await request('/api/network/validation', json('PUT', value));
        poolObservations = {};
        renderPool();
        translatedMessage('network-message', 'validationSaved');
        await loadPool();
        if (andValidate) await validatePool(false);
    }
    async function validatePool(selected) {
        requireAdmin(); if (selected && !selectedNodes.size) throw new Error(t('bulkNoSelection'));
        const result = await runPoolJob('/api/network/validate', {node_ids: selected ? [...selectedNodes] : []}, 'diagnosing');
        if (result) { message(t('validationSummary', result) + (result.pruning_suppressed ? '\n' + t('cleanupSuppressed') : '') + (result.reason ? '\n' + result.reason : '')); await loadPool(); }
    }
    async function applyBulk(ids, action) {
        const total = {updated: 0, skipped: 0};
        try {
            for (let offset = 0; offset < ids.length; offset += 1000) {
                requireAdmin();
                const result = await request('/api/network/proxies/bulk', json('POST', {node_ids: ids.slice(offset, offset + 1000), action}));
                total.updated += result.updated; total.skipped += result.skipped;
            }
            message(t('bulkDone', total));
        } finally { await loadPool(); }
    }
    async function mutatePool(run) {
        requireAdmin(); if (poolMutationBusy) throw new Error(t('mutationBusy'));
        poolMutationBusy = true;
        try { await run(); } finally { poolMutationBusy = false; }
    }
    async function bulkNodes() {
        await mutatePool(async () => {
            const ids = [...selectedNodes]; if (!ids.length) throw new Error(t('bulkNoSelection'));
            const action = byId('network-bulk-action').value;
            if (action === 'delete' && !window.confirm(t('bulkConfirm', {count: ids.length}))) return;
            await applyBulk(ids, action);
        });
    }
    async function deleteAllNodes() {
        await mutatePool(async () => {
            // Read the global inventory, independent of target diagnostics and display filters.
            const data = await request('/api/network/proxies');
            const ids = (data.nodes || []).map(value => value.id);
            if (!ids.length) { message(t('poolEmpty')); return; }
            if (!window.confirm(t('deleteAllConfirm', {count: ids.length}))) return;
            await applyBulk(ids, 'delete');
        });
    }
    function buildPool() {
        if (byId('page-network')) return;
        const anchor = document.querySelector('.nav-item[data-page="projects"]');
        if (anchor) {
            const nav = node('div', undefined, 'nav-item'); nav.dataset.page = 'network'; nav.setAttribute('data-require-permission', 'auth:self');
            const content = node('div', undefined, 'nav-item-content'); content.id = 'network-nav-content'; content.setAttribute('data-title', t('nav'));
            const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            for (const [key, value] of Object.entries({width: '20', height: '20', viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round'})) icon.setAttribute(key, value);
            const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', 'M4 7h16m-4-4 4 4-4 4M20 17H4m4-4-4 4 4 4'); icon.append(path);
            content.append(icon, label('span', 'nav')); content.addEventListener('click', () => window.switchPage('network')); nav.append(content); anchor.after(nav);
        }
        const projectPage = byId('page-projects'); if (!projectPage) return;
        const page = node('div', undefined, 'page network-page'); page.id = 'page-network';
        const header = node('div', undefined, 'page-header');
        const title = node('div', undefined, 'network-pool-heading'); const count = node('span', '', 'network-pool-count'); count.id = 'network-pool-count'; title.append(label('h2', 'title'), count); header.append(title);
        const headerActions = node('div', undefined, 'page-header-actions');
        const targetField = field('target', 'network-target', 'https://api.example.com'); targetField.setAttribute('class', 'network-field network-header-target');
        const refresh = button('refresh', loadPool);
        const cancelJob = button('cancelJob', async () => {
            const control = poolJob; if (!control?.id) return;
            await request(`/api/network/jobs/${encodeURIComponent(control.id)}/cancel`, json('POST', {}));
            control.cancelled = true; translatedMessage('network-message', 'jobCancelled');
        }); cancelJob.id = 'network-job-cancel'; cancelJob.hidden = true;
        const exportControl = adminControl(button('export', async () => { requireAdmin(); const response = await window.apiFetch('/api/network/export'); if (!response.ok) throw new Error(t('exportFailed')); const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = node('a'); link.href = url; link.download = 'proxies.txt'; link.click(); URL.revokeObjectURL(url); }));
        const content = node('div', undefined, 'page-content network-content');
        const filters = node('div', undefined, 'network-toolbar network-pool-filters'); filters.append(field('filter', 'network-filter', '', 'text', 'filterHint'));
        const state = node('select', undefined, 'form-input'); state.id = 'network-filter-state'; state.setAttribute('aria-label', t('status'));
        [['all', 'all'], ['enabled', 'enabled'], ['disabled', 'disabled'], ['passed', 'filterPassed'], ['failed', 'filterFailed']].forEach(([value, key]) => { const option = label('option', key); option.value = value; state.append(option); }); state.value = 'all'; filters.append(state);
        const notice = node('button', '', 'network-message network-result-trigger'); notice.type = 'button'; notice.id = 'network-message'; notice.setAttribute('aria-live', 'polite'); notice.setAttribute('aria-haspopup', 'dialog'); notice.addEventListener('click', () => showDetails(notice.textContent));
        const tableWrapper = node('div', undefined, 'network-table-wrapper'); tableWrapper.tabIndex = 0; tableWrapper.setAttribute('role', 'region'); tableWrapper.setAttribute('aria-label', t('title')); const table = node('table', undefined, 'network-table'); const head = node('thead'); const heading = node('tr'); ['selection', 'address', 'source', 'auth', 'status', 'reachability', 'poolValidation', 'actions'].forEach(key => { const th = label('th', key); th.scope = 'col'; heading.append(th); }); head.append(heading); const body = node('tbody'); body.id = 'network-rows'; table.append(head, body); tableWrapper.append(table);
        content.append(filters, notice, tableWrapper);
        const imports = dialog('network-manual-dialog', 'manualAdd');
        const importForm = adminControl(node('div')); importForm.append(field('importAddresses', 'network-import', 'http://127.0.0.1:8080\nsocks5://user:password@127.0.0.1:1080', 'textarea'), label('p', 'importHint', 'network-help'));
        finishDialog(imports, [importForm], [primaryControl(adminControl(button('import', importNodes)))]);
        const sources = dialog('network-source-dialog', 'sourcesTitle');
        const kind = node('select', undefined, 'form-input'); kind.id = 'network-source-kind'; kind.setAttribute('aria-label', t('sourceKind')); [['fofa', 'FOFA'], ['quake', 'Quake'], ['hunter', 'Hunter'], ['zoomeye', 'ZoomEye'], ['shodan', 'Shodan'], ['subscription', t('subscription')]].forEach(([value, text]) => { const option = value === 'subscription' ? label('option', 'subscription') : node('option', text); option.value = value; kind.append(option); }); kind.value = 'fofa'; kind.addEventListener('change', changeSourceKind);
        const presets = node('div', undefined, 'network-query-presets'); presets.id = 'network-source-presets'; presets.append(selectionField('queryProtocol', 'network-source-protocol', [['socks5', 'protocolSOCKS5'], ['http', 'protocolHTTP'], ['https', 'protocolHTTPS']]), field('queryCountry', 'network-source-country', 'CN')); const noAuth = node('label', undefined, 'network-checkbox'); const noAuthCheck = node('input'); noAuthCheck.type = 'checkbox'; noAuthCheck.id = 'network-source-no-auth'; noAuth.append(noAuthCheck, label('span', 'queryNoAuth')); const resetQuery = button('queryReset', applySourcePreset); resetQuery.id = 'network-source-query-reset'; presets.append(noAuth, resetQuery);
        const queryHint = node('p'); queryHint.id = 'network-source-query-hint';
        const providerStatus = node('p'); providerStatus.id = 'network-source-provider-status'; providerStatus.setAttribute('role', 'status');
        const sourceMeta = node('div', undefined, 'network-form-grid network-source-meta');
        const sourceKind = node('label', undefined, 'network-field'); sourceKind.append(label('span', 'sourceKind'), kind);
        sourceMeta.append(field('sourceName', 'network-source-name', '', 'text', 'sourceNameHint'), sourceKind, field('limit', 'network-source-limit', '100', 'number'));
        providerStatus.className = 'network-provider-status'; queryHint.className = 'network-help';
        const crawl = primaryControl(poolJobButton('crawl', crawlSource)); crawl.id = 'network-source-crawl';
        const sourceActions = node('div', undefined, 'network-actions'); sourceActions.id = 'network-source-actions'; sourceActions.append(crawl);
        finishDialog(sources, [sourceMeta, providerStatus, presets, queryHint, field('sourceQuery', 'network-source-query', '', 'textarea'), field('subscription', 'network-source-url', '', 'password', 'sourceURLHint')], [sourceActions], true);
        const subscription = dialog('network-subscription-dialog', 'subscriptionImport');
        const submitSubscription = primaryControl(poolJobButton('import', importSubscription)); submitSubscription.id = 'network-subscription-submit';
        finishDialog(subscription, [selectionField('subscriptionInput', 'network-subscription-kind', [['content', 'subscriptionContentMode'], ['urls', 'subscriptionURLMode']]), field('subscriptionInput', 'network-subscription-input', '', 'textarea'), label('p', 'subscriptionFormatHint', 'network-help')], [submitSubscription], true);
        const validation = dialog('network-validation-dialog', 'validationConfig');
        const cleanup = node('div', undefined, 'network-form-grid'); cleanup.append(selectionField('failureAction', 'network-validation-action', [['keep', 'keep'], ['disable', 'disable'], ['delete', 'delete']]), field('failureThreshold', 'network-validation-threshold', '3', 'number'));
        const saveValidationButton = button('saveOnly', () => saveValidation()); saveValidationButton.id = 'network-validation-save';
        const saveValidate = primaryControl(poolJobButton('saveAndValidate', () => saveValidation(true))); saveValidate.id = 'network-validation-save-run';
        finishDialog(validation, [field('target', 'network-validation-target', 'https://www.baidu.com'), field('contains', 'network-validation-contains'), cleanup, label('p', 'validationHint', 'network-help')], [saveValidationButton, saveValidate], true);
        const workflows = node('div', undefined, 'network-actions network-pool-workflows'); workflows.append(openDialogButton('manualAdd', 'network-open-manual', imports.id), openDialogButton('subscriptionImport', 'network-open-subscription', subscription.id), openDialogButton('collection', 'network-open-sources', sources.id, loadSourceProviders));
        headerActions.append(workflows, exportControl, refresh); header.append(headerActions);
        const validationBar = node('div', undefined, 'network-validation-bar');
        const validationButtons = node('div', undefined, 'network-actions network-validation-actions'); validationButtons.append(openDialogButton('validationConfig', 'network-open-validation', validation.id, loadValidation), adminControl(poolJobButton('validateAll', () => validatePool(false))), adminControl(poolJobButton('validateSelected', () => validatePool(true))), ); validationBar.append(targetField, validationButtons);
        const bulkControls = adminControl(node('span', undefined, 'network-actions network-pool-bulk')); const selectVisible = button('selectVisible', () => { const checks = [...body.querySelectorAll('input')].filter(e => e.type === 'checkbox'); const allSelected = checks.length > 0 && checks.every(e => e.checked); checks.forEach(e => { e.checked = !allSelected; const id = e.id.slice('network-select-'.length); if (e.checked) selectedNodes.add(id); else selectedNodes.delete(id); }); updatePagerControls(); });
        const bulkApply = button('bulkExecute', bulkNodes); bulkApply.id = 'network-bulk-apply'; bulkControls.append(selectVisible, selectionField('bulkManage', 'network-bulk-action', [['enable', 'enable'], ['disable', 'disable'], ['delete', 'remove']]), bulkApply);
        const deleteAll = adminControl(button('deleteAll', deleteAllNodes)); deleteAll.id = 'network-delete-all'; deleteAll.className += ' network-danger';
        const toolbar = node('div', undefined, 'network-pool-toolbar'); toolbar.id = 'network-pool-toolbar'; toolbar.append(filters, bulkControls, deleteAll);
        const editor = dialog('network-edit-dialog', 'editNode');
        const currentAddress = node('p', '', 'network-edit-current'); currentAddress.id = 'network-edit-current';
        const saveEdit = button('save', saveNodeEdit); saveEdit.id = 'network-edit-save';
        finishDialog(editor, [label('p', 'currentProxy', 'network-help'), currentAddress, field('editAddress', 'network-edit-address', 'socks5://user:password@127.0.0.1:1080', 'password')], [button('cancel', () => { editor.close(); byId('network-edit-address').value = ''; editingNodeID = ''; }), primaryControl(saveEdit)]);
        editor.addEventListener('close', () => { byId('network-edit-address').value = ''; editingNodeID = ''; });
        const pager = node('div', undefined, 'network-toolbar network-pager'); const previous = button('previousPage', () => { poolPage--; renderPool(); }); previous.id = 'network-page-previous'; previous.dataset.poolPage = 'true'; const next = button('nextPage', () => { poolPage++; renderPool(); }); next.id = 'network-page-next'; next.dataset.poolPage = 'true'; const pageSummary = node('span', undefined, 'network-pager-summary'); pageSummary.id = 'network-page-summary'; pageSummary.setAttribute('role', 'status'); const pageSize = selectionField('pageSize', 'network-page-size', [20, 50, 100, 200, 500].map(size => [String(size), String(size)]));
        const sizeSelect = pageSize.querySelector('select'); sizeSelect.value = String(poolPageSize); sizeSelect.addEventListener('change', () => { const size = Number(sizeSelect.value); if ([20, 50, 100, 200, 500].includes(size)) { poolPageSize = size; poolPage = 0; renderPool(); } else sizeSelect.value = String(poolPageSize); });
        pager.append(notice, pageSize, pageSummary, previous, next);
        const detailsDialog = dialog('network-observation-dialog', 'observationDetails'); detailsDialog.dataset.networkReadOnly = 'true';
        const detailsField = field('detailsText', 'network-observation-details', '', 'textarea'); detailsField.querySelector('textarea').readOnly = true;
        const copyDetails = button('copyDetails', copyObservationDetails, text => setMessage('network-observation-dialog-message', text)); copyDetails.id = 'network-observation-copy';
        finishDialog(detailsDialog, [detailsField], [primaryControl(copyDetails)]);
        const jobStatus = node('div', '', 'network-job-status'); jobStatus.id = 'network-job-status'; jobStatus.hidden = true; jobStatus.setAttribute('role', 'status'); jobStatus.setAttribute('data-job-progress', 'true');
        const taskBar = node('div', undefined, 'network-task-bar'); taskBar.setAttribute('data-job-container', 'true'); taskBar.hidden = true;
        const progress = node('progress'); progress.id = 'network-task-progress'; progress.hidden = true; progress.setAttribute('aria-label', t('taskProgress'));
        const taskSummary = node('div', undefined, 'network-task-summary'); taskSummary.append(jobStatus, progress);
        const taskActions = node('div', undefined, 'network-actions'); taskActions.append(pauseJobButton('network-job-pause'), cancelJob); taskBar.append(taskSummary, taskActions);
        content.replaceChildren(validationBar, toolbar, taskBar, tableWrapper, pager, imports, sources, subscription, validation, editor, detailsDialog);
        page.append(header, content); projectPage.parentNode.append(page);
        resetSourceForm(); byId('network-source-limit').min = '1'; byId('network-source-limit').max = '10000';
        for (const key of ['protocol', 'country', 'no-auth']) byId('network-source-' + key).addEventListener('change', () => { try { applySourcePreset(); } catch (error) { message(error.message); } });
        byId('network-source-country').maxLength = 2;
        byId('network-validation-threshold').min = '1'; byId('network-validation-threshold').max = '10';
        byId('network-filter').addEventListener('input', () => { poolPage = 0; renderPool(); }); state.addEventListener('change', () => { poolPage = 0; renderPool(); });
        byId('network-target').addEventListener('input', () => { poolSequence++; poolData = poolData.map(value => ({node: value.node})); renderPool(); message(''); });
        if (typeof MutationObserver !== 'undefined') new MutationObserver(refreshPermissions).observe(page, {subtree: true, attributes: true, attributeFilter: ['hidden', 'aria-hidden']});
    }
    async function openPool() {
        buildPool(); refreshPermissions(); translatedMessage('network-message', 'loading');
        try { if (await loadPool()) { message(''); loadValidation().catch(() => {}); restorePoolJob().catch(error => message(error.message)); } } catch (error) { message(error.message); }
    }
    function projectDraftSnapshot() {
        return JSON.stringify(['mode','targets','dns','proxy','username','password','asset','config','certificates'].map(name => {
            const input = byId('project-network-' + name);
            return input?.type === 'file' ? Array.from(input.files || []).map(file => [file.name,file.size,file.lastModified]) : input?.value || '';
        }));
    }
    function hasProjectDraft() { return !!projectPolicy && projectDraftBaseline !== null && projectDraftSnapshot() !== projectDraftBaseline; }
    function currentProject(id, sequence) { return projectID === id && projectSequence === sequence; }
    function projectCanWrite() { return typeof window.hasPermission === 'function' && window.hasPermission('project:write'); }
    function updateProjectControls() {
        const card = byId('project-network-card'); if (!card) return;
        const mode = byId('project-network-mode').value;
        card.querySelectorAll('input, textarea, select, button').forEach(e => {
            const available = e.dataset.projectAction === 'cancel' ? !!projectOperation?.jobID && projectCanWrite() : e.dataset.projectAction === 'refresh' ? !!projectID && !projectBusy && !projectOperation : !!projectPolicy && !projectBusy && !projectOperation && projectCanWrite();
            const modeDisabled = e.id === 'project-network-proxy' ? mode !== 'fixed_proxy' : ['project-network-config', 'project-network-certificates', 'project-network-dns', 'project-network-username', 'project-network-password'].includes(e.id) ? mode !== 'fixed_vpn' : false;
            const busy = !!e.dataset.networkBusy && (!e.dataset.busyProject || e.dataset.busyProject === projectID);
            const disabled = !available || busy || modeDisabled || !!e.dataset.vpnAction && (mode !== 'fixed_vpn' || projectPolicy?.mode !== 'fixed_vpn' || !projectPolicy?.vpn_profile_id);
            e.disabled = disabled; e.setAttribute('aria-disabled', String(disabled)); if (disabled) e.dataset.stateDisabled = 'true'; else delete e.dataset.stateDisabled;
            if (['project-network-proxy','project-network-config','project-network-certificates','project-network-dns','project-network-username','project-network-password'].includes(e.id)) {
                const field = e.closest('.network-field'); if (field) field.hidden = modeDisabled;
            }
            if (e.dataset.vpnAction) e.hidden = mode !== 'fixed_vpn';
        });
        const cancel = byId('project-network-job-cancel'); if (cancel) cancel.hidden = !projectOperation?.jobID;
        window.ProjectSettingsUI?.refresh();
    }
    function clearProjectForm() {
        projectPolicy = null; projectBusy = false;
        for (const id of ['targets', 'dns', 'proxy', 'config', 'certificates', 'asset', 'username', 'password']) { const e = byId('project-network-' + id); if (e) e.value = ''; }
        projectDraftBaseline = null;
        byId('project-network-mode').value = 'auto'; byId('project-network-bindings').replaceChildren(); setMessage('project-network-status', ''); setMessage('project-network-profile-hint', ''); updateProjectControls();
    }
    async function loadProject(id, initialScope = '') {
        clearTimeout(projectRefreshTimer);
        projectRefreshSequence++;
        const sequence = ++projectSequence; projectID = id; projectOperation = null; buildProject(); clearProjectForm(); translatedMessage('project-network-message', 'loading');
        try {
            const data = await request(`/api/projects/${encodeURIComponent(id)}/network-policy`);
            if (!currentProject(id, sequence)) return false;
            projectPolicy = data.policy;
            byId('project-network-mode').value = data.policy.mode || 'auto';
            byId('project-network-targets').value = (data.policy.targets?.length ? data.policy.targets : data.declared_scope?.targets || data.scope.targets || parseTargets(initialScope)).join('\n');
            byId('project-network-dns').value = (data.policy.dns_servers || []).join('\n');
            projectMessage(''); renderProjectStatus(data); renderBindings(data.bindings || []); updateProjectControls(); projectDraftBaseline = projectDraftSnapshot(); window.ProjectSettingsUI?.refresh(); scheduleProjectRefresh(id, sequence); return true;
        } catch (error) { if (currentProject(id, sequence)) { clearProjectForm(); projectMessage(error.message); } return false; }
    }
    function renderProjectStatus(data) {
        setMessage('project-network-status', vpnText(data)); byId('project-network-status').setAttribute('data-network-vpn', JSON.stringify({mode: data.policy.mode, vpn: data.vpn, assigned_proxy: data.assigned_proxy, platform: data.platform}));
        const hint = data.policy.vpn_profile_id ? 'profileSaved' : 'profileMissing';
        translatedMessage('project-network-profile-hint', hint); byId('project-network-profile-hint').hidden = byId('project-network-mode').value !== 'fixed_vpn';
        translatedMessage('project-network-auth-hint', data.vpn_has_auth ? 'vpnAuthConfigured' : 'vpnAuthMissing'); byId('project-network-auth-hint').hidden = byId('project-network-mode').value !== 'fixed_vpn';
    }
    async function refreshProject(id, sequence) {
        if (!projectPolicy) return loadProject(id);
        const refreshSequence = ++projectRefreshSequence;
        const data = await request(`/api/projects/${encodeURIComponent(id)}/network-policy`);
        if (!currentProject(id, sequence) || refreshSequence !== projectRefreshSequence) return;
        renderProjectStatus(data); renderBindings(data.bindings || []);
        updateProjectControls();
        if (projectPolicy && data.policy.version !== projectPolicy.version) translatedMessage('project-network-message', 'policyChanged');
    }
    function scheduleProjectRefresh(id, sequence) {
        // Only observe a visible project; refresh never rewrites draft fields or file inputs.
        if (typeof document.visibilityState === 'undefined') return;
        projectRefreshTimer = setTimeout(async () => {
            if (!currentProject(id, sequence)) return;
            try {
                const panel = byId('project-panel-settings');
                if (document.visibilityState === 'visible' && panel?.getClientRects().length && !projectBusy && !projectOperation) await refreshProject(id, sequence);
            } catch (error) { if (currentProject(id, sequence)) projectMessage(error.message); }
            finally { if (currentProject(id, sequence)) scheduleProjectRefresh(id, sequence); }
        }, 3000);
    }
    function projectButton(key, run, action = 'write') {
        const e = button(key, async () => {
            const id = projectID, sequence = projectSequence;
            projectRefreshSequence++;
            const operation = {id}; projectOperation = operation; updateProjectControls();
            try { await run(id, sequence); } catch (error) { if (currentProject(id, sequence)) projectMessage(error.message); }
            finally { if (projectOperation === operation) { projectOperation = null; updateProjectControls(); } }
        }, projectMessage);
        e.dataset.projectAction = action;
        if (key === 'connect' || key === 'disconnect') e.dataset.vpnAction = 'true';
        if (action !== 'refresh') e.setAttribute('data-require-permission', 'project:write');
        return e;
    }
    function renderBindings(bindings) {
        const id = projectID, sequence = projectSequence;
        const snapshot = JSON.stringify([id, sequence, bindings]);
        if (snapshot === bindingsSnapshot) return;
        bindingsSnapshot = snapshot;
        byId('project-network-bindings').replaceChildren(...bindings.map(binding => {
            const row = node('div', undefined, 'network-source'); const summary = node('span', bindingText(binding)); summary.setAttribute('data-network-binding', JSON.stringify(binding)); row.append(summary);
            row.append(projectButton(binding.excluded ? 'restore' : 'exclude', async () => {
                if (!currentProject(id, sequence)) return;
                await request(`/api/projects/${encodeURIComponent(id)}/network-assets`, json('POST', {target: binding.target, excluded: !binding.excluded, evidence: t('userAdjustEvidence')}));
                if (currentProject(id, sequence)) { projectMessage(''); await refreshProject(id, sequence); }
            })); return row;
        }));
    }
    async function saveProject(id, sequence) {
        if (!id || !projectPolicy) throw new Error(t('notLoaded'));
        // Snapshot before reading files: the user may switch projects while file.text() awaits.
        const snapshot = {policy: JSON.parse(JSON.stringify(projectPolicy)), mode: byId('project-network-mode').value, targets: parseTargets(byId('project-network-targets').value), dns: parseTargets(byId('project-network-dns').value), proxy: byId('project-network-proxy').value.trim(), config: byId('project-network-config').files?.[0], certificates: Array.from(byId('project-network-certificates').files || []), username: byId('project-network-username').value.trim(), password: byId('project-network-password').value};
        if (snapshot.mode === 'fixed_vpn' && snapshot.certificates.length && !snapshot.config) throw new Error(t('configRequiredForCerts'));
        const hasCredentials = !!(snapshot.username || snapshot.password);
        if (snapshot.mode === 'fixed_vpn' && hasCredentials && (!snapshot.username || !snapshot.password)) throw new Error(t('vpnAuthPairRequired'));
        projectBusy = true; updateProjectControls(); translatedMessage('project-network-message', 'saving');
        try {
            let path = 'network-policy', method = 'PUT', value = {...snapshot.policy, mode: snapshot.mode, targets: snapshot.targets, dns_servers: snapshot.dns, proxy_address: snapshot.proxy};
            if (snapshot.mode === 'fixed_vpn' && (snapshot.config || hasCredentials)) {
                if (snapshot.config?.size > 2 * 1024 * 1024) throw new Error(t('profileLimit'));
                const files = {}; let total = snapshot.config?.size || 0;
                for (const file of snapshot.certificates) { total += file.size; if (file.size > 1024 * 1024 || total > 4 * 1024 * 1024) throw new Error(t('certLimit')); files[file.name] = await file.text(); if (!currentProject(id, sequence)) return; }
                const config = snapshot.config ? await snapshot.config.text() : ''; if (!currentProject(id, sequence)) return;
                path = 'vpn-profile'; method = 'POST'; value = {config, files, targets: snapshot.targets, dns_servers: snapshot.dns, version: snapshot.policy.version};
                if (hasCredentials) value.credentials = {username: snapshot.username, password: snapshot.password};
            }
            if (!currentProject(id, sequence)) return;
            await request(`/api/projects/${encodeURIComponent(id)}/${path}`, json(method, value));
            if (!currentProject(id, sequence)) return;
            if (await loadProject(id)) translatedMessage('project-network-message', 'saved');
            else if (currentProject(id, sequence + 1)) translatedMessage('project-network-message', 'savedRefreshFailed');
        } finally { if (currentProject(id, sequence)) { projectBusy = false; updateProjectControls(); } }
    }
    async function vpnAction(action, id, sequence) {
        if (!id) return;
        const operation = projectOperation;
        const data = await request(`/api/projects/${encodeURIComponent(id)}/vpn/${action}`, json('POST', {}));
        if (!currentProject(id, sequence)) return;
        if (data.job_id) { operation.jobID = data.job_id; operation.cancelMessage = 'vpnJobCancelled'; updateProjectControls(); translatedMessage('project-network-message', 'connecting'); await waitJob(data.job_id, operation); }
        if (currentProject(id, sequence)) { projectMessage(''); await refreshProject(id, sequence); }
    }
    async function bindAsset(excluded, id, sequence) {
        const target = byId('project-network-asset').value.trim();
        await request(`/api/projects/${encodeURIComponent(id)}/network-assets`, json('POST', {target, excluded, evidence: t('userAssetEvidence')}));
        if (currentProject(id, sequence)) { if (byId('project-network-asset').value.trim() === target) byId('project-network-asset').value = ''; projectMessage(''); await refreshProject(id, sequence); }
    }
    function buildProject() {
        if (byId('project-network-card')) return;
        const panel = byId('project-panel-settings'); if (!panel) return;
        const card = node('section', undefined, 'network-card'); card.id = 'project-network-card';
        const head = node('div', undefined, 'projects-settings-card-head'); const heading = node('div'); heading.append(label('h3', 'projectTitle'), label('p', 'projectIntro', 'projects-settings-card-hint')); head.append(heading); card.append(head);
        const draftNotice = node('p', '', 'project-network-draft'); draftNotice.id = 'project-network-draft'; draftNotice.hidden = true; card.append(draftNotice);
        const mode = node('select', undefined, 'form-input'); mode.id = 'project-network-mode'; mode.setAttribute('aria-label', t('projectTitle'));
        [['auto', 'modeAuto'], ['fixed_proxy', 'modeProxy'], ['fixed_vpn', 'modeVPN']].forEach(([value, key]) => { const option = label('option', key); option.value = value; mode.append(option); }); mode.value = 'auto'; mode.addEventListener('change', () => { updateProjectControls(); byId('project-network-profile-hint').hidden = mode.value !== 'fixed_vpn'; byId('project-network-auth-hint').hidden = mode.value !== 'fixed_vpn'; });
        const modeField = node('label', undefined, 'network-field network-mode-field'); modeField.append(label('span', 'modeLabel'), mode); card.append(modeField, field('projectTargets', 'project-network-targets', '', 'textarea', 'targetsHint'), field('projectProxy', 'project-network-proxy', 'socks5://user:password@127.0.0.1:1080', 'password'), field('vpnConfig', 'project-network-config', '', 'file'), field('certificates', 'project-network-certificates', '', 'file'));
        const profileHint = node('p'); profileHint.id = 'project-network-profile-hint'; card.append(profileHint);
        card.append(field('vpnUsername', 'project-network-username', '', 'text', 'vpnAuthHint'), field('vpnPassword', 'project-network-password', '', 'password', 'vpnAuthHint'));
        const authHint = node('p'); authHint.id = 'project-network-auth-hint'; card.append(authHint);
        const advanced = node('details'); advanced.append(label('summary', 'advanced'), field('dns', 'project-network-dns', '', 'textarea', 'dnsHint'));
        advanced.append(field('asset', 'project-network-asset', '', 'text', 'assetHint'), projectButton('bind', (id, sequence) => bindAsset(false, id, sequence)), projectButton('excludeAsset', (id, sequence) => bindAsset(true, id, sequence)));
        const bindings = node('div'); bindings.id = 'project-network-bindings'; advanced.append(bindings); card.append(advanced);
        const tools = node('div', undefined, 'network-actions project-network-actions'); tools.append(projectButton('saveProject', saveProject), projectButton('connect', (id, sequence) => vpnAction('connect', id, sequence)), projectButton('disconnect', (id, sequence) => vpnAction('disconnect', id, sequence)), projectButton('refreshStatus', refreshProject, 'refresh'));
        const cancel = button('cancelJob', async () => {
            const operation = projectOperation, sequence = projectSequence; if (!operation?.jobID) return;
            operation.cancellation = (async () => {
                await request(`/api/network/jobs/${encodeURIComponent(operation.jobID)}/cancel`, json('POST', {}));
                operation.cancelled = true;
                await request(`/api/projects/${encodeURIComponent(operation.id)}/vpn/disconnect`, json('POST', {}));
                if (currentProject(operation.id, sequence)) await refreshProject(operation.id, sequence);
            })();
            try {
                await operation.cancellation;
            } catch (error) { if (currentProject(operation.id, sequence)) projectMessage(error.message); }
        }, projectMessage);
        cancel.id = 'project-network-job-cancel'; cancel.dataset.projectAction = 'cancel'; cancel.hidden = true; cancel.setAttribute('data-require-permission', 'project:write'); tools.append(cancel);
        const status = node('p', '', 'network-message'); status.id = 'project-network-status'; status.setAttribute('role', 'status');
        const notice = node('p', '', 'network-message'); notice.id = 'project-network-message'; notice.setAttribute('role', 'status'); card.append(status, tools, notice); (panel.querySelector('.projects-settings-primary') || panel).append(card);
        byId('project-network-username').autocomplete = 'off'; byId('project-network-password').autocomplete = 'new-password';
        byId('project-network-config').accept = '.ovpn,.conf'; byId('project-network-certificates').multiple = true;
        if (typeof MutationObserver !== 'undefined') new MutationObserver(refreshPermissions).observe(card, {subtree: true, attributes: true, attributeFilter: ['aria-hidden']});
    }
    window.NetworkTools = {openPool, loadPool, parseTargets, loadProject, refreshPermissions, hasProjectDraft};
    document.addEventListener('languagechange', () => {
        document.querySelectorAll('[data-i18n]').forEach(e => { const key = e.getAttribute('data-i18n'); if (!key?.startsWith('network.')) return; const value = t(key.slice(8)); if (e.getAttribute('data-i18n-attr') === 'placeholder') e.placeholder = value; else e.textContent = value; });
        document.querySelectorAll('[data-network-message]').forEach(e => { e.textContent = t(e.dataset.networkMessage); });
        byId('network-filter-state')?.setAttribute('aria-label', t('status')); byId('project-network-mode')?.setAttribute('aria-label', t('projectTitle'));
        byId('network-task-progress')?.setAttribute('aria-label', t('taskProgress'));
        byId('network-nav-content')?.setAttribute('data-title', t('nav'));
        updatePagerControls(); if (byId('network-source-kind')) updateSourceFields();
        document.querySelectorAll('[data-network-observation]').forEach(e => {
            const text = observationText(JSON.parse(e.getAttribute('data-network-observation')));
            const trigger = e.querySelector('.network-observation-trigger');
            if (trigger) trigger.textContent = text; else e.textContent = text;
            e.title = text;
        });
        document.querySelectorAll('[data-network-binding]').forEach(e => { e.textContent = bindingText(JSON.parse(e.getAttribute('data-network-binding'))); });
        document.querySelectorAll('[data-network-vpn]').forEach(e => { e.textContent = vpnText(JSON.parse(e.getAttribute('data-network-vpn'))); });
    });
    document.addEventListener('DOMContentLoaded', () => { buildPool(); if (location.hash.replace(/^#\/?/, '').split('?')[0] === 'network' && typeof window.switchPage === 'function') window.switchPage('network'); });
}());
