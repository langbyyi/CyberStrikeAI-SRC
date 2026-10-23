/** Project form drafts stay in memory and are independent of network credentials. */
(function () {
    'use strict';
    const ids = ['project-edit-name', 'project-edit-description', 'project-edit-scope', 'project-edit-status', 'project-edit-pinned', 'project-spec-name', 'project-spec-content'];
    const byId = id => document.getElementById(id);
    const copy = {clean:'项目设置已同步',dirty:'有未保存的项目设置',saving:'正在保存项目设置…',saved:'项目设置已保存',loading:'正在读取项目设置…',readonly:'当前账号仅可查看项目设置',networkDirty:'网络配置有未保存内容，请在网络区保存',leave:'存在未保存的项目或网络配置，仍要切换项目吗？',discard:'撤销尚未保存的项目设置？网络配置不受影响。'};
    const text = key => { const value = window.t?.('projectSettings.' + key); return value && value !== 'projectSettings.' + key ? value : copy[key]; };
    let ready = false, saving = false, baseline = null, message = '', messageType = '';
    function snapshot() { return Object.fromEntries(ids.map(id => [id, id === 'project-edit-pinned' ? !!byId(id)?.checked : byId(id)?.value || ''])); }
    const dirty = () => ready && baseline !== null && JSON.stringify(snapshot()) !== JSON.stringify(baseline);
    const networkDirty = () => !!window.NetworkTools?.hasProjectDraft?.();
    function feedback(value, type = '') { message = value; messageType = type; refresh(); }
    function refresh() {
        const writable = !window.hasPermission || window.hasPermission('project:write');
        const changed = dirty();
        const notice = byId('project-settings-feedback');
        if (notice) { notice.textContent = !writable ? text('readonly') : saving ? text('saving') : message || (!ready ? text('loading') : changed ? text('dirty') : networkDirty() ? text('networkDirty') : text('clean')); notice.dataset.state = messageType || (changed ? 'dirty' : 'clean'); }
        ids.concat(['project-spec-file','project-spec-file-trigger','project-scope-format','project-scope-example','project-settings-archive']).forEach(id => { const input = byId(id); if (input) input.disabled = !ready || saving || !writable; });
        if (byId('project-edit-status')) window.syncProjectsFilterSelect?.(byId('project-edit-status'));
        const save = byId('project-settings-save'), reset = byId('project-settings-reset');
        if (save) { save.disabled = !ready || saving || !changed || !writable; save.setAttribute('aria-busy', String(saving)); }
        if (reset) reset.disabled = !ready || saving || !changed || !writable;
        const networkNotice = byId('project-network-draft'); if (networkNotice) { networkNotice.textContent = networkDirty() ? text('networkDirty') : ''; networkNotice.hidden = !networkDirty(); }
    }
    function beginLoad() { ready = false; saving = false; baseline = null; message = ''; messageType = ''; ids.forEach(id => { const e = byId(id); if (e) { if (id === 'project-edit-pinned') e.checked = false; else e.value = id === 'project-edit-status' ? 'active' : ''; e.removeAttribute('aria-invalid'); } }); window.TestingSpecifications?.fillEditor('project-spec',null); refresh(); }
    function loaded() { ready = true; baseline = snapshot(); message = ''; messageType = ''; refresh(); }
    function error(value, id) { message = value; messageType = 'error'; const field = byId(id); if (field) { field.setAttribute('aria-invalid','true'); field.focus(); } refresh(); }
    function saved(value) { baseline = value || snapshot(); feedback(text('saved'),'success'); }
    function mergeSavedProject(project) {
        if (!ready || !baseline) return;
        const values = {};
        if (project.name !== undefined) values['project-edit-name'] = project.name || '';
        if (project.description !== undefined) values['project-edit-description'] = project.description || '';
        if (Object.prototype.hasOwnProperty.call(project, 'testing_specification')) {
            if (['project-spec-name', 'project-spec-content'].every(id => byId(id)?.value === baseline[id])) window.TestingSpecifications?.fillEditor?.('project-spec', project.testing_specification);
            values['project-spec-name'] = project.testing_specification?.name || '';
            values['project-spec-content'] = project.testing_specification?.content || '';
        }
        for (const [id, value] of Object.entries(values)) {
            const field = byId(id);
            if (field && field.value === baseline[id]) field.value = value;
            baseline[id] = value;
        }
        feedback(text('saved'), 'success');
    }
    function reset() {
        if (!baseline || !window.confirm(text('discard'))) return;
        ids.forEach(id => { const e=byId(id); if (!e) return; if(id==='project-edit-pinned') e.checked=baseline[id]; else e.value=baseline[id]; e.removeAttribute('aria-invalid'); });
        window.TestingSpecifications?.fillEditor('project-spec',{name:baseline['project-spec-name'],content:baseline['project-spec-content']}); feedback('');
    }
    function syncStatus(value) {
        const field = byId('project-edit-status');
        if (!ready || !baseline || !field) return;
        if (field.value === baseline['project-edit-status']) field.value = value;
        baseline['project-edit-status'] = value;
        refresh();
    }
    function canLeave() { return !dirty() && !networkDirty() || window.confirm(text('leave')); }
    function init() {
        const panel=byId('project-panel-settings'); if (!panel) return;
        panel.addEventListener('input',event=>{event.target.removeAttribute?.('aria-invalid'); message='';messageType='';refresh();});
        panel.addEventListener('change',()=>{message='';messageType='';refresh();});
        const layout=panel.querySelector('.projects-settings-layout');
        const intro=panel.querySelector('.projects-settings-intro');
        const updateOffset=()=>{ const offset=String((intro?.offsetHeight || 84)+16)+'px'; layout?.style.setProperty('--project-settings-nav-offset',offset); byId('page-projects')?.style.setProperty('--project-settings-nav-offset',offset); };
        if (typeof ResizeObserver !== 'undefined' && intro) new ResizeObserver(updateOffset).observe(intro);
        updateOffset();
        panel.querySelectorAll('[data-settings-section]').forEach(button=>button.addEventListener('click',()=>{
            const section=byId(button.dataset.settingsSection); if (!section) return;
            const scroller=window.matchMedia?.('(max-width: 767.98px)').matches ? panel.closest('.projects-page-layout') : layout;
            const offset=intro && window.getComputedStyle(intro).position==='sticky' ? intro.offsetHeight+16 : 16;
            if (scroller) scroller.scrollTo({top:scroller.scrollTop+section.getBoundingClientRect().top-scroller.getBoundingClientRect().top-offset,behavior:window.matchMedia?.('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'});
            panel.querySelectorAll('[data-settings-section]').forEach(item=>{item.classList.toggle('is-active',item===button);item.setAttribute('aria-current',item===button?'location':'false');});
        }));
        byId('project-settings-reset')?.addEventListener('click',reset);
        document.addEventListener('projectsettingschange',()=>{message='';messageType='';refresh();});
        document.addEventListener('languagechange',()=>{message='';refresh();}); refresh();
    }
    window.addEventListener('beforeunload',event=>{if(dirty()||networkDirty()){event.preventDefault();event.returnValue='';}});
    window.ProjectSettingsUI={beginLoad,loaded,error,saved,snapshot,refresh,canLeave,syncStatus,mergeSavedProject,hasDraft:()=>dirty()||networkDirty(),setSaving(value){saving=value;refresh();}};
    document.addEventListener('DOMContentLoaded',init);
})();
