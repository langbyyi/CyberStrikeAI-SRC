const fs=require('node:fs');
const vm=require('node:vm');
const test=require('node:test');
const assert=require('node:assert/strict');
const source=fs.readFileSync('web/static/js/audit.js','utf8');
test('reset clears the keyword and requests an unfiltered first page',() => {
 const fields={
  'audit-filter-category':{value:'auth'},'audit-filter-action':{value:'login',disabled:false},
  'audit-filter-result':{value:'failure'},'audit-filter-q':{value:'does-not-exist'},
  'audit-filter-since':{value:'2026-09-01T00:00'},'audit-filter-until':{value:'2026-09-02T00:00'}
 };
 let requested,cleared=false;
 const ctx={auditLogsPage:4,auditLogsPageSize:20,URLSearchParams,
  document:{getElementById:id => fields[id]},
  window:{AuditDatetimePicker:{clearAll(){cleared=true;fields['audit-filter-since'].value='';fields['audit-filter-until'].value='';}}},
  getAuditFilterDatetimeValue:id => fields[id].value,auditDatetimeLocalToRFC3339:x => x,
  rebuildAuditActionSelect(){fields['audit-filter-action'].value='';fields['audit-filter-action'].disabled=true;},
  syncAuditCustomSelect(){},loadAuditLogs(){requested=ctx.buildAuditQueryParams(false);}};
 vm.createContext(ctx);
 for (const [startMarker,endMarker] of [
  ['function buildAuditQueryParams(','async function loadAuditSummary('],
  ['function filterAuditLogs(','function applyAuditTimePreset(']
 ]) {
  const start=source.indexOf(startMarker);
  vm.runInContext(source.slice(start,source.indexOf(endMarker,start)),ctx);
 }
 ctx.resetAuditLogFilters();
 const params=new URLSearchParams(requested);
 assert.equal(fields['audit-filter-q'].value,'');
 assert.equal(params.get('page'),'1');
 for (const key of ['q','category','action','result','since','until']) assert.equal(params.has(key),false);
 assert.equal(cleared,true);
 const html=fs.readFileSync('web/templates/index.html','utf8');
 assert.match(html,/<button[^>]*onclick="resetAuditLogFilters\(\)"[^>]*data-i18n="settingsAudit.resetBtn"/);
});
