const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const taskSource = fs.readFileSync('web/static/js/tasks.js','utf8');
function concurrencyHarness(value) {
 let calls = 0, message, focused = false;
 const input = {value, focus() { focused = true; }};
 const ctx = {_bqInlineSaving:false, batchQueuesState:{currentQueueId:'q'},
  document:{getElementById:() => input}, _t:x => x, alert:x => {message=x;},
  apiFetch:async () => {calls++;return {ok:true,json:async () => ({queue:{title:'title'}})};},
  showBatchQueueDetail() {},refreshBatchQueues() {},console};
 vm.createContext(ctx);
 const start = taskSource.indexOf('async function saveInlineConcurrency(');
 vm.runInContext(taskSource.slice(start,taskSource.indexOf('// --- 单条执行 ---',start)),ctx);
 return {ctx,calls:() => calls,message:() => message,focused:() => focused};
}
test('invalid concurrency leaves the editor open and makes no API calls', async () => {
 for (const value of ['0','9','1.5','2abc','']) {
  const h=concurrencyHarness(value);
  await h.ctx.saveInlineConcurrency();
  assert.equal(h.calls(),0);
  assert.equal(h.message(),'tasks.concurrencyInvalid');
  assert.equal(h.focused(),true);
  assert.equal(h.ctx._bqInlineSaving,false);
 }
});
test('valid concurrency updates and refreshes normally',async () => {
 for (const value of ['1','8']) {
  const h=concurrencyHarness(value);
  await h.ctx.saveInlineConcurrency();
  assert.equal(h.calls(),2);
  assert.equal(h.message(),undefined);
 }
});
test('blank project name stops before making a save request',async () => {
 const source=fs.readFileSync('web/static/js/projects.js','utf8');
 let calls=0,message;
 const ctx={currentProjectId:'p',requireProjectWrite:() => true,
 document:{getElementById:() => ({value:'   '})},tp:x => x,alert:x => {message=x;},apiFetch:() => {calls++;}};
 vm.createContext(ctx);
 const start=source.indexOf('async function saveProjectSettings(');
 vm.runInContext(source.slice(start,source.indexOf('function findProjectById(',start)),ctx);
 await ctx.saveProjectSettings();
 assert.equal(calls,0);
 assert.equal(message,'projects.enterProjectName');
});
test('RBAC creation buttons use the existing permission visibility guard',() => {
 const html=fs.readFileSync('web/templates/index.html','utf8');
 const buttons=html.match(/<button\b[^>]*onclick="openRbac(?:Role|User)Modal\(\)"[^>]*>/g);
 assert.ok(buttons.length>=3);
 for (const b of buttons) assert.match(b,/data-require-permission="rbac:write"/);
 const auth=fs.readFileSync('web/static/js/auth.js','utf8');
 const ctx={permissionAllowedForElement:() => false};
 vm.createContext(ctx);
 const start=auth.indexOf('function applyPermissionElement(');
 vm.runInContext(auth.slice(start,auth.indexOf('let permissionClickGuardInstalled',start)),ctx);
 const button={disabled:false,hidden:false,getAttribute:key => key==='data-require-permission'?'rbac:write':null,classList:{toggle() {}},setAttribute() {}};
 ctx.applyPermissionElement(button);
 assert.equal(button.hidden,true);
 assert.equal(button.disabled,true);
});
