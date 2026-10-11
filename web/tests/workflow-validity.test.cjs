const fs=require('node:fs');
const vm=require('node:vm');
const test=require('node:test');
const assert=require('node:assert/strict');
const source=fs.readFileSync('web/static/js/workflows.js','utf8');
function harness(workflows,cy=null,errors=[]) {
 const list={innerHTML:''};
 const ctx={workflows,cy,currentWorkflowId:'selected',
  document:{getElementById:() => list},esc:x => String(x||''),_t:x => x,WORKFLOW_EDIT_ICON:'edit',
  elementsToGraph:() => ({}),validateWorkflowGraph:() => errors};
 vm.createContext(ctx);
 let start=source.indexOf('    function workflowValidationError(');
 vm.runInContext(source.slice(start,source.indexOf('    function updateWorkflowCanvasTitle(',start)),ctx);
 start=source.indexOf('    function renderWorkflowList(');
 vm.runInContext(source.slice(start,source.indexOf('    function nextNodeId(',start)),ctx);
 return {ctx,list};
}
test('invalid saved graph is labeled as invalid and never gets a green enabled badge',() => {
 const h=harness([{id:'invalid',name:'Invalid',enabled:true,validation_error:'missing start'}]);
 h.ctx.renderWorkflowList();
 assert.match(h.list.innerHTML,/workflows.statusInvalid/);
 assert.match(h.list.innerHTML,/is-invalid/);
 assert.doesNotMatch(h.list.innerHTML,/is-enabled/);
 assert.match(h.list.innerHTML,/title="missing start"/);
});
test('a selected invalid draft updates the list status',() => {
 const h=harness([{id:'selected',name:'Draft',enabled:true}],{},['missing output']);
 h.ctx.renderWorkflowList();
 assert.match(h.list.innerHTML,/workflows.statusInvalid/);
});
test('valid enabled and disabled definitions retain their configured status',() => {
 const h=harness([{id:'valid',enabled:true},{id:'off',enabled:false}]);
 h.ctx.renderWorkflowList();
 assert.match(h.list.innerHTML,/workflows.statusEnabled/);
 assert.match(h.list.innerHTML,/workflows.statusDisabled/);
 assert.doesNotMatch(h.list.innerHTML,/statusInvalid/);
});
