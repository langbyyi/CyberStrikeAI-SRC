const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const settings=fs.readFileSync(path.join(__dirname,'../static/js/settings.js'),'utf8');
const example=fs.readFileSync(path.join(__dirname,'../../config.example.yaml'),'utf8');
const defaultNames=example.match(/tool_search_always_visible_tools:\s*\[([^\]]+)\]/)[1].split(',').map(s=>s.trim());
const networkNames=['network_status','network_diagnose','network_acquire','network_release','network_bind_asset','network_sync_source'];
test('network tools default to checked, editable resident preferences and preserve opt-out on save',()=>{
  const ctx={};vm.createContext(ctx);
  vm.runInContext('let alwaysVisibleToolNames=new Set(); let alwaysVisibleBuiltinToolNames=new Set(["record_vulnerability"]);',ctx);
  vm.runInContext(settings.slice(settings.indexOf('function getToolKey(tool)'),settings.indexOf('function countUserAlwaysVisibleTools()')),ctx);
  for(const name of defaultNames)ctx.addAlwaysVisibleAliases(name);
  for(const name of networkNames){
    assert.equal(ctx.isToolAlwaysVisible({name}),true,name+' should be checked by default');
    assert.equal(ctx.isToolAlwaysVisibleBuiltin({name}),false,name+' should remain editable');
    ctx.removeAlwaysVisibleAliases(name);
    assert.equal(ctx.isToolAlwaysVisible({name}),false);
  }
  const saved=Array.from(ctx.getAlwaysVisibleForSave());
  for(const name of networkNames)assert.equal(saved.includes(name),false,name+' opt-out should be saved');
  assert.equal(saved.includes('exec'),true,'unrelated resident preferences should survive');
});
