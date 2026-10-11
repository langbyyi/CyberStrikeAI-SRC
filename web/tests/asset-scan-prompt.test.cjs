const fs=require('node:fs');
const vm=require('node:vm');
const test=require('node:test');
const assert=require('node:assert/strict');
const source=fs.readFileSync('web/static/js/assets.js','utf8');
const start=source.indexOf('function renderAssetScanPrompt(');
const ctx={assetTargetLabel:a=>a.host,assetT:(key,fallback,values)=>fallback.replaceAll('{{asset_id}}',values.asset_id)};
vm.createContext(ctx);
vm.runInContext(source.slice(start,source.indexOf('function commonAssetProjectId(',start)),ctx);
test('custom limited checks retain their scope and asset completion instruction',()=>{
 const prompt=ctx.renderAssetScanPrompt('只读核验 {{target}}:{{port}} 的连通性和指纹；不枚举路径。',{id:'test-only-asset',host:'192.0.2.42',port:8080});
 assert.ok(prompt.startsWith('只读核验 192.0.2.42:8080 的连通性和指纹；不枚举路径。'));
 assert.ok(prompt.includes('complete_asset_scan(id=test-only-asset)'));
 assert.doesNotMatch(prompt,/弱口令|WAF|record_vulnerability/);
});
test('existing completion instructions are not duplicated and missing asset IDs are not invented',()=>{
 const prompt='核验后 complete_asset_scan(id={{asset_id}})';
 assert.equal(ctx.renderAssetScanPrompt(prompt,{id:'test-only-asset',host:'192.0.2.42'}),'核验后 complete_asset_scan(id=test-only-asset)');
 assert.equal(ctx.renderAssetScanPrompt('只读核验 {{target}}',{host:'192.0.2.42'}),'只读核验 192.0.2.42');
});
