const fs=require('node:fs'),vm=require('node:vm'),test=require('node:test'),assert=require('node:assert/strict');
const source=fs.readFileSync('web/static/js/tasks.js','utf8');
const start=source.indexOf('function getBatchQueueStatusPresentation('),end=source.indexOf('\nfunction ',start+10);
const c=vm.createContext({_t:key=>key,_tPlain:(key,args)=>key+':'+JSON.stringify(args)});vm.runInContext(source.slice(start,end),c);
test('all failed batch tasks show failure even when the queue lifecycle is completed',()=>{
 const q={status:'completed',tasks:[{status:'failed'},{status:'failed'}]};const p=c.getBatchQueueStatusPresentation(q);
 assert.equal(p.text,'tasks.statusFailed');assert.equal(p.class,'batch-queue-status-failed');assert.equal(q.status,'completed');
});
test('mixed outcome names the failure count while successful queues remain completed',()=>{
 const mixed=c.getBatchQueueStatusPresentation({status:'completed',tasks:[{status:'completed'},{status:'failed'}]});
 assert.match(mixed.text,/statusEndedWithFailures.*"count":1/);assert.equal(mixed.progressNote,'tasks.finishedProgressHint');
 assert.equal(c.getBatchQueueStatusPresentation({status:'completed',tasks:[{status:'completed'}]}).text,'tasks.statusCompleted');
});
test('running queues retain running status and existing recurring queues retain their next-run information',()=>{
 assert.equal(c.getBatchQueueStatusPresentation({status:'running',tasks:[{status:'failed'}]}).text,'tasks.statusRunning');
 const p=c.getBatchQueueStatusPresentation({status:'completed',scheduleMode:'cron',scheduleEnabled:true,nextRunAt:'2026-10-07T00:00:00Z',tasks:[{status:'failed'}]});
 assert.equal(p.text,'tasks.statusFailed');assert.match(p.sublabel,/cronNextRunLine/);assert.equal(p.callout,'tasks.cronRecurringCallout');
});
