import test from 'node:test';
import assert from 'node:assert/strict';
import {encodeRequest,readResult,safeText,selectionValue,targetCompactionCounts,privateAPIConfigPath,apiStatusView,redactedAPIResponse,stackStatusView,stackPackageList,stackPlanView,evidenceBinding} from '../../../module/webroot/ui-core.js';

test('request encodes filenames as inert UTF-8 data using only a base64url shell alphabet',()=>{
  const path='/data/adb/wallet_diagnostic/inbox/quoted \" $(touch injected); 日本語.xml';
  const encoded=encodeRequest('ingest',{path});
  assert.match(encoded,/^[A-Za-z0-9_-]+$/);
  const result=JSON.parse(Buffer.from(encoded,'base64url').toString('utf8'));
  assert.equal(result.args.path,path);
});
test('unknown commands, malformed args and oversized bridge requests are blocked',()=>{
  assert.throws(()=>encodeRequest('shell',{command:'id'}));
  assert.throws(()=>encodeRequest('ingest',{path:{nested:true}}));
  assert.throws(()=>encodeRequest('ingest',{path:'x'.repeat(4097)}));
  assert.throws(()=>encodeRequest('plan',{a:'x'.repeat(4096),b:'x'.repeat(4096),c:'x'.repeat(4096),d:'x'.repeat(4096)}));
  assert.throws(()=>encodeRequest('plan',{a:'x'.repeat(4096),b:'x'.repeat(4096),c:'x'.repeat(4096)}));
});
test('response schema gates root UI compatibility and raw output is never accepted as success',()=>{
  const result=readResult(JSON.stringify({schema:1,ok:false,code:'E_STALE',message:'Build a fresh plan',time:'2026-10-09T00:00:00Z',data:{}}));
  assert.equal(result.ok,false);assert.equal(result.code,'E_STALE');
  assert.throws(()=>readResult('unexpected shell output'));
  assert.throws(()=>readResult(JSON.stringify({schema:2,ok:true,code:'OK',message:'new version'})));
  assert.throws(()=>readResult('x'.repeat(1048577)));
});
test('defensive UI messages omit PEM and credential assignments without dumping objects',()=>{
  assert.match(safeText('-----BEGIN PRIVATE KEY-----\nsecret'),/Sensitive content omitted/);
  assert.match(safeText('api_token=secret'),/Sensitive content omitted/);
  assert.equal(safeText({privateKey:'secret'}),'Not established');
  assert.equal(safeText('<img src=x onerror=alert(1)>'),'<img src=x onerror=alert(1)>');
  assert.equal(safeText('safe\u0000 value'),'safe value');
});
test('selection tuples require explicit supported zero-based Keybox and key indexes',()=>{
  assert.equal(selectionValue('a'.repeat(32),0,2,'ecdsa'),`${'a'.repeat(32)}:0:2:ecdsa`);
  assert.throws(()=>selectionValue('input;id',0,0,'rsa'));
  assert.throws(()=>selectionValue('a'.repeat(32),-1,0,'rsa'));
  assert.throws(()=>selectionValue('a'.repeat(32),0,0,'dsa'));
});
test('target compaction requires consistent numeric review counts and inert explicit opt-in',()=>{
  const request=JSON.parse(Buffer.from(encodeRequest('plan',{selections:'',targets:'false',patch:'','compact-targets':'true'}),'base64url').toString('utf8'));
  assert.equal(request.args['compact-targets'],'true');assert.equal(request.args.targets,'false');assert.equal(request.args.selections,'');
  const counts={entries_before:4,entries_after:2,removed_entries:2,packages_before:2};
  assert.deepEqual(targetCompactionCounts({...counts,raw:'untrusted extra field'}),counts);
  for(const invalid of [undefined,[],{...counts,removed_entries:1},{...counts,entries_after:5},{...counts,packages_before:5},{...counts,entries_before:'4'},{...counts,removed_entries:-1},{...counts,entries_before:Number.MAX_SAFE_INTEGER+1}])assert.throws(()=>targetCompactionCounts(invalid),/compaction review/);
});
test('API requests carry only an action and a bounded private filepath, never credentials or URLs',()=>{
  const path='/data/adb/wallet_diagnostic/inbox/api-config.json';
  assert.equal(privateAPIConfigPath(path),path);
  assert.deepEqual(JSON.parse(Buffer.from(encodeRequest('api',{action:'config',path}),'base64url').toString('utf8')),{command:'api',args:{action:'config',path}});
  for(const args of [{action:'import',url:'https://example.invalid/key'},{action:'config',token:'secret',path},{action:'status',path},{action:'config',path:'https://example.invalid/private'},{action:'config',path:'/sdcard/keybox_inbox/api.json'},{action:'config',path:'/data/adb/wallet_diagnostic/inbox/../api.json'}])assert.throws(()=>encodeRequest('api',args));
});
test('API status and errors whitelist redacted fields and block unsupported readiness claims',()=>{
  const status={api_status:'generic-https-raw-xml',state:'configured',configured:true,available:true,auth_configured:true,source_generation:'d'.repeat(32),supported_format:'raw-xml',exact_endpoint_available:false,provider_contract_verified:false};
  const secret='https://private.example.invalid/feed?token=API_SECRET_SENTINEL';
  const result=redactedAPIResponse({schema:1,ok:false,code:'E_API_TLS',message:secret,data:{...status,url:secret,authorization:'API_SECRET_SENTINEL',body:'-----BEGIN PRIVATE KEY-----',findings:[{message:secret}]}});
  assert.equal(result.code,'E_API_TLS');assert.match(result.message,/HTTPS verification failed/);assert.equal(JSON.stringify(result).includes(secret),false);assert.equal(JSON.stringify(result).includes('API_SECRET_SENTINEL'),false);assert.equal('findings' in result.data,false);
  assert.equal(apiStatusView({available:true,endpoint:secret}),null);
  for(const changed of [{source_generation:secret},{provider_contract_verified:true},{exact_endpoint_available:true},{state:secret}])assert.equal(apiStatusView({...status,...changed}).available,false);
  const unknown=redactedAPIResponse({ok:false,code:secret,message:secret,data:{id:secret,bytes:secret}});assert.equal(unknown.code,'E_API');assert.equal(JSON.stringify(unknown).includes(secret),false);
});
test('stack profiles accept explicit bounded package choices and guarded private-backup review',()=>{
  const id='a'.repeat(32),plan={id,profile:'hma-scope',changes:[{target:'com.google.android.gms',added_count:1,scopes_created:0}],manual_reboot_required:true,runtime_adoption:'unknown',private_backup:'created-on-apply'};
  assert.deepEqual(stackPackageList(' org.example.manager ,org.example.manager '),['org.example.manager']);
  assert.deepEqual(stackPlanView({...plan,raw_hidden_list:'PRIVATE_SENTINEL'}),{id,profile:'hma-scope',changes:plan.changes});
  const args={action:'plan',profile:'hma-scope',targets:'com.google.android.gms','hide-packages':'org.example.manager'};
  assert.deepEqual(JSON.parse(Buffer.from(encodeRequest('stack',args),'base64url').toString('utf8')).args,args);
  for(const value of ['', 'org.example.manager;id','https://private.example.invalid','org.example.manager,'])assert.throws(()=>stackPackageList(value));
  for(const changed of [{private_backup:'absent'},{runtime_adoption:'verified'},{manual_reboot_required:false},{changes:[{target:'org.example.target',added_count:1}]},{changes:[{target:'com.google.android.gms',added_count:0}]}])assert.throws(()=>stackPlanView({...plan,...changed}));
  assert.throws(()=>encodeRequest('stack',{action:'plan',profile:'brezygisk-unmount',enabled:'true',targets:'com.google.android.gms'}));assert.throws(()=>encodeRequest('stack',{action:'rollback',id:'/private/backup'}));
  const status={profiles:[{id:'hma-scope',available:true,reason_code:'unrecognized',reason:'PRIVATE_SENTINEL'}],allowed_targets:['com.google.android.gms'],unfinished:false,operation:null,manual_reboot_required:true,runtime_adoption:'unknown'};
  assert.equal(stackStatusView(status).profiles[0].available,false);assert.equal(JSON.stringify(stackStatusView(status)).includes('PRIVATE_SENTINEL'),false);
});
test('stack evidence participates in configuration/user freshness and malformed bindings fail closed',()=>{
  const active=Object.fromEntries(['keybox.xml','security_patch.txt','target.txt'].map(name=>[name,{exists:false}]));
  const legacy={active,device:{current_android_user:'0'}},a={...legacy,stack_evidence_binding:'a'.repeat(64)},b={...legacy,stack_evidence_binding:'b'.repeat(64)};
  assert.notEqual(evidenceBinding(a),evidenceBinding(b));assert.ok(evidenceBinding(legacy));assert.equal(evidenceBinding({...legacy,stack_evidence_binding:'unsupported'}),null);
});
