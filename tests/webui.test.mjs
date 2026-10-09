import test from 'node:test';
import assert from 'node:assert/strict';
import {encodeRequest,readResult,safeText,selectionValue} from '../module/webroot/ui-core.js';

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
