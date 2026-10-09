// Offline integration test only. Mock bridge never touches a phone or active configuration.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.WALLETDIAG_NODE_MODULES?path.join(process.env.WALLETDIAG_NODE_MODULES,'playwright'):'playwright');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..','..','..');
const webroot=path.join(root,'module','webroot');
async function openDisclosure(page,id) {
  const details=page.locator('#'+id);
  assert.equal(await details.count(),1,`disclosure ${id} exists exactly once`);
  if(!await details.evaluate(el=>el.open))await details.locator(':scope > summary').click();
  assert.equal(await details.evaluate(el=>el.open),true,`disclosure ${id} opens through its summary`);
}
async function assertUnsplitNavigationWords(page) {
  const splitWords=await page.locator('nav button,h1').evaluateAll(elements=>elements.flatMap(el=>{
    const failures=[],walker=document.createTreeWalker(el,NodeFilter.SHOW_TEXT);
    for(let node=walker.nextNode();node;node=walker.nextNode())for(const word of node.textContent.matchAll(/\S+/g)) {
      const range=document.createRange();range.setStart(node,word.index);range.setEnd(node,word.index+word[0].length);
      if(Array.from(range.getClientRects()).filter(rect=>rect.width>0&&rect.height>0).length>1)failures.push(word[0]);
    }
    return failures;
  }));
  assert.deepEqual(splitWords,[],'navigation labels and the brand remain readable without splitting individual words across lines');
}
const mime={'.html':'text/html','.js':'text/javascript','.css':'text/css'};
const server=createServer(async(req,res)=>{
  try {const url=new URL(req.url,'http://localhost');const name=url.pathname==='/'?'index.html':url.pathname.slice(1);if(!/^[a-z_-]+\.(html|js|css)$/.test(name))throw new Error('not found');res.setHeader('Content-Type',mime[path.extname(name)]);res.end(await readFile(path.join(webroot,name)));}catch{res.writeHead(404).end();}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin=`http://127.0.0.1:${server.address().port}`;
let browser;
try {
  browser=await chromium.launch({headless:true,channel:process.env.WALLETDIAG_BROWSER_CHANNEL || 'chrome'});
  const page=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1});
  const runtimeRequests=[];page.on('request',request=>runtimeRequests.push(request.url()));
  const consoleErrors=[];page.on('pageerror',error=>consoleErrors.push(error.message));
  const mockBridge=()=>{
    window.testRequests=[];window.testActiveHash='1'.repeat(64);window.testCurrentUser='0';window.testVerifyError=false;window.testTrustAvailable=true;window.testRecovery=false;window.testApiSupported=false;window.testApiConfigured=false;window.testApiGeneration='d'.repeat(32);window.testStackSupported=false;window.testStackPending=false;window.testStackOperation=null;window.testMarkerEnabled=false;
    window.ksu={exec(command,_options,callback){
      const match=command.match(/^\/data\/adb\/modules\/wallet_diagnostic\/bin\/walletdiag request ([A-Za-z0-9_-]+)$/);if(!match)throw new Error('Unsafe bridge command');
      const request=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(match[1].replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0))));window.testRequests.push(request);
      const id='a'.repeat(32),plan='b'.repeat(32);
      const summary={structural_valid:true,cryptographic_consistent:true,trust:'unknown',revocation:'unknown',keyboxes:[{index:0,keys:[{index:0,algorithm:'ecdsa',parameter:'P-256',certificate_count:3,valid_until:'2030-01-01T00:00:00Z',private_key_format:'sec1',warnings:[]},{index:1,algorithm:'rsa',parameter:'RSA-2048',certificate_count:3,valid_until:'2030-01-01T00:00:00Z',private_key_format:'pkcs1',warnings:[]}]}]};
      const configuration=()=>Object.fromEntries(['keybox.xml','security_patch.txt','target.txt'].map(file=>[file,{exists:true,sha256:file==='target.txt'&&window.testTargetHash?window.testTargetHash:window.testActiveHash,size:100,metadata:{uid:0,gid:0,mode:384,selinux:'test-only'}}]));
      const publicEvidence=()=>({available:true,state:'fresh',checked_at:'2026-10-09T00:00:00Z',expires_at:'2026-10-10T00:00:00Z',keys:[{keybox_index:0,key_index:0,algorithm:'ecdsa',google_root_key:true,revocation:'not-listed-as-of-feed',listed_certificate_count:0}],limitations:['Feed absence does not guarantee acceptance.'],next_step:'Collect fresh signer evidence.'});
      const apiSecret='https://private.example.invalid/feed?token=API_SECRET_SENTINEL';
      const apiStatus=()=>({api_status:'generic-https-raw-xml',state:window.testApiConfigured?'configured':'unconfigured',configured:window.testApiConfigured,available:window.testApiConfigured,auth_configured:window.testApiConfigured,source_generation:window.testApiConfigured?window.testApiGeneration:undefined,supported_format:'raw-xml',exact_endpoint_available:false,provider_contract_verified:false,endpoint:apiSecret,authorization:'API_SECRET_SENTINEL',raw_body:'-----BEGIN PRIVATE KEY----- API_SECRET_SENTINEL',provenance:apiSecret});
      const stackStatus=()=>({profiles:['hma-scope','brezygisk-unmount'].map(id=>({id,resource:'PRIVATE_STACK_SENTINEL',available:!window.testStackUnavailable&&!window.testStackPending,reason_code:window.testStackPending?'recovery_pending':window.testStackUnavailable?'unsupported_capability':'available',reason:'PRIVATE_STACK_SENTINEL'})),allowed_targets:['com.google.android.apps.walletnfcrel','com.google.android.gms','com.android.vending','com.google.android.gsf'],unfinished:window.testStackPending,stack_pending:window.testStackPending,operation:window.testStackOperation,manual_reboot_required:true,runtime_adoption:'unknown',private_hidden_list:['PRIVATE_STACK_SENTINEL']});
      let data={},ok=true,code='OK',message='Completed';
      if(request.command==='status'||request.command==='diagnose')data={active:configuration(),reset:{state:window.testResetState || 'none',user:window.testCurrentUser},api:window.testApiSupported?apiStatus():{available:false,endpoint:apiSecret},device:{current_android_user:window.testCurrentUser,wallet_role:'Google Play services TapAndPay'},keybox_summaries:{'keybox.xml':window.testInvalidInventory?{structural_valid:false,cryptographic_consistent:false,structural_inventory_only:true}:summary},algorithms:['ecdsa'],evidence_time:'2026-10-09T00:00:00Z',next_step:'Collect fresh diagnostics',findings:[{title:'<img src=x onerror=alert(1)>',message:'Untrusted text stays text',kind:'hypothesis'}],last_operation:{type:'plan',state:'review',time:'2026-10-09T00:01:00Z',id:plan},history:[],...(window.testTrustAvailable?{public_attestation:publicEvidence()}:{})};
      if((request.command==='status'||request.command==='diagnose'||request.command==='verify')&&window.testStackSupported)data={...data,stack:stackStatus(),stack_pending:window.testStackPending,stack_evidence_binding:window.testStackHash};
      if(request.command==='ingest')data={id};
      if(request.command==='validate'){data={id:request.args.id,summary};if(request.args.id==='f'.repeat(32) && window.testApiValidationError){ok=false;code='E_VALIDATION';message=apiSecret;data={findings:[{title:apiSecret,message:apiSecret}]};}}
      if(request.command==='plan')data={id:plan,algorithms:['ecdsa','rsa'],summary,changes:['keybox.xml'],preview:[{file:'keybox.xml',old_exists:true,old_sha256:'1'.repeat(64),new_sha256:'2'.repeat(64),metadata:{uid:0,gid:0,mode:384,selinux:'test-only'}}],active:{'keybox.xml':{exists:true,sha256:'1'.repeat(64)}},intended:{'keybox.xml':{sha256:'2'.repeat(64)}},warnings:['Trust and revocation remain unknown'],required_capabilities:{validation:'available'}};
      if(request.command==='plan'){
        window.testLastPlanCompact=request.args['compact-targets']==='true';
        if(window.testLastPlanCompact){
          data={id:plan,changes:['target.txt'],preview:[{file:'target.txt',old_exists:true,old_sha256:window.testTargetHash || window.testActiveHash,new_sha256:'4'.repeat(64),metadata:{uid:0,gid:0,mode:384,selinux:'test-only'},removed_lines:['com.example.one!','com.example.two?'],added_lines:[]}],active:configuration(),intended:{'target.txt':{exists:true,sha256:'4'.repeat(64)}},target_compaction:{entries_before:4,entries_after:2,removed_entries:2,packages_before:2},warnings:['Package modes unchanged; Wallet acceptance remains unverified.']};
          if(request.args.targets==='true')data.preview[0].added_lines=['com.google.android.gms!'];
          if(window.testCompactReview==='missing')delete data.target_compaction;
          if(window.testCompactReview==='invalid')data.target_compaction.removed_entries=3;
          if(window.testCompactReview==='no-target'){data.changes=['keybox.xml'];data.preview=[{file:'keybox.xml'}];}
          if(window.testCompactError){ok=false;code='E_SELECTION';message='Conflicting target modes require manual review.';}
        }
      }
      if(request.command==='apply'){if(window.testLastPlanCompact)window.testTargetHash='4'.repeat(64);else window.testActiveHash='2'.repeat(64);data={files_committed:true,engine_health:'healthy',adoption:'pending',configuration:configuration(),current_android_user:window.testCurrentUser};}
      if(request.command==='verify'){if(window.testVerifyError){ok=false;code='E_STALE';message='Active files changed after commit. Verification is stale.';}else data={files_committed:true,engine_health:'healthy',adoption:'pending',wallet_acceptance:'unverified',wallet_readiness:request.args['wallet-ready']==='true'?'user-confirmed':'unverified',tap_to_pay:request.args['tap-confirmed']==='true'?'user-confirmed':'unverified',configuration:configuration(),current_android_user:window.testCurrentUser};}
      if(request.command==='verify'&&window.testStackSupported)data.stack_evidence_binding=window.testStackHash;
      if(request.command==='rollback')data={state:'restored',adoption:'pending'};
      if(request.command==='recovery')data={state:request.args.action==='restore'?'restored':window.testRecovery?'writing':'none',lock_present:false};
      if(request.command==='watch')data={estimate:'2026-11-18',days_remaining:40,fingerprint_estimate_state:'estimate-valid-for-supplied-fingerprint',patch_aligned:'unknown',warnings:['Patch evidence unavailable.']};
      if(request.command==='trust')data=publicEvidence();
      if(request.command==='reset'&&request.args.action==='preview')data={review_hash:'c'.repeat(64),user:'0',steps:['Wallet clear','GMS clear twice','Manual reboot'],consequences:['App data cannot be restored from configuration backups']};
      if(request.command==='reset'&&request.args.action==='status')data={state:window.testResetState||'none',can_close:['clearing','attempting-clear','failed-do-not-repeat'].includes(window.testResetState),close_review_hash:window.testResetCloseHash||'9'.repeat(64)};
      if(request.command==='reset'&&request.args.action==='close'){if(request.args.confirmation!=='CLOSE INCOMPLETE RESET WITHOUT REPEATING'||request.args.review_hash!==(window.testResetCloseHash||'9'.repeat(64)))throw new Error('Unreviewed reset closure');window.testResetState='closed-incomplete';data={state:'closed-incomplete',clear_steps_repeated:false};}
      if(request.command==='api'){
        if(!window.testApiSupported){ok=false;code='E_API_UNAVAILABLE';message=apiSecret;data={endpoint:apiSecret};}
        else if(request.args.action==='config'){window.testApiConfigured=true;window.testApiGeneration=window.testApiGeneration==='e'.repeat(32)?'8'.repeat(32):'e'.repeat(32);data=apiStatus();}
        else if(request.args.action==='import'){data={schema:1,id:window.testApiBadStage?apiSecret:'f'.repeat(32),sha256:'7'.repeat(64),time:'2026-10-09T00:00:00Z',bytes:100,raw_body:apiSecret};if(window.testApiImportError){ok=false;code=window.testApiImportError;message=apiSecret;data={...apiStatus(),findings:[{title:apiSecret,message:apiSecret}]};}}
        else data=apiStatus();
      }
      if(request.command==='stack'){
        if(!window.testStackSupported){ok=false;code='E_CAPABILITY';message='PRIVATE_STACK_SENTINEL';}
        else if(request.args.action==='status')data=stackStatus();
        else if(request.args.action==='plan'){const profile=request.args.profile,id=profile==='hma-scope'?'c'.repeat(32):'d'.repeat(32);window.testStackLastPlan={id,profile,enabled:request.args.enabled};data={id,profile,resource:'PRIVATE_STACK_SENTINEL',changes:profile==='hma-scope'?request.args.targets.split(',').map(target=>({target:window.testStackWrongScope?'com.android.vending':target,added_count:request.args['hide-packages'].split(',').length,scopes_created:1})): [{enabled_before:window.testMarkerEnabled,enabled_after:request.args.enabled==='true'}],manual_reboot_required:true,runtime_adoption:window.testStackInvalidPlan?'verified':'unknown',private_backup:'created-on-apply',raw_hidden_list:['PRIVATE_STACK_SENTINEL']};}
        else if(request.args.action==='apply'){const p=window.testStackLastPlan;window.testStackBeforeHash=window.testStackHash;window.testStackHash='6'.repeat(64);window.testStackOperation={id:p.id,profile:p.profile,state:window.testStackApplyError?'writing':'committed',can_verify:true,can_rollback:true,backup_available:true};window.testStackPending=!!window.testStackApplyError;if(p.profile==='brezygisk-unmount')window.testMarkerEnabled=p.enabled==='true';data={...window.testStackOperation,private_backup:'verified',manual_reboot_required:true,runtime_adoption:'unknown',readback_verified:true,private_hidden_list:['PRIVATE_STACK_SENTINEL']};if(window.testStackApplyError){ok=false;code='E_IO';message='PRIVATE_STACK_SENTINEL';}}
        else if(request.args.action==='rollback'){window.testStackPending=false;window.testStackHash=window.testStackBeforeHash;window.testMarkerEnabled=false;window.testStackOperation={...window.testStackOperation,state:'restored',can_rollback:false};data={...window.testStackOperation,private_backup:'verified',manual_reboot_required:true,runtime_adoption:'unknown',readback_verified:true};}
        else if(request.args.action==='resolve'){if(request.args.confirmation!=='KEEP CURRENT STACK FILE'||request.args.review_hash!==window.testStackOperation.resolution_review_hash)throw new Error('Unreviewed stack closure');window.testStackPending=false;window.testStackOperation={...window.testStackOperation,state:'superseded',can_rollback:false,can_resolve:false};data={...window.testStackOperation,evidence_preserved:true,active_resource_written:false,runtime_adoption:'unknown'};}
        else data={...window.testStackOperation,private_backup:'verified',manual_reboot_required:true,runtime_adoption:'unknown',readback_verified:true,private_hidden_list:['PRIVATE_STACK_SENTINEL']};
      }
      setTimeout(()=>window[callback](ok?0:5,JSON.stringify({schema:1,ok,code,message,time:'2026-10-09T00:00:00Z',data}),''),request.command==='apply'||(request.command==='api'&&request.args.action==='import')?180:10);
    }};
  };
  await page.addInitScript(mockBridge);
  await page.goto(origin);await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));
  assert.equal(await page.locator('nav [data-view="dashboard"]').getAttribute('aria-current'),'page');
  assert.equal(await page.locator('#dashboard .guide > li').count(),3,'overview explains the check, review and verification sequence');
  assert.equal(await page.locator('#dashboard .start-card [data-action="diagnose"]').count(),1,'overview offers a direct read-only phone check');
  assert.match(await page.locator('#dashboard').innerText(),/do not guarantee Wallet approval or successful Tap-to-Pay/);
  const disclosureViews=[['dashboard','configuration-details'],['import','optional-repairs'],['stack','stack-recovery-controls'],['stack','stack-close-controls'],['history','backup-restore-controls'],['advanced','api-source-controls'],['advanced','recovery-restore-controls'],['advanced','reset-clear-controls'],['advanced','reset-manual-controls'],['advanced','reset-close-controls']];
  const navigationBaseline=await page.evaluate(()=>window.testRequests);
  for(const [view,id] of disclosureViews) {
    const details=page.locator('#'+id);
    assert.equal(await details.evaluate(el=>el.open),false,`${id} starts closed`);
    await page.locator(`nav [data-view="${view}"]`).click();
    await openDisclosure(page,id);
    await details.locator(':scope > summary').click();
    assert.equal(await details.evaluate(el=>el.open),false,`${id} can close without a backend action`);
  }
  await page.locator('nav [data-view="dashboard"]').click();
  assert.deepEqual(await page.evaluate(()=>window.testRequests),navigationBaseline,'navigation and opening advanced controls never fetch, clear data or mutate configuration');
  assert.equal(await page.locator('#compact-targets').isChecked(),false,'overview does not select target compaction');
  assert.equal(await page.locator('#repair-targets').isChecked(),false,'overview does not select a required-target repair');
  assert.equal(await page.locator('#patch').inputValue(),'','overview does not propose a patch value');
  assert.equal(await page.locator('#stack-profile').inputValue(),'','overview does not choose a root-setting profile');
  assert.equal(await page.locator('[name="stack-target"]:checked,[name="stack-enabled"]:checked').count(),0,'root-setting targets and marker states start unselected');
  await mkdir(path.join(root,'build'),{recursive:true});
  await page.setViewportSize({width:1280,height:900});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'desktop overview does not overflow');
  await page.screenshot({path:path.join(root,'build','webui-overview-1280.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:path.join(root,'build','webui-390.png'),fullPage:true});
  await page.setViewportSize({width:320,height:680});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'320px overview does not overflow');
  await page.screenshot({path:path.join(root,'build','webui-overview-320.png'),fullPage:true});
  await assertUnsplitNavigationWords(page);
  await page.setViewportSize({width:390,height:844});
  await page.locator('#dashboard .start-card [data-action="diagnose"]').click();
  await page.waitForFunction(()=>!document.getElementById('diagnostics').hidden&&document.getElementById('diagnostics-time').textContent.startsWith('Collected'));
  assert.deepEqual(await page.evaluate(()=>window.testRequests.slice(-1)),[{command:'diagnose',args:{}}],'guided action submits only a read-only diagnosis');
  assert.equal(await page.evaluate(()=>window.testRequests.length),navigationBaseline.length+1,'guided phone check causes no secondary backend operation');
  await page.locator('nav [data-view="dashboard"]').click();
  await openDisclosure(page,'configuration-details');
  assert.equal(await page.locator('#dashboard-findings img').count(),0,'untrusted result must not create HTML');
  assert.match(await page.locator('#dashboard-findings').innerText(),/<img/);
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  assert.match(await page.locator('#current-summary').innerText(),/plan · review · 2026-10-09T00:01:00Z/,'last operation includes state and time');
  await page.locator('nav [data-view="import"]').click();
  await page.locator('#input-path').fill('/data/adb/wallet_diagnostic/inbox/synthetic.xml');
  await page.locator('[data-action="ingest"]').click();await page.waitForFunction(()=>document.getElementById('input-list').textContent.includes('Input 1'));
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'staged IDs must wrap on a narrow display');
  assert.equal(await page.locator('input[name="key-ecdsa"][value=""]').isChecked(),true,'explicit algorithm selection required');
  await page.locator('input[name="key-ecdsa"]:not([value=""])').check();
  await page.locator('input[name="key-rsa"]:not([value=""])').check();
  await page.locator('[data-action="plan"]').click();await page.locator('#plan-card').waitFor({state:'visible'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'plan IDs and SHA256 hashes must wrap');
  await page.screenshot({path:path.join(root,'build','webui-plan-390.png'),fullPage:true});
  assert.equal(await page.locator('#apply-button').isDisabled(),true,'apply requires review confirmation');
  await page.locator('#apply-confirm').check();await page.locator('#apply-button').click();
  assert.equal(await page.locator('[data-action="ingest"]').isDisabled(),true,'duplicate actions blocked during commit');
  await page.locator('#verify-card').waitFor({state:'visible'});
  assert.equal(await page.evaluate(()=>window.testRequests.filter(x=>x.command==='apply').length),1);
  await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete')&&!document.getElementById('wallet-ready').disabled);
  await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('unverified'));
  assert.match(await page.locator('#verification-result').innerText(),/Engine using this configuration\npending/,'public flags never promote pending engine adoption');
  await page.locator('#wallet-ready').check();await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('user-confirmed'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(x=>x.command==='verify').at(-1).args['reviewed-user']),'0','personal declarations bind the reviewed numeric user');
  const previous=await page.locator('#verification-result').textContent();
  await page.locator('nav [data-view="dashboard"]').click();await page.locator('[data-action="status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));
  assert.equal(await page.locator('#verification-result').textContent(),previous,'unchanged complete evidence binding retains its current outcome');
  await page.evaluate(()=>window.testActiveHash='3'.repeat(64));await page.locator('[data-action="status"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('no longer current'));
  assert.equal(await page.locator('#wallet-ready').isChecked(),false,'configuration change clears personal declarations');assert.doesNotMatch(await page.locator('#verification-result').textContent(),/user-confirmed/);
  await page.locator('nav [data-view="import"]').click();await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('unverified'));
  await page.locator('#wallet-ready').check();await page.evaluate(()=>window.testCurrentUser='10');
  const verifyCount=await page.evaluate(()=>window.testRequests.filter(x=>x.command==='verify').length);
  await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Repeat your personal checks'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(x=>x.command==='verify').length),verifyCount,'profile change discovered before Verify stops declaration submission');assert.equal(await page.locator('#wallet-ready').isChecked(),false);
  await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('unverified'));
  await page.locator('#wallet-ready').check();await page.evaluate(()=>window.testVerifyError=true);await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('E_STALE'));
  assert.match(await page.locator('#verification-result').textContent(),/no longer current/,'failed Verify replaces the previous outcome');assert.equal(await page.locator('#wallet-ready').isChecked(),false);
  await page.evaluate(()=>window.testVerifyError=false);await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('unverified'));await page.locator('#wallet-ready').check();
  await page.locator('nav [data-view="history"]').click();await openDisclosure(page,'backup-restore-controls');await page.locator('#rollback-confirm').check();await page.locator('#rollback-button').click();await page.waitForFunction(()=>document.getElementById('backup-preview').textContent.includes('restored'));
  assert.match(await page.locator('#verification-result').textContent(),/rollback was submitted/);assert.equal(await page.locator('#wallet-ready').isChecked(),false);
  await page.locator('nav [data-view="import"]').click();await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('unverified'));await page.locator('#wallet-ready').check();
  await page.locator('nav [data-view="advanced"]').click();
  await page.evaluate(()=>window.testRecovery=true);await page.locator('[data-action="recovery-status"]').click();await page.waitForFunction(()=>!document.getElementById('recovery-confirm').disabled);await openDisclosure(page,'recovery-restore-controls');await page.locator('#recovery-confirm').check();await page.locator('#recovery-button').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('Recovery restoration was submitted'));
  assert.equal(await page.locator('#wallet-ready').isChecked(),false);
  await page.locator('[data-action="trust-refresh"]').click();await page.waitForFunction(()=>document.getElementById('public-trust-result').textContent.includes('not-listed-as-of-feed'));
  assert.match(await page.locator('#public-trust-card').innerText(),/No keybox, private key, certificate or certificate serial is uploaded/);
  assert.deepEqual(await page.evaluate(()=>window.testRequests.filter(x=>x.command==='trust').at(-1)),{command:'trust',args:{action:'refresh'}},'public refresh passes only its action; no keys or identifiers');
  await page.locator('[data-action="watch"]').click();await page.waitForFunction(()=>document.getElementById('watch-result').textContent.includes('Patch alignment unknown'));
  await page.locator('nav [data-view="dashboard"]').click();await page.evaluate(()=>{window.testInvalidInventory=true;window.testTrustAvailable=false;});await page.locator('[data-action="status"]').click();await page.waitForFunction(()=>document.getElementById('current-summary').textContent.includes('declared inventory only'));
  assert.equal(await page.locator('#public-trust-card').isVisible(),false,'old backend without public evidence field hides unsupported controls');
  await page.locator('nav [data-view="import"]').click();await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('unverified'));await page.locator('#wallet-ready').check();await page.locator('[data-action="cancel-import"]').click();assert.match(await page.locator('#verification-result').textContent(),/review was cancelled/);assert.equal(await page.locator('#wallet-ready').isChecked(),false);
  await page.locator('nav [data-view="advanced"]').click();
  await openDisclosure(page,'reset-clear-controls');
  await page.locator('[data-action="reset-preview"]').click();await page.locator('#reset-confirm-fields').waitFor({state:'visible'});
  assert.match(await page.locator('#reset-preview').innerText(),/Reviewed numeric Android user: 0/);
  await page.locator('#reset-phrase').fill('wrong');assert.equal(await page.locator('#reset-button').isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.testRequests.filter(x=>x.command==='reset'&&x.args.action==='confirm').length),0,'test never executes reset even through mock');
  await page.locator('[data-action="api"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('E_API_UNAVAILABLE'));
  await page.evaluate(()=>window.testInvalidInventory=false);
  await page.locator('nav [data-view="import"]').click();
  await openDisclosure(page,'optional-repairs');
  assert.equal(await page.locator('#compact-targets').isChecked(),false,'compaction is an independent unchecked option');
  const compactionBaseline=await page.evaluate(()=>({ingests:window.testRequests.filter(r=>r.command==='ingest').length,applies:window.testRequests.filter(r=>r.command==='apply').length,hash:window.testActiveHash}));
  await page.locator('#compact-targets').check();
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='apply').length),compactionBaseline.applies,'checking compaction does not Apply');
  await page.locator('#plan-button').click();await page.locator('#plan-card').waitFor({state:'visible'});
  assert.deepEqual(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='plan').at(-1).args),{selections:'',targets:'false',patch:'','compact-targets':'true'},'compaction-only plan does not import keys or enable generate-mode repair');
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='ingest').length),compactionBaseline.ingests);
  assert.match(await page.locator('#plan-changes').innerText(),/4 entries → 2; 2 repeated entries removed/);
  await page.locator('#plan-changes details').filter({hasText:'target.txt: exact redacted changes and metadata'}).locator('summary').click();
  assert.match(await page.locator('#plan-changes').innerText(),/com\.example\.one!/);
  assert.equal(await page.locator('#apply-button').isDisabled(),true,'compaction needs separate review confirmation');
  await page.locator('[data-action="back-review"]').click();await page.locator('[data-action="cancel-import"]').click();
  assert.equal(await page.locator('#compact-targets').isChecked(),false,'cancel clears compaction opt-in');
  assert.equal(await page.evaluate(()=>window.testActiveHash),compactionBaseline.hash,'cancel does not mutate the active set');
  for(const review of ['missing','invalid','no-target']){
    await page.evaluate(value=>window.testCompactReview=value,review);await page.locator('#compact-targets').check();await page.locator('#plan-button').click();
    await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Apply is blocked'));
    assert.equal(await page.locator('#apply-button').isDisabled(),true,'incomplete or inconsistent compaction evidence cannot enable Apply');
    await page.locator('[data-action="cancel-import"]').click();
  }
  await page.evaluate(()=>{window.testCompactReview=undefined;window.testCompactError=true;});await page.locator('#compact-targets').check();await page.locator('#plan-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('E_SELECTION'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='apply').length),compactionBaseline.applies,'conflicting modes do not cause an automatic repair or Apply');
  await page.locator('[data-action="cancel-import"]').click();await page.evaluate(()=>window.testCompactError=false);
  await page.locator('#compact-targets').check();await page.locator('#repair-targets').check();await page.locator('#plan-button').click();await page.locator('#plan-card').waitFor({state:'visible'});
  assert.deepEqual(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='plan').at(-1).args),{selections:'',targets:'true',patch:'','compact-targets':'true'},'required-target repair joins compaction only by separate opt-in');
  assert.match(await page.locator('#plan-changes').innerText(),/before any separately selected required-target repair/);
  await page.locator('#plan-changes details summary').click();assert.match(await page.locator('#plan-changes').innerText(),/Added lines\ncom.google.android.gms!/);
  await page.locator('[data-action="back-review"]').click();await page.locator('[data-action="cancel-import"]').click();
  await page.locator('#compact-targets').check();await page.locator('#plan-button').click();await page.locator('#plan-card').waitFor({state:'visible'});
  await page.locator('nav [data-view="dashboard"]').click();await page.evaluate(()=>window.testResetState='awaiting-manual-reboot');await page.locator('[data-action="status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));
  await page.locator('nav [data-view="import"]').click();await page.locator('#apply-confirm').check();assert.equal(await page.locator('#apply-button').isDisabled(),true,'unfinished reset blocks even an already reviewed compaction plan');
  await page.locator('[data-action="back-review"]').click();assert.equal(await page.locator('#compact-targets').isDisabled(),true);assert.equal(await page.locator('#plan-button').isDisabled(),true);assert.match(await page.locator('#plan-blocker').innerText(),/Do not repeat app-data clears/);
  const pendingPlans=await page.evaluate(()=>window.testRequests.filter(r=>r.command==='plan').length);await page.locator('#plan-button').evaluate(button=>button.click());assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='plan').length),pendingPlans);
  await page.locator('[data-action="cancel-import"]').click();await page.evaluate(()=>window.testResetState='completed');await page.locator('nav [data-view="dashboard"]').click();await page.locator('[data-action="status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));
  await page.locator('nav [data-view="import"]').click();await page.locator('#compact-targets').check();await page.locator('#plan-button').click();await page.locator('#plan-card').waitFor({state:'visible'});await page.locator('#apply-confirm').check();await page.locator('#apply-button').click();
  await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete')&&!document.getElementById('wallet-ready').disabled);
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='apply').length),compactionBaseline.applies+1,'explicit compaction confirmation submits one Apply');assert.equal(await page.evaluate(()=>window.testActiveHash),compactionBaseline.hash,'target-only mocked Apply preserves keybox configuration');
  assert.match(await page.locator('#verification-result').innerText(),/Engine using this configuration\npending/);
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='reset'&&r.args.action==='confirm').length),0,'compaction tests never restart destructive clears');
  await page.locator('nav [data-view="advanced"]').click();await openDisclosure(page,'api-source-controls');assert.equal(await page.locator('#api-import-button').isDisabled(),true,'unsupported adapter cannot fetch');
  await page.evaluate(()=>window.testApiSupported=true);await page.locator('[data-action="api"]').click();await page.waitForFunction(()=>!document.getElementById('api-config-button').disabled);
  assert.match(await page.locator('#api-result').innerText(),/unconfigured/);assert.equal(await page.locator('#api-import-button').isDisabled(),true);
  const apiBaseline=await page.evaluate(()=>({config:window.testRequests.filter(r=>r.command==='api'&&r.args.action==='config').length,imports:window.testRequests.filter(r=>r.command==='api'&&r.args.action==='import').length,validation:window.testRequests.filter(r=>r.command==='validate').length,plans:window.testRequests.filter(r=>r.command==='plan').length,applies:window.testRequests.filter(r=>r.command==='apply').length}));
  await page.locator('#api-config-path').fill('https://private.example.invalid/feed?token=DO_NOT_SEND');await page.locator('#api-config-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Never enter a URL or credential'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='api'&&r.args.action==='config').length),apiBaseline.config,'URL entry is rejected before bridge serialization');
  await page.locator('#api-config-path').fill('/data/adb/wallet_diagnostic/inbox/api-config.json');await page.locator('#api-config-button').click();await page.waitForFunction(()=>!document.getElementById('api-import-button').disabled);
  await page.screenshot({path:path.join(root,'build','webui-api-390.png'),fullPage:true});
  assert.deepEqual(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='api'&&r.args.action==='config').at(-1).args),{action:'config',path:'/data/adb/wallet_diagnostic/inbox/api-config.json'});
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='api'&&r.args.action==='import').length),apiBaseline.imports,'configuration and status never fetch');
  await page.locator('#api-import-button').click();assert.equal(await page.locator('#api-import-button').isDisabled(),true,'duplicate fetch is disabled while busy');await page.waitForFunction(()=>document.getElementById('api-stage-result').textContent.includes('Validate it next'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='validate').length),apiBaseline.validation,'fetch stages without automatic validation');assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='plan').length),apiBaseline.plans);assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='apply').length),apiBaseline.applies);
  await page.locator('#api-validate-button').click();await page.waitForFunction(()=>!document.getElementById('import').hidden&&document.getElementById('input-list').textContent.includes('Input 1'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='validate').at(-1).args.id),'f'.repeat(32));assert.equal(await page.locator('input[name="key-ecdsa"][value=""]').isChecked(),true,'API validation never selects an algorithm');assert.equal(await page.locator('input[name="key-rsa"][value=""]').isChecked(),true);
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='plan').length),apiBaseline.plans);assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='apply').length),apiBaseline.applies);
  await page.locator('input[name="key-ecdsa"]:not([value=""])').check();await page.locator('#plan-button').click();await page.locator('#plan-card').waitFor({state:'visible'});await page.locator('nav [data-view="advanced"]').click();await page.locator('#api-config-button').click();await page.waitForFunction(()=>!document.getElementById('api-import-button').disabled);
  assert.equal(await page.locator('#apply-button').isDisabled(),true,'source reconfiguration discards a reviewed plan');assert.equal(await page.locator('#input-list').textContent(),'','source reconfiguration removes API inputs from the UI review');
  await page.locator('#api-import-button').click();await page.waitForFunction(()=>document.getElementById('api-stage-result').textContent.includes('Validate it next'));await page.evaluate(()=>window.testApiGeneration='9'.repeat(32));await page.locator('[data-action="api"]').click();await page.waitForFunction(()=>document.getElementById('api-stage-result').textContent.includes('configured source changed'));
  assert.equal(await page.locator('#api-validate-button').isDisabled(),true,'external source generation change invalidates unvalidated API staging');
  await page.locator('#api-import-button').click();await page.waitForFunction(()=>document.getElementById('api-stage-result').textContent.includes('Validate it next'));const staleAPIValidationCount=await page.evaluate(()=>window.testRequests.filter(r=>r.command==='validate').length);await page.evaluate(()=>window.testApiGeneration='6'.repeat(32));await page.locator('#api-validate-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('validation was not submitted'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='validate').length),staleAPIValidationCount,'manual API validation rechecks source freshness before submitting Validate');
  await page.locator('#api-import-button').click();await page.waitForFunction(()=>document.getElementById('api-stage-result').textContent.includes('Validate it next'));await page.evaluate(()=>window.testResetState='awaiting-manual-reboot');await page.locator('nav [data-view="dashboard"]').click();await page.locator('[data-action="status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));await page.locator('nav [data-view="advanced"]').click();
  for(const id of ['api-config-button','api-import-button','api-validate-button'])assert.equal(await page.locator('#'+id).isDisabled(),true,'pending reset blocks API mutations and validation');
  const pendingAPIRequests=await page.evaluate(()=>window.testRequests.length);await page.locator('#api-import-button').evaluate(button=>button.click());assert.equal(await page.evaluate(()=>window.testRequests.length),pendingAPIRequests);
  await page.evaluate(()=>window.testResetState='completed');await page.locator('nav [data-view="dashboard"]').click();await page.locator('[data-action="status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));await page.locator('nav [data-view="advanced"]').click();assert.equal(await page.locator('#api-validate-button').isDisabled(),true,'completing reset does not revive discarded staging or fetch automatically');
  await page.evaluate(()=>window.testApiImportError='E_API_TLS');await page.locator('#api-import-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('HTTPS verification failed'));assert.equal(await page.locator('#api-validate-button').isDisabled(),true);
  await page.evaluate(()=>{window.testApiImportError=undefined;window.testApiBadStage=true;});await page.locator('#api-import-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('no usable staged input ID'));assert.equal(await page.locator('#api-validate-button').isDisabled(),true);
  await page.evaluate(()=>{window.testApiBadStage=false;window.testApiValidationError=true;});await page.locator('#api-import-button').click();await page.waitForFunction(()=>document.getElementById('api-stage-result').textContent.includes('Validate it next'));await page.locator('#api-validate-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Mandatory keybox validation did not pass'));
  assert.doesNotMatch(await page.locator('body').textContent(),/API_SECRET_SENTINEL|private\.example\.invalid|BEGIN PRIVATE KEY/,'provider extras, errors and validation failures never enter UI text');assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  assert.equal(await page.evaluate(()=>window.testRequests.some(r=>JSON.stringify(r).includes('API_SECRET_SENTINEL')||JSON.stringify(r).includes('DO_NOT_SEND')||JSON.stringify(r).includes('private.example.invalid'))),false,'no credential or provider URL is serialized to bridge argv');assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='apply').length),apiBaseline.applies,'API operations never apply');
  await page.locator('nav [data-view="stack"]').click();assert.equal(await page.locator('#stack-profile').inputValue(),'');assert.equal(await page.locator('#stack-plan-button').isDisabled(),true,'unsupported stack cannot plan');
  await page.evaluate(()=>{window.testStackSupported=true;window.testStackHash='5'.repeat(64);window.testStackUnavailable=true;});await page.locator('[data-action="stack-status"]').click();await page.waitForFunction(()=>document.getElementById('stack-status-result').textContent.includes('unavailable'));await page.locator('#stack-profile').selectOption('hma-scope');assert.equal(await page.locator('#stack-plan-button').isDisabled(),true);assert.doesNotMatch(await page.locator('#stack-status-result').innerText(),/PRIVATE_STACK_SENTINEL/);
  await page.evaluate(()=>window.testStackUnavailable=false);await page.locator('[data-action="stack-status"]').click();await page.waitForFunction(()=>!document.getElementById('stack-plan-button').disabled);assert.equal(await page.locator('[name="stack-target"]:checked').count(),0,'Google scopes are never selected automatically');
  await page.locator('#stack-plan-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('target and one package checkbox explicitly'));
  await page.locator('#stack-package-input').fill('org.example.manager');await page.locator('[data-action="stack-candidates"]').click();assert.equal(await page.locator('[name="stack-package"]:checked').count(),0,'adding a package creates an unchecked candidate');await page.locator('[name="stack-target"][value="com.google.android.gms"]').check();await page.locator('[name="stack-package"]').check();
  for(const flag of ['testStackInvalidPlan','testStackWrongScope']){await page.evaluate(name=>window[name]=true,flag);await page.locator('#stack-plan-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Apply is blocked'));assert.equal(await page.locator('#stack-apply-button').isDisabled(),true);await page.evaluate(name=>window[name]=false,flag);}
  await page.locator('#stack-plan-button').click();await page.locator('#stack-plan-card').waitFor({state:'visible'});assert.match(await page.locator('#stack-plan-result').innerText(),/create the selected scope/);assert.equal(await page.locator('#stack-apply-button').isDisabled(),true,'stack Apply needs separate confirmation');
  await page.screenshot({path:path.join(root,'build','webui-stack-plan-390.png'),fullPage:true});
  assert.deepEqual(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='stack'&&r.args.action==='plan').at(-1).args),{action:'plan',profile:'hma-scope',targets:'com.google.android.gms','hide-packages':'org.example.manager'});
  const stackApplyBeforeUserChange=await page.evaluate(()=>window.testRequests.filter(r=>r.command==='stack'&&r.args.action==='apply').length);await page.locator('#stack-apply-confirm').check();await page.evaluate(()=>window.testCurrentUser='20');await page.locator('#stack-apply-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Apply was not submitted'));assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='stack'&&r.args.action==='apply').length),stackApplyBeforeUserChange,'profile switch before stack Apply invalidates review');
  await page.locator('#stack-plan-button').click();await page.locator('#stack-plan-card').waitFor({state:'visible'});await page.locator('nav [data-view="import"]').click();await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('unverified'));await page.locator('#wallet-ready').check();await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('user-confirmed'));await page.locator('nav [data-view="stack"]').click();await page.locator('#stack-apply-confirm').check();await page.locator('#stack-apply-button').click();await page.waitForFunction(()=>document.getElementById('stack-operation-result').textContent.includes('state: committed')&&!document.getElementById('stack-verify-button').disabled);
  assert.equal(await page.locator('#wallet-ready').isChecked(),false,'stack Apply invalidates Wallet user declarations');assert.match(await page.locator('#verification-result').textContent(),/no longer current/);assert.match(await page.locator('#stack-operation-result').innerText(),/Runtime adoption: unknown/);assert.match(await page.locator('#stack-operation-result').innerText(),/Reboot manually/);
  await page.locator('#stack-verify-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));assert.match(await page.locator('#stack-operation-result').innerText(),/Persisted file readback verified/);assert.match(await page.locator('#stack-operation-result').innerText(),/Runtime adoption: unknown/,'readback never promotes runtime adoption');
  await page.locator('nav [data-view="import"]').click();await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('unverified'));await page.locator('#wallet-ready').check();await page.locator('[data-action="verify"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('user-confirmed'));await page.locator('nav [data-view="dashboard"]').click();await page.evaluate(()=>window.testStackHash='9'.repeat(64));await page.locator('[data-action="status"]').click();await page.waitForFunction(()=>document.getElementById('verification-result').textContent.includes('no longer current'));assert.equal(await page.locator('#wallet-ready').isChecked(),false,'external stack evidence change clears readiness with unchanged Wallet files');
  await page.locator('nav [data-view="stack"]').click();await openDisclosure(page,'stack-recovery-controls');await page.locator('#stack-rollback-confirm').check();await page.evaluate(()=>window.testCurrentUser='21');await page.locator('#stack-rollback-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('review is stale'));assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='stack'&&r.args.action==='rollback').length),0,'current-user switch before rollback requires a new confirmation');
  await page.locator('#stack-rollback-confirm').check();await page.locator('#stack-rollback-button').click();await page.waitForFunction(()=>document.getElementById('stack-operation-result').textContent.includes('state: restored'));assert.match(await page.locator('#stack-operation-result').innerText(),/Runtime adoption: unknown/);
  await page.locator('#stack-profile').selectOption('brezygisk-unmount');assert.equal(await page.locator('[name="stack-enabled"]:checked').count(),0,'unmount marker has no default');await page.locator('#stack-plan-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('marker value explicitly'));await page.locator('[name="stack-enabled"][value="true"]').check();await page.locator('#stack-plan-button').click();await page.locator('#stack-plan-card').waitFor({state:'visible'});
  assert.deepEqual(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='stack'&&r.args.action==='plan').at(-1).args),{action:'plan',profile:'brezygisk-unmount',enabled:'true'},'marker plan carries no previously selected HMA packages/scopes');
  await page.evaluate(()=>window.testStackApplyError=true);await page.locator('#stack-apply-confirm').check();await page.locator('#stack-apply-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('stack file operation stopped'));
  assert.equal(await page.locator('#stack-plan-button').isDisabled(),true);assert.equal(await page.locator('#plan-button').isDisabled(),true,'pending stack journal blocks keybox planning');assert.equal(await page.locator('#api-import-button').isDisabled(),true,'pending stack journal blocks API imports');
  await page.locator('#stack-rollback-confirm').check();assert.equal(await page.locator('#stack-rollback-button').isDisabled(),false,'matching explicit stack rollback is available for own interrupted write');await page.evaluate(()=>window.testResetState='awaiting-manual-reboot');await page.locator('[data-action="stack-status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));assert.equal(await page.locator('#stack-rollback-button').isDisabled(),true,'foreign unfinished reset blocks stack rollback');
  await page.evaluate(()=>{window.testResetState='completed';window.testStackApplyError=false;});await page.locator('[data-action="stack-status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));await page.locator('#stack-rollback-confirm').check();await page.locator('#stack-rollback-button').click();await page.waitForFunction(()=>document.getElementById('stack-operation-result').textContent.includes('state: restored')&&!document.getElementById('stack-plan-button').disabled);
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='stack'&&r.args.action==='rollback').length),2,'rollback happens only through explicit confirmation');assert.doesNotMatch(await page.locator('body').textContent(),/PRIVATE_STACK_SENTINEL/,'private stack fields and errors never enter UI');assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='reset'&&r.args.action==='confirm').length),0);
  await page.locator('[data-action="stack-cancel"]').click();assert.equal(await page.locator('#stack-profile').inputValue(),'');assert.equal(await page.locator('[name="stack-target"]:checked').count(),0);assert.equal(await page.locator('[name="stack-package"]').count(),0);assert.equal(await page.locator('[name="stack-enabled"]:checked').count(),0);
  assert.deepEqual(consoleErrors,[]);
  assert.equal(runtimeRequests.some(url=>url.endsWith('.wasm')),false,'explicit WASM bytes require no file-origin fetch');
  assert.equal(runtimeRequests.some(url=>!url.startsWith(origin)),false,'the Rust interface never fetches remote scripts or private API feeds from the browser');
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth);assert.equal(overflow,false,'narrow mobile layout must not overflow');
  const noBridge=await browser.newPage({viewport:{width:320,height:680}});await noBridge.goto(origin);await noBridge.waitForFunction(()=>document.getElementById('notice').textContent.includes('bridge unavailable'));
  assert.equal(await noBridge.locator('[data-action="status"]').isDisabled(),true,'missing bridge blocks backend actions');
  await page.evaluate(()=>{window.testResetState='failed-do-not-repeat';window.testResetCloseHash='9'.repeat(64);});
  await page.locator('nav [data-view="advanced"]').click();
  await openDisclosure(page,'reset-close-controls');
  await page.locator('[data-action="reset-status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));
  await page.locator('#reset-close-phrase').fill('CLOSE INCOMPLETE RESET WITHOUT REPEATING');
  await page.evaluate(()=>window.testResetCloseHash='8'.repeat(64));
  await page.locator('#reset-close-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Reset evidence changed'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='reset'&&r.args.action==='close').length),0,'stale reset ledger is never closed');
  await page.locator('[data-action="reset-status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));
  await page.locator('#reset-close-phrase').fill('CLOSE INCOMPLETE RESET WITHOUT REPEATING');await page.locator('#reset-close-button').click();
  await page.waitForFunction(()=>window.testResetState==='closed-incomplete'&&document.getElementById('notice').textContent.startsWith('Complete'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='reset'&&r.args.action==='confirm').length),0,'closing never dispatches the destructive reset');
  await page.evaluate(()=>{window.testStackPending=true;window.testStackOperation={id:'d'.repeat(32),profile:'brezygisk-unmount',state:'recovery-required',can_verify:false,can_rollback:false,can_resolve:true,resolution_review_hash:'9'.repeat(64)};});
  await page.locator('nav [data-view="stack"]').click();await page.locator('[data-action="stack-status"]').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));
  await openDisclosure(page,'stack-close-controls');
  await page.locator('#stack-resolve-phrase').fill('KEEP CURRENT STACK FILE');await page.evaluate(()=>window.testStackOperation.resolution_review_hash='8'.repeat(64));
  await page.locator('#stack-resolve-button').click();await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Stack evidence changed'));
  assert.equal(await page.evaluate(()=>window.testRequests.filter(r=>r.command==='stack'&&r.args.action==='resolve').length),0,'stale stack resource is never closed');
  await page.locator('#stack-resolve-phrase').fill('KEEP CURRENT STACK FILE');await page.locator('#stack-resolve-button').click();await page.waitForFunction(()=>document.getElementById('stack-operation-result').textContent.includes('Stack operation closed'));
  assert.equal(await page.evaluate(()=>window.testStackOperation.state),'superseded');
  const brokenWasm=await browser.newPage({viewport:{width:320,height:680}});
  await brokenWasm.route('**/rhso_webui_bytes.js',route=>route.fulfill({contentType:'text/javascript',body:'export const wasmBase64="aW52YWxpZA==";'}));
  await brokenWasm.goto(origin);await brokenWasm.waitForFunction(()=>document.getElementById('notice').textContent.includes('Rust interface could not start'));
  assert.equal(await brokenWasm.locator('button:enabled,input:enabled,select:enabled').count(),0,'incompatible WASM bootstrap fails closed with an exact CLI fallback');
  const enlarged=await browser.newPage({viewport:{width:320,height:680}});
  const normalFontSizes=await page.evaluate(()=>[document.documentElement,document.body,document.querySelector('nav button')].map(el=>Number.parseFloat(getComputedStyle(el).fontSize)));
  assert.ok(normalFontSizes.every(size=>Number.isFinite(size)&&size>0),'baseline font sizes are measurable');
  await enlarged.addInitScript(mockBridge);
  enlarged.on('request',request=>runtimeRequests.push(request.url()));
  enlarged.on('pageerror',error=>consoleErrors.push(error.message));
  await enlarged.route('**/style.css',async route=>route.fulfill({contentType:'text/css',body:(await readFile(path.join(webroot,'style.css'),'utf8'))+`\n:root { font-size: ${normalFontSizes[0]*2}px !important; }\n`}));
  await enlarged.goto(origin);await enlarged.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete'));
  const enlargedFontSizes=await enlarged.evaluate(()=>[document.documentElement,document.body,document.querySelector('nav button')].map(el=>Number.parseFloat(getComputedStyle(el).fontSize)));
  for(let i=0;i<normalFontSizes.length;i++)assert.ok(Math.abs(enlargedFontSizes[i]-normalFontSizes[i]*2)<0.01,'computed root, body and navigation text really doubles');
  assert.equal(await enlarged.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'200% enlarged overview must remain usable at 320px');
  await enlarged.screenshot({path:path.join(root,'build','webui-overview-enlarged-320.png'),fullPage:true});
  await assertUnsplitNavigationWords(enlarged);
  await enlarged.locator('nav [data-view="import"]').click();await openDisclosure(enlarged,'optional-repairs');
  assert.equal(await enlarged.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'200% enlarged text must remain usable at 320px');
  await enlarged.screenshot({path:path.join(root,'build','webui-enlarged-320.png'),fullPage:true});
  await enlarged.locator('nav [data-view="stack"]').click();await enlarged.evaluate(()=>window.testStackSupported=true);await enlarged.locator('[data-action="stack-status"]').click();await enlarged.waitForFunction(()=>document.getElementById('notice').textContent.startsWith('Complete')&&!document.getElementById('stack-profile').disabled);await enlarged.locator('#stack-profile').selectOption('hma-scope');await openDisclosure(enlarged,'stack-recovery-controls');assert.equal(await enlarged.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'stack scopes and recovery controls remain usable with 200% text at 320px');
  await enlarged.locator('nav [data-view="advanced"]').click();await openDisclosure(enlarged,'api-source-controls');assert.equal(await enlarged.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'private-file API controls remain usable with 200% text at 320px');
  assert.equal(await enlarged.evaluate(()=>window.testRequests.some(r=>!['status','stack'].includes(r.command)||(r.command==='stack'&&r.args.action!=='status'))),false,'enlarged layout checks dispatch no write or private-source fetch');
  assert.deepEqual(consoleErrors,[]);assert.equal(runtimeRequests.some(url=>!url.startsWith(origin)||url.endsWith('.wasm')),false,'all enlarged-page assets stay local and require no WASM fetch');
  console.log('PASS: guided read-only overview, default-closed controls and inert navigation, mobile and true 200% text layout, safe rendering, stale/user-bound verification, target compaction, redacted private-file API staging, explicit stack selectors/review/apply/file verification/rollback, external stack evidence freshness and pending reset/journal gates.');
  console.log('Screenshots: build/webui-overview-1280.png, build/webui-390.png, build/webui-overview-320.png, build/webui-overview-enlarged-320.png and workflow captures (mock evidence only).');
} finally {if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
