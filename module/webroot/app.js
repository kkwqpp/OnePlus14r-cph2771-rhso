import {exec} from './ksu.js';
import {encodeRequest,readResult,safeText,list,selectionValue,evidenceBinding,targetCompactionCounts,privateAPIConfigPath,apiStatusView,redactedAPIResponse,stackTargets,stackProfiles,stackStates,stackStatusView,stackPackageList,stackPlanView,redactedStackError} from './ui-core.js';

const $ = id => document.getElementById(id);
const state = {busy:false,bridge:false,inputs:[],plan:null,reset:null,resetPending:false,stackPending:false,backups:[],recovery:false,lockPresent:false,applyAvailable:true,evidenceBinding:null,currentUser:null,verificationBinding:null,verificationSeen:false,diagnosticBinding:null,apiSupported:false,apiReady:false,apiGeneration:null,apiStage:null,stack:null,stackPlan:null,stackPlanBinding:null,stackRollbackBinding:null};
const confirmations = ['apply-confirm','rollback-confirm','recovery-confirm'];
function text(value, fallback) { return safeText(value, fallback); }
function node(tag, content, className) { const el=document.createElement(tag); if(content!==undefined)el.textContent=text(content); if(className)el.className=className; return el; }
function clear(id) { $(id).replaceChildren(); return $(id); }
function invalidateVerification(reason) {
  $('wallet-ready').checked=false;$('tap-confirmed').checked=false;
  if(state.verificationSeen || $('verification-result').childElementCount) {
    clear('verification-result').append(node('p',`Previous verification is no longer current. ${reason} Collect fresh verification and repeat any user checks after the relevant change.`));
    $('apply-result').textContent='';
  }
  state.verificationSeen=false;state.verificationBinding=null;
}
function recordVerification(response) {
  describeOutcome('verification-result',response);
  state.verificationSeen=true;state.verificationBinding=evidenceBinding(response.data);
  if(state.verificationBinding){state.evidenceBinding=state.verificationBinding;state.currentUser=response.data.current_android_user;}
  if(!state.verificationBinding) $('verification-result').append(node('p','Configuration/user binding is unavailable. This result is historical evidence; collect current status and repeat user checks before relying on readiness.'));
}
function show(view) {
  for (const el of document.querySelectorAll('.view')) el.hidden=el.id!==view;
  for (const el of document.querySelectorAll('nav [data-view]')) { if(el.dataset.view===view)el.setAttribute('aria-current','page'); else el.removeAttribute('aria-current'); }
  $('main').focus({preventScroll:true});
}
function notice(message, error=false) { $('notice').textContent=text(message); $('notice').classList.toggle('error',error); }
function sync() {
  for(const button of document.querySelectorAll('[data-action]')) button.disabled=state.busy || !state.bridge;
  $('apply-button').disabled=state.busy || !state.bridge || !state.applyAvailable || !state.plan || !$('apply-confirm').checked;
  $('plan-button').disabled=state.busy || !state.bridge || !state.applyAvailable;
  $('rollback-button').disabled=state.busy || !state.bridge || !$('rollback-confirm').checked;
  $('recovery-button').disabled=state.busy || !state.bridge || !state.recovery || !$('recovery-confirm').checked;
  $('release-lock-button').disabled=state.busy || !state.bridge || !state.lockPresent;
  $('reset-button').disabled=state.busy || !state.bridge || !state.reset || $('reset-phrase').value!=='CLEAR WALLET AND GOOGLE SERVICES';
  $('reset-complete-button').disabled=state.busy || !state.bridge || $('reset-complete-phrase').value!=='PIF ACTION AND GMS FORCE-STOP COMPLETED';
  for(const input of document.querySelectorAll('input,select')) input.disabled=state.busy;
  $('compact-targets').disabled=state.busy || !state.bridge || !state.applyAvailable;
  const apiBlocked=state.busy || !state.bridge || state.resetPending || state.recovery || state.stackPending;
  $('api-config-button').disabled=apiBlocked || !state.apiSupported;
  $('api-config-path').disabled=apiBlocked || !state.apiSupported;
  $('api-import-button').disabled=apiBlocked || !state.apiReady;
  $('api-validate-button').disabled=apiBlocked || !state.apiStage;
  const profile=$('stack-profile').value,capability=state.stack?.profiles.find(item=>item.id===profile),stackBlocked=apiBlocked;
  $('stack-plan-button').disabled=stackBlocked || !capability?.available;
  $('stack-apply-button').disabled=stackBlocked || !state.stackPlan || !$('stack-apply-confirm').checked;
  $('stack-hma-fields').hidden=profile!=='hma-scope';$('stack-marker-fields').hidden=profile!=='brezygisk-unmount';
  for(const input of document.querySelectorAll('[name="stack-target"]'))input.disabled=stackBlocked || !state.stack?.allowed_targets.includes(input.value);
  const operationID=$('stack-operation-id').value,operation=state.stack?.operation,matching=operation?.id===operationID;
  $('stack-verify-button').disabled=state.busy || !state.bridge || !/^[a-f0-9]{32}$/.test(operationID) || !matching || !operation.can_verify;
  $('stack-rollback-button').disabled=state.busy || !state.bridge || state.resetPending || state.recovery || !matching || !operation?.can_rollback || !state.stackRollbackBinding || state.stackRollbackBinding!==state.evidenceBinding || !$('stack-rollback-confirm').checked;
  $('stack-blocker').textContent=state.resetPending || state.recovery || state.stackPending?'A pending reset or transaction blocks new stack changes. Inspect its state and use the matching explicit recovery action.':capability?.available?'Review every selected target and package; a manual reboot follows Apply and rollback.':capability?.reason || 'Inspect capabilities and choose a supported profile. Nothing is selected automatically.';
  $('notice').classList.toggle('busy',state.busy);
  $('main').setAttribute('aria-busy',String(state.busy));
  for(const button of document.querySelectorAll('[data-view]')) button.disabled=state.busy;
}
async function request(command,args={},progress='Collecting evidence…',privateResult=false) {
  if(state.busy)throw new Error('An operation is already running.');
  if(!state.bridge)throw new Error('WebUI root bridge unavailable. Use the exact CLI entry point in Advanced.');
  const payload=encodeRequest(command,args);
  state.busy=true; sync(); notice(progress);
  try {
    // The only dynamic shell token is a bounded base64url alphabet. No filename/token/XML interpolation.
    const result=await exec('/data/adb/modules/wallet_diagnostic/bin/walletdiag request '+payload);
    let response=readResult(result.stdout);
    if(command==='api')response=redactedAPIResponse(response);
    else if(command==='stack' && !response.ok)response=redactedStackError(response);
    else if(privateResult) {const redacted=redactedAPIResponse(response);response={...response,code:redacted.code,message:redacted.message,...(!response.ok?{data:redacted.data}:{})};}
    if(Number(result.errno)!==0 && response.ok)throw new Error('Backend ended unexpectedly despite a success-shaped response. Inspect recovery before another write.');
    notice(`${response.ok?'Complete':'Stopped'} · ${response.code}: ${response.message}`,!response.ok);
    if(!response.ok) { const error=new Error(response.message); error.response=response; throw error; }
    return response;
  } finally { state.busy=false; sync(); }
}
function pairs(id, entries) {
  const el=clear(id);
  for(const [label,value] of entries) { el.append(node('dt',label),node('dd',value)); }
}
function items(container, values) {
  const ul=node('ul');
  for(const value of list(values)) if(typeof value==='string')ul.append(node('li',warningText(value)));
  if(ul.childElementCount)container.append(ul);
}
function warningText(value) {
  const known={trust_not_established:'Public trust is not established by local chain validation.',revocation_unknown:'Revocation status is unknown.',engine_compatibility_requires_verification:'Engine compatibility and actual adoption require separate verification.',pkcs8_requires_traditional_pem_for_installed_engine:'Source private key uses PKCS#8. A reviewed merge converts it to the traditional PEM required by the inspected engine.',private_key_encoding_normalized_for_installed_engine:'Output private-key encoding is converted to SEC1 for ECDSA or PKCS#1 for RSA. The mathematical key and complete chain stay together.',metadata_placeholder_indicator:'Source metadata has a placeholder indicator; source identity is withheld.',certificate_placeholder_indicator:'A certificate has a placeholder indicator; review provenance and trust.',single_self_signed_certificate_placeholder_possible:'A single self-signed certificate may be placeholder material.',self_signed_anchor_does_not_establish_trust:'A self-signed chain anchor does not establish public trust.',duplicate_algorithm_explicit_selection_required:'Duplicate algorithm entries require explicit selection.'};
  return known[value] || value;
}
function finding(container,f) {
  if(!f || typeof f!=='object')return;
  const card=node('article',undefined,'card');
  card.append(node('h3',f.title || f.code || 'Finding'),node('p',f.message || f.summary || f.evidence));
  const dl=node('dl');
  const entries=[['Evidence type',f.kind || f.certainty || 'Hypothesis / evidence limits unspecified'],['Collected',f.collected_at || f.time],['Freshness',f.stale===true?'Stale — collect again':f.freshness || 'Recheck after relevant changes']];
  for(const [k,v] of entries)dl.append(node('dt',k),node('dd',v));
  card.append(dl);
  const details=node('details'); details.append(node('summary','Evidence, repair and verification'));
  for(const [k,v] of [['Evidence',f.evidence],['Expected effect',f.expected_effect],['Proposed repair',f.repair || f.proposed_repair],['Risk',f.risk],['Rollback',f.rollback],['Verify with',f.verification],['Dependencies / uncertainty',f.dependency || f.dependencies || f.uncertainty]]) {
    if(typeof v==='string')details.append(node('p',`${k}: ${text(v)}`)); else if(Array.isArray(v)) { details.append(node('p',k)); items(details,v); }
  }
  card.append(details); container.append(card);
}
function findings(id,value) { const el=clear(id); for(const f of list(value))finding(el,f); if(!el.childElementCount)el.append(node('p','No findings in this response. This does not establish Wallet acceptance.')); }
function describeOutcome(id,response) {
  const el=clear(id);
  const d=response.data;
  el.append(node('p',d.message || response.message));
  const dl=node('dl');
  if(d.user!==undefined)dl.append(node('dt','Reviewed numeric Android user'),node('dd',d.user));
  const reboot=d.manual_reboot_required ?? d.reboot_required;
  for(const [k,v] of [['Files committed',d.files_committed ?? d.committed],['Engine health',d.engine_health || d.health || d.engine?.health],['Adoption',d.adoption || d.engine_adoption],['Wallet readiness',d.wallet_readiness || 'User test required'],['Tap-to-Pay',d.tap_to_pay || 'User test required'],['Wallet acceptance',d.wallet_acceptance || 'User test required'],['Operation / journal state',d.state],['Lock present',d.lock_present],['Manual reboot',reboot===true?'Required by reviewed procedure; never automatic':reboot===false?'Not required by this result':'Not established'],['Evidence collected',response.time]])dl.append(node('dt',k),node('dd',v));
  el.append(dl);if(d.identity_evidence)el.append(node('p',d.identity_evidence));if(d.next_step)el.append(node('p',d.next_step));items(el,d.warnings); if(Array.isArray(d.findings))for(const f of d.findings)finding(el,f);
}
function renderDiagnosticContext(data) {
  const el=clear('diagnostic-context'), device=data.device || {};
  const dl=node('dl');
  for(const [label,key] of [['Wallet stage','wallet_stage'],['Generic integrity','generic_integrity'],['Real bootloader','real_bootloader'],['Current numeric Android user','current_android_user'],['Wallet role','wallet_role'],['NFC','nfc'],['Default contactless payment','default_payment'],['Automatic time','automatic_time'],['Device time','device_time'],['Validated connectivity','validated_connectivity'],['Persistent aliases counted','persistent_alias_count'],['Alias limits','persistent_alias_warning'],['Certification','certification'],['Issuer / region / account limits','issuer_region_account']])dl.append(node('dt',label),node('dd',device[key]));
  el.append(dl);
  for(const app of list(data.applications))if(app && typeof app==='object')el.append(node('p',`${text(app.package)} · Version ${text(app.version)} · Current UID ${text(app.uid)}`));
  if(device.network_checks){el.append(node('p',device.network_checks.failure_evidence));items(el,device.network_checks.blocked_service_domains);}
}
function renderStatus(response) {
  const d=response.data, active=d.active || {}, last=d.last_operation || {};
  const binding=evidenceBinding(d), previous=state.evidenceBinding;
  const changed=previous!==null && previous!==binding;
  if(changed){$('stack-rollback-confirm').checked=false;state.stackRollbackBinding=null;}
  if(state.stackPlan && state.stackPlanBinding!==binding)discardStackPlan('Current configuration, stack evidence or numeric Android user changed. Build a fresh stack plan.');
  if(changed || (state.verificationSeen && (!binding || binding!==state.verificationBinding)))invalidateVerification('Current configuration or Android user changed, or its binding could not be established.');
  if(state.diagnosticBinding && state.diagnosticBinding!==binding) {
    $('diagnostics-time').textContent='Previous diagnostic view is stale: configuration or Android user changed. Collect diagnostics again.';
    clear('diagnostic-context').append(node('p','Collect diagnostics again for current device evidence.'));
    clear('diagnostic-findings').append(node('p','Previous findings were invalidated by a relevant configuration/user change.'));
    state.diagnosticBinding=null;
  }
  state.evidenceBinding=binding;
  state.currentUser=binding?d.device?.current_android_user ?? d.current_android_user:null;
  let algorithms=Array.isArray(d.algorithms)?d.algorithms.join(', '):d.algorithms;
  if(!algorithms && Array.isArray(active.algorithms))algorithms=active.algorithms.join(', ');
  const keybox=d.keybox_summaries?.['keybox.xml'];
  const validated=keybox?.structural_valid===true && keybox?.cryptographic_consistent===true;
  if(!validated)algorithms=algorithms?`${algorithms} (declared inventory only; mandatory validation not established)`:'No validated signing-key inventory established';
  const configuration=active.summary || d.configuration_summary || (active['keybox.xml']?['keybox.xml','security_patch.txt','target.txt'].map(name=>`${name}: ${active[name]?.exists?'present':'absent'}`).join(' · '):'See fresh diagnostics for configuration validation');
  const backupCount=list(d.rollback?.backups).length;
  pairs('current-summary',[['Algorithms',algorithms],['Mandatory keybox checks',validated?'Structure and cryptographic consistency passed':'Not established; inspect current findings'],['Public trust / revocation',`${text(keybox?.trust,'unknown')} / ${text(keybox?.revocation,'unknown')}`],['Active configuration',configuration],['Current numeric Android user',d.device?.current_android_user],['Evidence collected',d.evidence_time || response.time],['Freshness',d.freshness || 'Recollect after configuration changes'],['Last operation',typeof last==='string'?last:(last.type || last.command?`${text(last.type || last.command)} · ${text(last.state || last.status)} · ${text(last.time || last.timestamp)}`:'No recorded operation')],['Rollback available',typeof d.rollback==='string'?d.rollback:(d.rollback?.available===true || backupCount?'Yes; inspect backups':d.rollback?.available===false || Array.isArray(d.rollback?.backups)?'No recorded backup':'Inspect backups')]]);
  $('next-step').textContent=text(d.next_step,'Collect fresh diagnostics before selecting a repair.');
  findings('dashboard-findings',d.findings);
  const recovery=d.recovery;
  state.recovery=needsRecovery(recovery);
  $('recovery-card').hidden=!state.recovery;
  $('recovery-summary').textContent=text(recovery?.message || recovery?.next_step,'A journal needs review. Inspect recovery before starting another write.');
  const resetPending=!!(d.reset && typeof d.reset.state==='string' && !['none','completed'].includes(d.reset.state));
  state.resetPending=resetPending;
  state.stackPending=d.stack_pending===true || d.stack?.stack_pending===true;
  state.applyAvailable=d.apply_available!==false && !resetPending && !state.stackPending;
  $('plan-blocker').textContent=resetPending?'A one-shot reset is unfinished. Inspect reset state and complete its reviewed manual steps before another plan. Do not repeat app-data clears.':state.stackPending?'An unfinished stack transaction blocks new configuration changes. Inspect the stack operation and explicitly restore its private backup.':state.applyAvailable?'':'Apply is unavailable: inspect the capability finding in Diagnostics, then refresh status after the supported resolution.';
  const history=clear('history-list');
  for(const op of list(d.history)) {
    if(!op || typeof op!=='object')continue;
    history.append(node('p',`${text(op.time || op.timestamp)} · ${text(op.command || op.type)} · ${text(op.code || op.status || op.state)}${op.verified?' · Recorded verification':''}`));
  }
  if(!history.childElementCount)history.append(node('p','No operation history returned.'));
  renderPublicTrust(d.public_attestation);
  renderAPI(d.api);
  if(d.stack!==undefined)renderStackStatus(d.stack);
  if((resetPending || state.recovery || state.stackPending) && (state.apiStage || state.inputs.some(input=>input.source==='api')))discardAPIReview('A pending reset or transaction invalidated this API review. Complete the reviewed recovery steps, then explicitly import again.',true);
  sync();
}
function discardAPIReview(reason,dropInputs=false) {
  state.apiStage=null;state.plan=null;$('apply-confirm').checked=false;$('plan-card').hidden=true;$('selection-card').hidden=false;$('import-input').hidden=false;
  $('api-stage-result').textContent=reason;
  if(dropInputs)state.inputs=state.inputs.filter(input=>input.source!=='api');
  renderSelections();sync();
}
function renderAPI(value) {
  const data=apiStatusView(value),generation=data?.configured?data.source_generation:null;
  if(state.apiGeneration!==null && state.apiGeneration!==generation)discardAPIReview('The configured source changed or became unavailable. Previous API inputs were removed from this review; private staged files are retained. Explicitly import and validate again.',true);
  state.apiGeneration=generation;state.apiSupported=!!data;state.apiReady=data?.available===true;
  const el=clear('api-result'),dl=node('dl');
  if(!data)el.append(node('p','This backend does not expose the configured generic raw-XML adapter. The exact supplied endpoint remains unverified and unavailable. Local import remains available.'));
  else {
    for(const [label,result] of [['Generic adapter','Configured HTTPS raw XML'],['Configuration state',data.state],['Configured source ready',data.available],['Authentication configured',data.auth_configured],['Exact supplied endpoint available','No'],['Provider contract verified','No']])dl.append(node('dt',label),node('dd',result));
    el.append(dl);
  }
  $('api-reason').textContent=state.resetPending || state.recovery || state.stackPending?'An unfinished reset or transaction blocks configuration, fetch and API validation. Inspect its state; do not repeat app-data clears.':data?'Only an explicit Fetch reads the configured feed. Imported material stays staged until you validate and review it; no key selection, Plan or Apply is automatic.':'Install a matching backend to use private-file configuration. Never enter credentials or a URL here.';
  sync();
}
function discardStackPlan(reason) {
  state.stackPlan=null;state.stackPlanBinding=null;$('stack-apply-confirm').checked=false;$('stack-plan-card').hidden=true;
  if(reason)$('stack-operation-result').textContent=reason;
}
function invalidateStackEvidence(reason) {
  invalidateVerification(reason);state.evidenceBinding=null;state.diagnosticBinding=null;
  $('diagnostics-time').textContent='Previous diagnostics are stale after a submitted stack change. Collect diagnostics again.';
  clear('diagnostic-context').append(node('p','Collect fresh device and stack evidence.'));clear('diagnostic-findings').append(node('p',reason));
  state.plan=null;$('apply-confirm').checked=false;$('plan-card').hidden=true;$('selection-card').hidden=false;$('import-input').hidden=false;
}
function renderStackStatus(value) {
  const data=stackStatusView(value),previous=state.stack?.operation;
  if(state.stackPlan && (!data || data.unfinished || !data.profiles.find(profile=>profile.id===state.stackPlan.profile)?.available || (data.operation?.id!==state.stackPlan.operationBefore && data.operation?.id!==state.stackPlan.id)))discardStackPlan('Stack capability or operation changed. Build a fresh review before another Apply.');
  state.stack=data;
  if(data?.unfinished){if(data.stack_pending)state.stackPending=true;state.applyAvailable=false;discardStackPlan('An unfinished configuration operation blocks new stack changes. Inspect its matching recovery action.');}
  const el=clear('stack-status-result');
  if(!data)el.append(node('p','This backend does not expose a supported stack interface. Install a matching module; no stack changes are available.'));
  else {
    for(const profile of data.profiles)el.append(node('p',`${stackProfiles[profile.id]}: ${profile.available?'available':'unavailable'}. ${profile.reason}`));
    el.append(node('p',`Unfinished configuration operation: ${data.unfinished?'yes':'no'}. Runtime adoption: unknown. Manual reboot is required after Apply and rollback.`));
    if(data.operation){const op=data.operation;el.append(node('p',`Operation ${op.id} · ${stackProfiles[op.profile]} · ${op.state} · Private backup ${op.backup_available?'available':'not established'}.`));if(!$('stack-operation-id').value || $('stack-operation-id').value===previous?.id)$('stack-operation-id').value=op.id;}
  }
  sync();
}
function renderStackPlan(value,choices) {
  const plan=stackPlanView(value);
  if(plan.profile!==choices.profile || (plan.profile==='hma-scope' && plan.changes.some(change=>!choices.targets.includes(change.target) || change.added_count>choices.packages.length)) || (plan.profile==='brezygisk-unmount' && plan.changes[0].enabled_after!==(choices.enabled==='true')))throw new Error('Stack preview differs from the explicit selections. Apply is blocked.');
  state.stackPlan={...plan,operationBefore:state.stack?.operation?.id,choices};state.stackPlanBinding=state.evidenceBinding;
  const el=clear('stack-plan-result');el.append(node('p',`${stackProfiles[plan.profile]} · Plan ${plan.id}`),node('p','Apply creates and verifies a private full backup before writing. Apply and rollback require a manual reboot. Runtime adoption and Wallet acceptance remain unknown.'));
  if(plan.profile==='hma-scope'){el.append(node('p','Explicit packages selected in this review: '+choices.packages.join(', ')));for(const change of plan.changes)el.append(node('p',`${change.target}: ${change.scopes_created?'create the selected scope and ':''}add ${change.added_count} blacklist entries. Existing private lists are withheld.`));}
  else el.append(node('p',`Unmount marker: ${plan.changes[0].enabled_before?'enabled':'disabled'} → ${plan.changes[0].enabled_after?'enabled':'disabled'}.`));
  $('stack-plan-card').hidden=false;$('stack-apply-confirm').checked=false;sync();
}
function renderStackOutcome(response) {
  const data=response.data,el=clear('stack-operation-result');
  const id=typeof data.id==='string' && /^[a-f0-9]{32}$/.test(data.id)?data.id:null;
  if(id)$('stack-operation-id').value=id;
  const stateText=stackStates.includes(data.state)?data.state:'not established';
  el.append(node('p',`Stack operation state: ${stateText}. Persisted file readback ${data.readback_verified===true?'verified':'not established'}. Private backup ${data.private_backup==='verified'?'verified':'not established'}.`),node('p','Runtime adoption: unknown. Wallet acceptance is not established by a file check. Reboot manually after Apply or rollback; the helper never reboots automatically.'));
}
function initPublicTrustCard() {
  const card=node('div',undefined,'card');card.id='public-trust-card';card.hidden=true;
  card.append(node('h3','Google public attestation evidence'),node('p','An explicit refresh downloads Google public attestation roots and status feeds over HTTPS GET. No keybox, private key, certificate or certificate serial is uploaded. Root matching and feed flags do not establish Wallet acceptance.'));
  const status=node('button','Inspect cached public evidence');status.type='button';status.dataset.action='trust-status';
  const refresh=node('button','Fetch Google public feeds (GET)');refresh.type='button';refresh.dataset.action='trust-refresh';
  const result=node('div');result.id='public-trust-result';card.append(status,refresh,result);
  $('watch-result').closest('.card').before(card);
}
function renderPublicTrust(data) {
  if(!data || typeof data.available!=='boolean'){$('public-trust-card').hidden=true;return;}
  $('public-trust-card').hidden=false;
  const el=clear('public-trust-result'),dl=node('dl');
  for(const [label,value] of [['Cache state',data.state],['Public evidence available',data.available],['Checked',data.checked_at],['Expires',data.expires_at]])dl.append(node('dt',label),node('dd',value));
  el.append(dl);
  for(const key of list(data.keys)) {
    if(!Number.isSafeInteger(key.keybox_index) || key.keybox_index<0 || !Number.isSafeInteger(key.key_index) || key.key_index<0 || !['ecdsa','rsa'].includes(key.algorithm))continue;
    const rootMatch=key.google_root_key===true?'matches':key.google_root_key===false?'does not match':'unknown';
    const revocation=['listed-revoked','listed-suspended','not-listed-as-of-feed','unknown'].includes(key.revocation)?key.revocation:'unknown';
    el.append(node('p',`Keybox ${key.keybox_index+1} · Key ${key.key_index+1} · ${key.algorithm.toUpperCase()} · Google root public key ${rootMatch} · Public status ${revocation}.`));
  }
  items(el,data.limitations);
  if(typeof data.next_step==='string')el.append(node('p',data.next_step));
}
function renderSelections() {
  $('selection-card').hidden=false;
  const inputs=clear('input-list'), choices=clear('selection-list');
  for(const input of state.inputs)inputs.append(node('p',`Staged ${input.id}: structural validity ${input.summary.structural_valid===true?'passed':'unknown'}, cryptographic consistency ${input.summary.cryptographic_consistent===true?'passed':'unknown'}. Trust ${text(input.summary.trust,'unknown')}; revocation ${text(input.summary.revocation,'unknown')}.`));
  for(const algorithm of ['ecdsa','rsa']) {
    const field=node('fieldset'); field.append(node('legend',algorithm.toUpperCase()));
    const none=node('label',undefined,'choice'), radio=node('input'); radio.type='radio';radio.name=`key-${algorithm}`;radio.value='';radio.checked=true;
    none.append(radio,node('span','Omit this algorithm from a new merged keybox (target/patch-only plans preserve the whole existing keybox)')); field.append(none);
    let count=0;
    for(const input of state.inputs) for(const box of list(input.summary.keyboxes)) for(const key of list(box.keys)) {
      if(String(key.algorithm).toLowerCase()!==algorithm)continue;
      const label=node('label',undefined,'choice'), option=node('input');option.type='radio';option.name=`key-${algorithm}`;
      try { option.value=selectionValue(input.id,box.index,key.index,algorithm); } catch { continue; }
      const description=node('span',`${input.id} · Keybox ${box.index+1} · Key ${key.index+1} · ${text(key.parameter)} · ${text(key.certificate_count)} certificates · PEM ${text(key.private_key_format)} · Valid until ${text(key.valid_until)}.`);
      items(description,key.warnings); label.append(option,description);field.append(label);count++;
    }
    if(!count)field.append(node('p','No validated entry for this algorithm.'));
    choices.append(field);
  }
  $('step-review').classList.toggle('active',state.inputs.length>0);$('step-import').classList.toggle('active',state.inputs.length===0);sync();
}
function renderPlan(response) {
  const d=response.data;
  state.plan=null;
  if(typeof d.id!=='string' || !/^[A-Za-z0-9_-]{1,96}$/.test(d.id))throw new Error('Backend did not return a usable plan ID. Apply is blocked.');
  const previews=list(d.preview),changed=list(d.changes);
  if(!changed.length || changed.some(name=>!['keybox.xml','target.txt','security_patch.txt'].includes(name) || !previews.some(p=>p.file===name)))throw new Error('Plan lacks a complete redacted change preview. Apply is blocked; reinstall matching UI/backend.');
  const compaction=d.target_compaction!==undefined || $('compact-targets').checked?targetCompactionCounts(d.target_compaction):null;
  if(compaction?.removed_entries>0 && !changed.includes('target.txt'))throw new Error('Target compaction review has no target.txt change. Apply is blocked.');
  state.plan=d.id;
  const outputKeys=list(d.summary?.keyboxes).flatMap(box=>list(box.keys));
  const algorithms=Array.isArray(d.algorithms)?d.algorithms.join(', '):(d.algorithms || outputKeys.map(key=>text(key.algorithm)).join(', '));
  pairs('plan-summary',[['Plan',d.id],['Created',response.time],['Selected algorithms',algorithms || 'Only explicitly selected entries enter a merged keybox'],['Output metadata',d.device_id_policy || (typeof d.metadata==='string'?d.metadata:d.metadata?.device_id_policy) || 'Source identity is not recreated'],['Adoption procedure',typeof d.adoption==='string'?d.adoption:'Evidence collection; no automatic reboot'],['Recovery policy',d.recovery_policy || 'Restore the previous snapshot if a configuration write fails']]);
  const changes=clear('plan-changes');changes.append(node('h4','Configuration changes'));
  if(compaction)changes.append(node('p',`Target compaction: ${compaction.entries_before} entries → ${compaction.entries_after}; ${compaction.removed_entries} repeated entries removed. Reviewed input contains ${compaction.packages_before} packages. These counts describe compaction before any separately selected required-target repair. Review the final target.txt changes below.`));
  for(const change of list(d.changes)) {
    if(typeof change==='string') {const old=d.active?.[change], intended=d.intended?.[change];changes.append(node('p',`${change}: ${old?.exists?'replace existing file':'create previously absent file'}`));if(old?.sha256)changes.append(node('p','Before SHA-256: '+old.sha256));if(intended?.sha256)changes.append(node('p','After SHA-256: '+intended.sha256));}
    else if(change && typeof change==='object')changes.append(node('p',`${text(change.file || change.path || change.target)}: ${text(change.summary || change.action || change.description)}${change.before_hash?' · Before SHA-256 '+text(change.before_hash):''}${change.after_hash?' · After SHA-256 '+text(change.after_hash):''}`));
  }
  if(!list(d.changes).length)changes.append(node('p','No changes were reported. Inspect the CLI plan before applying.'));
  for(const key of outputKeys){changes.append(node('p',`Output ${text(key.algorithm).toUpperCase()}: ${text(key.parameter)} · ${text(key.certificate_count)} certificates · PEM ${text(key.private_key_format)} · Valid until ${text(key.valid_until)}.`));items(changes,key.warnings);}
  for(const preview of previews) {
    if(!['keybox.xml','target.txt','security_patch.txt'].includes(preview.file))continue;
    const detail=node('details');detail.append(node('summary',`${preview.file}: exact redacted changes and metadata`));
    detail.append(node('p',`Original file ${preview.old_exists?'present':'absent'}. Before SHA-256: ${text(preview.old_sha256,'Absent')}. After SHA-256: ${text(preview.new_sha256)}.`));
    const metadata=preview.metadata || {};detail.append(node('p',`Owner ${text(metadata.uid)}:${text(metadata.gid)} · Mode ${Number.isInteger(metadata.mode)?metadata.mode.toString(8):'unknown'} · SELinux ${text(metadata.selinux)}.`));
    if(preview.added_lines){detail.append(node('h4','Added lines'));items(detail,preview.added_lines);}
    if(preview.removed_lines){detail.append(node('h4','Removed lines'));items(detail,preview.removed_lines);}
    changes.append(detail);
  }
  items(changes,d.summary?.warnings);
  const warnings=clear('plan-warnings');items(warnings,d.warnings);items(warnings,d.required_capabilities);if(d.required_capabilities && !Array.isArray(d.required_capabilities))for(const [name,value] of Object.entries(d.required_capabilities))warnings.append(node('p',`${name}: ${text(value)}`));
  $('plan-card').hidden=false;$('selection-card').hidden=true;$('import-input').hidden=true;$('apply-confirm').checked=false;
  $('step-apply').classList.add('active');sync();$('plan-card').scrollIntoView({block:'start'});
}
function renderBackups(response) {
  const d=response.data;state.backups=list(Array.isArray(d)?d:d.backups);
  const select=$('backup-choice');select.replaceChildren();
  for(const [id,label] of [['previous','Previous configuration'],['last-verified','Last configuration with recorded verification']]) {const option=node('option',label);option.value=id;select.append(option);}
  const container=clear('backup-list');
  for(const backup of state.backups) {
    if(!backup || typeof backup.id!=='string' || !/^[A-Za-z0-9_-]{1,96}$/.test(backup.id))continue;
    const option=node('option',`${text(backup.time || backup.created_at)} · ${text(backup.type || backup.operation)} · ${backup.verified?'Verification recorded':'No recorded verification'} · ${backup.id}${backup.integrity==='failed'?' · Corrupt/unavailable; restore blocked':''}`);option.value=backup.id;option.disabled=backup.integrity==='failed';select.append(option);
    const article=node('article',undefined,'card');article.append(node('h3',backup.id),node('p',option.textContent));items(article,backup.changes);if(backup.changes && !Array.isArray(backup.changes))for(const name of ['keybox.xml','security_patch.txt','target.txt']){const file=backup.changes[name];if(file)article.append(node('p',`${name}: ${file.exists?'present · SHA-256 '+text(file.sha256):'originally absent'}`));}items(article,backup.warnings);container.append(article);
  }
  if(!container.childElementCount)container.append(node('p','No named backups returned. The backend checks symbolic rollback availability before writing.'));
  $('rollback-confirm').checked=false;sync();
}
const actions={
  async status(){renderStatus(await request('status'));},
  async diagnose(){const r=await request('diagnose',{},'Collecting targeted diagnostics…');renderStatus(r);renderDiagnosticContext(r.data);findings('diagnostic-findings',r.data.findings);state.diagnosticBinding=evidenceBinding(r.data);$('diagnostics-time').textContent='Collected '+text(r.time)+'; recheck after relevant changes.';show('diagnostics');},
  async ingest(){await ingestPath($('input-path').value.trim());},
  async 'ingest-active'(){await ingestPath('/data/adb/tricky_store/keybox.xml',true);},
  async plan(){const selections=Array.from(document.querySelectorAll('#selection-list input:checked')).map(el=>el.value).filter(Boolean).join(',');const targets=$('repair-targets').checked?'true':'false';const compact=$('compact-targets').checked;const patch=$('patch').value.trim();if(patch && !/^\d{4}-\d{2}-\d{2}$/.test(patch))throw new Error('Patch must be YYYY-MM-DD or empty.');if(!selections && targets==='false' && !compact && !patch)throw new Error('Select validated key material, target compaction or an evidence-supported target/patch repair.');const args={selections,targets,patch};if(compact)args['compact-targets']='true';renderPlan(await request('plan',args,'Building a plan bound to current input and configuration hashes…'));},
  async apply(){
    if(!state.plan || !$('apply-confirm').checked)throw new Error('Review and confirm the plan first.');
    const id=state.plan;state.plan=null;$('apply-confirm').checked=false;invalidateVerification('A new Apply was submitted.');state.evidenceBinding=null;sync();
    const r=await request('apply',{id},'Backing up and committing. Let the backend finish safe recovery if needed…');
    $('plan-card').hidden=true;$('verify-card').hidden=false;$('step-verify').classList.add('active');
    // Read a fresh current-user/configuration binding before any personal checks.
    let statusWarning;
    try{renderStatus(await request('status',{},'Collecting current configuration and Android user after Apply…'));}
    catch(error){statusWarning='Apply completed, but fresh status could not be collected. '+text(error.message);notice(statusWarning,true);}
    $('apply-result').textContent=text(r.data.message || r.message);describeOutcome('verification-result',r);state.verificationSeen=true;state.verificationBinding=evidenceBinding(r.data) || state.evidenceBinding;
    if(statusWarning)$('verification-result').append(node('p',statusWarning));
    $('import-input').hidden=false;renderSelections();
  },
  async verify(){
    const hadChecks=$('wallet-ready').checked || $('tap-confirmed').checked;
    if(hadChecks) {
      const binding=state.evidenceBinding;
      renderStatus(await request('status',{},'Rechecking the configuration and Android user reviewed by your personal checks…'));
      if(!binding || !state.evidenceBinding || binding!==state.evidenceBinding || (!$('wallet-ready').checked && !$('tap-confirmed').checked))throw new Error('Current configuration/user evidence changed or was unavailable. Repeat your personal checks before recording them.');
    }
    const args={'wallet-ready':$('wallet-ready').checked?'true':'false','tap-confirmed':$('tap-confirmed').checked?'true':'false'};
    if(hadChecks)args['reviewed-user']=state.currentUser;
    const r=await request('verify',args,'Checking files, engine health, and fresh adoption evidence…');
    if(hadChecks && evidenceBinding(r.data)!==state.evidenceBinding)throw new Error('Verification returned a different or unavailable configuration/user binding. Repeat personal checks against fresh status.');
    recordVerification(r);$('verify-card').hidden=false;show('import');
  },
  'back-review'(){state.plan=null;$('plan-card').hidden=true;$('selection-card').hidden=false;$('import-input').hidden=false;$('apply-confirm').checked=false;sync();},
  'cancel-import'(){state.plan=null;state.inputs=[];state.apiStage=null;$('api-stage-result').textContent='API review cancelled. Private staged files are retained; a new explicit import is required.';$('plan-card').hidden=true;$('import-input').hidden=false;$('apply-confirm').checked=false;$('repair-targets').checked=false;$('compact-targets').checked=false;$('patch').value='';invalidateVerification('The review was cancelled.');renderSelections();notice('Review cancelled. Private staged files are retained; active configuration unchanged.');sync();},
  async backups(){renderBackups(await request('backups'));},
  async rollback(){if(!$('rollback-confirm').checked)throw new Error('Confirm the selected rollback first.');$('rollback-confirm').checked=false;invalidateVerification('A rollback was submitted.');state.evidenceBinding=null;const r=await request('rollback',{id:$('backup-choice').value},'Backing up the current set and restoring the selected configuration…');describeOutcome('backup-preview',r);},
  async api(){renderAPI((await request('api',{action:'status'},'Reading redacted API status; no feed is fetched…')).data);},
  async 'api-config'(){const path=privateAPIConfigPath($('api-config-path').value.trim());discardAPIReview('The source is being reconfigured. Previous API inputs were removed from this review; private staged files are retained.',true);renderAPI((await request('api',{action:'config',path},'Saving the private-file configuration; no feed is fetched…')).data);},
  async 'api-import'(){if(!state.apiReady || state.resetPending || state.recovery)throw new Error('Inspect a ready source and complete pending recovery before importing.');discardAPIReview('Fetching one staged input. Any previous plan was discarded; active configuration is unchanged.');const r=await request('api',{action:'import'},'Fetching the configured HTTPS raw-XML feed once into private staging…');if(typeof r.data.id!=='string' || !/^[a-f0-9]{32}$/.test(r.data.id))throw new Error('API import returned no usable staged input ID. Validation and Apply are blocked.');state.apiStage=r.data.id;$('api-stage-result').textContent=`Staged ${r.data.id}${Number.isSafeInteger(r.data.bytes)?' · '+r.data.bytes+' bytes':''}. Not yet validated or selected. Use Validate to open the existing review flow.`;sync();},
  async 'api-validate'(){if(!state.apiStage || state.resetPending || state.recovery)throw new Error('Import a staged API input after pending recovery is complete.');const id=state.apiStage,generation=state.apiGeneration;renderStatus(await request('status',{},'Rechecking source generation and pending recovery before API validation…'));if(state.apiStage!==id || state.apiGeneration!==generation || !state.apiReady || state.resetPending || state.recovery)throw new Error('The API source or recovery state changed. Inspect status and explicitly import again; validation was not submitted.');await validateStage(id,'api');state.apiStage=null;$('api-stage-result').textContent='API input validated and listed for deliberate selection. No algorithm was selected and no plan or active change was made.';show('import');sync();},
  async 'stack-status'(){renderStatus(await request('status',{},'Collecting current user, configuration and stack evidence…'));renderStackStatus((await request('stack',{action:'status'},'Inspecting redacted stack capabilities and operation…')).data);},
  'stack-candidates'(){const packages=stackPackageList($('stack-package-input').value),existing=Array.from(document.querySelectorAll('[name="stack-package"]')).map(input=>input.value);if(new Set([...existing,...packages]).size>32)throw new Error('Offer at most 32 package choices in one review. Cancel to start a different list.');for(const name of packages){if(existing.includes(name))continue;const label=node('label',undefined,'check'),input=node('input');input.type='checkbox';input.name='stack-package';input.value=name;label.append(input,node('span',name));$('stack-package-choices').append(label);}discardStackPlan('Package choices changed. Select the desired packages explicitly, then build a new plan.');sync();},
  async 'stack-plan'(){discardStackPlan();const profile=$('stack-profile').value,choices={profile};let args={action:'plan',profile};if(profile==='hma-scope'){choices.targets=Array.from(document.querySelectorAll('[name="stack-target"]:checked')).map(input=>input.value);choices.packages=Array.from(document.querySelectorAll('[name="stack-package"]:checked')).map(input=>input.value);if(!choices.targets.length || !choices.packages.length)throw new Error('Choose at least one target and one package checkbox explicitly.');args.targets=choices.targets.join(',');args['hide-packages']=choices.packages.join(',');}else if(profile==='brezygisk-unmount'){choices.enabled=document.querySelector('[name="stack-enabled"]:checked')?.value;if(!['true','false'].includes(choices.enabled))throw new Error('Choose the intended unmount marker value explicitly.');args.enabled=choices.enabled;}else throw new Error('Choose a supported stack profile explicitly.');renderStatus(await request('status',{},'Rechecking current configuration and numeric Android user before stack planning…'));renderStackStatus((await request('stack',{action:'status'})).data);if(!state.evidenceBinding || state.resetPending || state.recovery || state.stackPending || !state.stack?.profiles.find(item=>item.id===profile)?.available || choices.targets?.some(target=>!state.stack.allowed_targets.includes(target)))throw new Error('Fresh stack capability, user or recovery evidence does not allow this plan.');renderStackPlan((await request('stack',args,'Building only the explicitly selected stack profile plan…')).data,choices);},
  async 'stack-apply'(){const plan=state.stackPlan;if(!plan || !$('stack-apply-confirm').checked)throw new Error('Review and confirm the stack plan first.');renderStatus(await request('status',{},'Rechecking configuration, stack evidence and numeric Android user before Apply…'));renderStackStatus((await request('stack',{action:'status'})).data);if(state.stackPlan!==plan || state.stackPlanBinding!==state.evidenceBinding || state.resetPending || state.recovery || state.stackPending)throw new Error('Stack review is stale or recovery is pending. Build a fresh plan; Apply was not submitted.');discardStackPlan();invalidateStackEvidence('A separately confirmed stack Apply was submitted.');renderStackOutcome(await request('stack',{action:'apply',id:plan.id},'Creating the private full backup and committing the reviewed stack change…'));renderStatus(await request('status',{},'Collecting status after the stack file change…'));renderStackStatus((await request('stack',{action:'status'})).data);},
  async 'stack-verify'(){const id=$('stack-operation-id').value;if(!/^[a-f0-9]{32}$/.test(id))throw new Error('Use the reviewed 32-character stack operation ID.');renderStackStatus((await request('stack',{action:'status'})).data);if(state.stack?.operation?.id!==id || !state.stack.operation.can_verify)throw new Error('Inspect an operation with available file verification first.');renderStackOutcome(await request('stack',{action:'verify',id},'Verifying persisted stack bytes and metadata; runtime adoption remains unknown…'));},
  async 'stack-rollback'(){const id=$('stack-operation-id').value,binding=state.stackRollbackBinding;if(!/^[a-f0-9]{32}$/.test(id) || !$('stack-rollback-confirm').checked || !binding)throw new Error('Inspect the matching operation and confirm private-backup restoration first.');renderStatus(await request('status',{},'Checking pending reset and stack recovery state…'));renderStackStatus((await request('stack',{action:'status'})).data);if(binding!==state.evidenceBinding || !$('stack-rollback-confirm').checked || state.resetPending || state.recovery || state.stack?.operation?.id!==id || !state.stack.operation.can_rollback)throw new Error('The matching private stack backup is unavailable, review is stale or another recovery is pending.');$('stack-rollback-confirm').checked=false;state.stackRollbackBinding=null;discardStackPlan();invalidateStackEvidence('A separately confirmed stack rollback was submitted.');renderStackOutcome(await request('stack',{action:'rollback',id},'Restoring the matching verified private stack backup…'));renderStatus(await request('status',{},'Collecting status after stack backup restoration…'));renderStackStatus((await request('stack',{action:'status'})).data);},
  'stack-cancel'(){discardStackPlan();$('stack-rollback-confirm').checked=false;state.stackRollbackBinding=null;$('stack-profile').value='';$('stack-package-input').value='';clear('stack-package-choices');for(const input of document.querySelectorAll('[name="stack-target"],[name="stack-enabled"]'))input.checked=false;$('stack-operation-result').textContent='Stack review cancelled. Private staged plans are retained; active stack configuration is unchanged.';sync();},
  async 'trust-status'(){renderPublicTrust((await request('trust',{action:'status'},'Reading cached redacted public attestation evidence…')).data);},
  async 'trust-refresh'(){renderPublicTrust((await request('trust',{action:'refresh'},'Fetching full Google public roots and status feeds over HTTPS GET; no private material is uploaded…')).data);},
  async watch(){const days=$('watch-days').value;if(!/^\d{1,3}$/.test(days)||Number(days)<1||Number(days)>365)throw new Error('Use 1–365 days.');const r=await request('watch',{days});const el=clear('watch-result');const alignment=r.data.patch_aligned===true?'aligned':r.data.patch_aligned===false?'mismatch':text(r.data.patch_aligned,'unknown');el.append(node('p',`Estimated expiry ${text(r.data.estimate)} · ${text(r.data.days_remaining)} days remaining · Fingerprint estimate: ${text(r.data.fingerprint_estimate_state)} · Patch alignment ${alignment}.`));items(el,r.data.warnings);},
  async 'recovery-status'(){const r=await request('recovery',{action:'status'});state.recovery=needsRecovery(r.data);state.lockPresent=r.data.lock_present===true;describeOutcome('recovery-result',r);sync();},
  async 'recovery-restore'(){if(!state.recovery||!$('recovery-confirm').checked)throw new Error('Inspect the journal and confirm restoration first.');$('recovery-confirm').checked=false;invalidateVerification('Recovery restoration was submitted.');state.evidenceBinding=null;const r=await request('recovery',{action:'restore'},'Restoring the interrupted transaction’s previous configuration…');describeOutcome('recovery-result',r);state.recovery=false;sync();},
  async 'recovery-release'(){if(!state.lockPresent)throw new Error('Inspect the recovery lock first.');const r=await request('recovery',{action:'release-lock'},'Checking that the lock-owning process ended before release…');describeOutcome('recovery-result',r);state.lockPresent=false;sync();},
  async 'reset-status'(){describeOutcome('reset-result',await request('reset',{action:'status'}));},
  async 'reset-preview'(){state.reset=null;$('reset-phrase').value='';const r=await request('reset',{action:'preview'});const el=clear('reset-preview');el.append(node('p',r.message),node('p',`Reviewed numeric Android user: ${text(r.data.user)}. All clears are bound to this user; a profile change blocks continuation.`));items(el,r.data.steps);items(el,r.data.consequences);if(typeof r.data.review_hash!=='string'||!r.data.review_hash)throw new Error('Reviewed reset hash unavailable. Reset is blocked.');state.reset=r.data.review_hash;$('reset-confirm-fields').hidden=false;sync();},
  async 'reset-confirm'(){if(!state.reset||$('reset-phrase').value!=='CLEAR WALLET AND GOOGLE SERVICES')throw new Error('Review the reset sequence and type the full confirmation phrase.');const review_hash=state.reset;state.reset=null;$('reset-phrase').value='';$('reset-confirm-fields').hidden=true;invalidateVerification('A separately confirmed app-data reset was submitted.');describeOutcome('reset-result',await request('reset',{action:'confirm',confirmation:'CLEAR WALLET AND GOOGLE SERVICES',review_hash},'Executing only the separately confirmed, reviewed app-data steps…'));},
  async 'reset-resume'(){describeOutcome('reset-result',await request('reset',{action:'resume'},'Checking the one-shot reset journal; PIF execution remains a manual action…'));},
  async 'reset-complete'(){if($('reset-complete-phrase').value!=='PIF ACTION AND GMS FORCE-STOP COMPLETED')throw new Error('Confirm the successful manual post-reboot commands first.');$('reset-complete-phrase').value='';invalidateVerification('Manual PIF/GMS completion was recorded.');describeOutcome('reset-result',await request('reset',{action:'complete',confirmation:'PIF ACTION AND GMS FORCE-STOP COMPLETED'},'Recording your separately confirmed manual completion…'));}
};
function needsRecovery(data) {return !!(data && (data.pending || data.required || data.interrupted || (typeof data.state==='string' && !['none','committed','restored'].includes(data.state))));}
async function ingestPath(path, active=false) {
    if(!active && (!/^\/(?:data\/adb\/wallet_diagnostic\/inbox|sdcard\/keybox_inbox)\/[A-Za-z0-9._ /-]+\.xml$/.test(path) || path.includes('..') || path.length>1024))throw new Error('Use an absolute XML path inside the private inbox or optional shared inbox. Use a simple filename.');
    const ingested=await request('ingest',{path},'Copying the input into private staging…');
    const id=ingested.data.id;
    if(typeof id!=='string' || !/^[A-Za-z0-9_-]{1,96}$/.test(id))throw new Error('Backend did not return a staged input ID.');
    await validateStage(id);
}
async function validateStage(id,source='local') {
    const validated=await request('validate',{id},'Validating XML, private key, and complete certificate chain…',source==='api');
    const summary=validated.data.summary || validated.data;
    if(summary.structural_valid!==true || summary.cryptographic_consistent!==true)throw new Error('Mandatory validation did not pass. Apply remains blocked for this input.');
    state.inputs=state.inputs.filter(input=>input.id!==id);state.inputs.push({id,summary,source});state.plan=null;$('apply-confirm').checked=false;$('plan-card').hidden=true;$('selection-card').hidden=false;$('import-input').hidden=false;renderSelections();
}
document.addEventListener('click',async event=>{
  const button=event.target.closest('button');if(!button || button.disabled)return;
  if(button.dataset.view){show(button.dataset.view);return;}
  const action=actions[button.dataset.action];if(!action)return;
  try{await action();}catch(error){const failure=error.response?`${error.response.code}: ${error.response.message}`:error.message;notice(failure,true);if(button.dataset.action==='verify')invalidateVerification('The latest Verify did not establish current evidence.');if(error.response?.data?.findings)findings('diagnostic-findings',error.response.data.findings);if(button.dataset.action?.startsWith('reset-') && error.response)describeOutcome('reset-result',error.response);if(button.dataset.action?.startsWith('trust-') && error.response)renderPublicTrust(error.response.data);if(button.dataset.action==='apply' && error.response){$('plan-card').hidden=true;$('verify-card').hidden=false;describeOutcome('verification-result',error.response);}if(['stack-apply','stack-rollback'].includes(button.dataset.action)){try{renderStatus(await request('status',{},'Inspecting recovery state after the stopped stack operation…'));renderStackStatus((await request('stack',{action:'status'})).data);}catch{state.stackPending=true;state.applyAvailable=false;discardStackPlan('Fresh stack state is unavailable. Inspect recovery before another write.');}notice(failure,true);}sync();}
});
for(const id of confirmations)$ (id).addEventListener('change',sync);
$('stack-apply-confirm').addEventListener('change',sync);
$('stack-rollback-confirm').addEventListener('change',()=>{state.stackRollbackBinding=$('stack-rollback-confirm').checked?state.evidenceBinding:null;sync();});
$('stack-operation-id').addEventListener('input',()=>{$('stack-rollback-confirm').checked=false;state.stackRollbackBinding=null;sync();});
$('stack-profile').addEventListener('change',()=>{discardStackPlan('The selected stack profile changed. Build a fresh review.');sync();});
document.addEventListener('change',event=>{if(['stack-target','stack-package','stack-enabled'].includes(event.target.name)){discardStackPlan('Stack selections changed. Build a fresh review.');sync();}});
$('reset-phrase').addEventListener('input',sync);
$('reset-complete-phrase').addEventListener('input',sync);
$('backup-choice').addEventListener('change',()=>{$('rollback-confirm').checked=false;sync();});
window.addEventListener('beforeunload',event=>{if(state.busy){event.preventDefault();event.returnValue='An operation is still running. Inspect recovery if interrupted.';}});
initPublicTrustCard();state.bridge=typeof window.ksu?.exec==='function';renderSelections();sync();
if(state.bridge)actions.status().catch(error=>notice(error.message,true));
else notice('WebUI root bridge unavailable. Open this module in KSU WebUI, or run /data/adb/modules/wallet_diagnostic/bin/walletdiag help through a root shell.',true);
