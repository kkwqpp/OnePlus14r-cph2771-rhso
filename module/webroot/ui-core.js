// Presentation helpers: no filesystem mutations, shell interpolation, or secret storage.
const commands = new Set(['status','diagnose','ingest','validate','plan','apply','verify','backups','rollback','api','watch','recovery','reset','trust','stack']);
export function encodeRequest(command, args = {}) {
  if (!commands.has(command)) throw new Error('Unsupported command.');
  if (!args || Array.isArray(args) || typeof args !== 'object') throw new Error('Invalid arguments.');
  if(command==='api') {
    if(!['status','config','import'].includes(args.action) || Object.keys(args).some(name=>!['action','path'].includes(name)) || (args.action!=='config' && args.path!==undefined))throw new Error('API requests accept only an action and a private configuration filepath.');
    if(args.action==='config')privateAPIConfigPath(args.path);
  }
  if(command==='stack') {
    const fields=args.action==='plan'?['action','profile','targets','hide-packages','enabled']:['action',...(['apply','verify','rollback'].includes(args.action)?['id']:[])];
    if(!['status','plan','apply','verify','rollback'].includes(args.action) || Object.keys(args).some(name=>!fields.includes(name)))throw new Error('Unsupported stack request fields.');
    if(['apply','verify','rollback'].includes(args.action) && !/^[a-f0-9]{32}$/.test(args.id))throw new Error('Use a reviewed stack operation ID.');
    if(args.action==='plan') {
      if(args.profile==='hma-scope'){if(args.enabled!==undefined || stackPackageList(args.targets).some(target=>!stackTargets.includes(target)))throw new Error('Choose only supported explicit stack targets.');stackPackageList(args['hide-packages']);}
      else if(args.profile==='brezygisk-unmount'){if(!['true','false'].includes(args.enabled) || args.targets!==undefined || args['hide-packages']!==undefined)throw new Error('Choose only an explicit marker value for this profile.');}
      else throw new Error('Choose a supported stack profile.');
    }
  }
  for (const [name, value] of Object.entries(args)) {
    if (!/^[a-z_-]{1,40}$/.test(name) || typeof value !== 'string' || value.length > 4096) throw new Error('Invalid argument.');
  }
  const bytes = new TextEncoder().encode(JSON.stringify({command, args}));
  if (bytes.length > 16384) throw new Error('Request is too large.');
  const payload=btoa(Array.from(bytes, b => String.fromCharCode(b)).join('')).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  if(payload.length>16384)throw new Error('Encoded request is too large.');
  return payload;
}
export function readResult(stdout) {
  if (typeof stdout !== 'string' || stdout.length > 1048576) throw new Error('Backend response is missing or too large.');
  let result;
  try { result = JSON.parse(stdout); } catch { throw new Error('Backend returned an invalid response. Use the CLI status/recovery commands.'); }
  if (!result || result.schema !== 1 || typeof result.ok !== 'boolean' || typeof result.code !== 'string' || typeof result.message !== 'string') throw new Error('Backend schema is unsupported. Reinstall matching UI and backend versions.');
  return {schema:1,ok:result.ok,code:safeText(result.code),message:safeText(result.message),time:safeText(result.time),data:result.data && typeof result.data === 'object' ? result.data : {}};
}
export function safeText(value, fallback = 'Not established') {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') return fallback;
  const text = String(value);
  if (/-----BEGIN|-----END|(?:authorization|api[_ -]?token|private[_ -]?key)\s*[:=]/i.test(text) || /[A-Za-z0-9+/]{180,}={0,2}/.test(text)) return 'Sensitive content omitted; use a redacted backend report.';
  return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g,'').slice(0,1400);
}
export function list(value) { return Array.isArray(value) ? value.slice(0,100) : []; }
export function selectionValue(id, box, key, algorithm) {
  if (!/^[A-Za-z0-9_-]{1,96}$/.test(id) || !Number.isSafeInteger(box) || box < 0 || !Number.isSafeInteger(key) || key < 0 || !['ecdsa','rsa'].includes(algorithm)) throw new Error('Backend returned an unsupported selection.');
  return `${id}:${box}:${key}:${algorithm}`;
}
export function targetCompactionCounts(value) {
  const fields=['entries_before','entries_after','removed_entries','packages_before'];
  if(!value || typeof value!=='object' || Array.isArray(value) || fields.some(name=>!Number.isSafeInteger(value[name]) || value[name]<0) || value.entries_after>value.entries_before || value.removed_entries!==value.entries_before-value.entries_after || value.packages_before>value.entries_before)throw new Error('Target compaction review is missing or inconsistent. Apply is blocked.');
  return Object.fromEntries(fields.map(name=>[name,value[name]]));
}
export function privateAPIConfigPath(value) {
  if(typeof value!=='string' || !/^\/data\/adb\/wallet_diagnostic\/inbox\/[A-Za-z0-9_-][A-Za-z0-9._-]{0,95}\.json$/.test(value) || value.includes('..'))throw new Error('Use a JSON filename inside the root-private inbox. Never enter a URL or credential.');
  return value;
}
export function apiStatusView(value) {
  if(!value || value.api_status!=='generic-https-raw-xml' || value.supported_format!=='raw-xml')return null;
  const state=['unconfigured','configured','invalid'].includes(value.state)?value.state:'invalid';
  const generation=typeof value.source_generation==='string' && /^[a-f0-9]{32}$/.test(value.source_generation)?value.source_generation:null;
  const configured=value.configured===true && state==='configured' && generation!==null;
  return {api_status:'generic-https-raw-xml',supported_format:'raw-xml',state,configured,available:configured && value.available===true && value.exact_endpoint_available===false && value.provider_contract_verified===false,auth_configured:value.auth_configured===true,source_generation:generation,exact_endpoint_available:false,provider_contract_verified:false};
}
const apiErrors={E_API_UNAVAILABLE:'No configured generic raw-XML source is available. The exact supplied endpoint remains unverified.',E_API_CONFIG:'Private API configuration is invalid or unsupported. Review the private JSON file locally.',E_API_SSRF:'The configured source or resolved address is not allowed.',E_API_TLS:'HTTPS verification failed. No staged input was accepted.',E_API_DNS:'The configured source could not be resolved. No staged input was accepted.',E_API_HTTP:'The source did not return an accepted HTTPS response.',E_API_FORMAT:'The source response is not an accepted raw-XML input.',E_API_LIMIT:'The source request exceeded a supported time, size or rate limit.',E_API_STALE:'The saved source changed. Inspect status and repeat the explicit import.',E_RECOVERY:'An unfinished reset or transaction blocks this operation. Inspect its state; do not repeat app-data clears.',E_BUSY:'Another operation is running. Let it finish before retrying.',E_PATH:'The private configuration file path or ownership is not accepted.',E_IO:'A private file operation failed. Inspect the file locally.',E_VALIDATION:'Mandatory keybox validation did not pass.',E_INPUT:'The staged input is not accepted.',E_REQUEST:'API request arguments are unsupported.',E_CAPABILITY:'This backend cannot perform the requested API network operation.'};
export function redactedAPIResponse(response) {
  const status=apiStatusView(response.data),data=status || {};
  if(typeof response.data?.id==='string' && /^[a-f0-9]{32}$/.test(response.data.id))data.id=response.data.id;
  if(Number.isSafeInteger(response.data?.bytes) && response.data.bytes>=0 && response.data.bytes<=1048576)data.bytes=response.data.bytes;
  const code=response.ok?'OK':Object.hasOwn(apiErrors,response.code)?response.code:'E_API';
  const time=typeof response.time==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(response.time)?response.time:'';
  return {schema:1,ok:response.ok===true,code,message:response.ok?'API operation completed. Review the redacted result before the next action.':apiErrors[code] || 'API operation stopped. Inspect redacted status or use the CLI; provider details are withheld.',time,data};
}
export const stackTargets=['com.google.android.apps.walletnfcrel','com.google.android.gms','com.android.vending','com.google.android.gsf'];
export const stackProfiles={'hma-scope':'HMA explicit blacklist scope','brezygisk-unmount':'BreZygisk unmount marker'};
export const stackStates=['applying','writing','committed','restoring','restored','recovery-required','unreadable'];
const stackReasons={available:'Supported capability is available.',recovery_pending:'A pending operation must be recovered before another change.',unsupported_capability:'The installed component does not match a supported capability.',unsupported_configuration:'The existing configuration is unsupported; no change is available.',resource_unavailable:'The required private configuration resource is unavailable.'};
export function stackStatusView(value) {
  if(!value || !Array.isArray(value.profiles) || !Array.isArray(value.allowed_targets) || typeof value.unfinished!=='boolean' || value.manual_reboot_required!==true || value.runtime_adoption!=='unknown')return null;
  const profiles=value.profiles.filter(profile=>profile && Object.hasOwn(stackProfiles,profile.id)).map(profile=>({id:profile.id,available:profile.available===true && profile.reason_code==='available',reason:stackReasons[profile.reason_code] || 'Capability status is unsupported; no change is available.'}));
  if(new Set(profiles.map(profile=>profile.id)).size!==profiles.length)return null;
  const operation=value.operation && /^[a-f0-9]{32}$/.test(value.operation.id) && Object.hasOwn(stackProfiles,value.operation.profile)?{id:value.operation.id,profile:value.operation.profile,state:stackStates.includes(value.operation.state)?value.operation.state:'unknown',can_verify:value.operation.can_verify===true,can_rollback:value.operation.can_rollback===true,backup_available:value.operation.backup_available===true}:null;
  return {profiles,allowed_targets:stackTargets.filter(target=>value.allowed_targets.includes(target)),unfinished:value.unfinished,stack_pending:value.stack_pending===true,operation};
}
export function stackPackageList(value) {
  if(typeof value!=='string' || value.length>2048)throw new Error('Enter a bounded comma-separated package list.');
  const packages=value.split(',').map(item=>item.trim());
  if(!packages.length || packages.length>32 || packages.some(item=>!/^([A-Za-z][A-Za-z0-9_]*\.)+[A-Za-z][A-Za-z0-9_]*$/.test(item) || item.length>255))throw new Error('Enter dotted package identifiers only, separated by commas.');
  return [...new Set(packages)];
}
export function stackPlanView(value) {
  if(!value || !/^[a-f0-9]{32}$/.test(value.id) || !Object.hasOwn(stackProfiles,value.profile) || value.manual_reboot_required!==true || value.runtime_adoption!=='unknown' || value.private_backup!=='created-on-apply' || !Array.isArray(value.changes) || !value.changes.length || value.changes.length>4)throw new Error('Stack plan lacks a supported review and private backup policy. Apply is blocked.');
  const changes=value.changes.map(change=>{
    if(value.profile==='hma-scope' && stackTargets.includes(change?.target) && Number.isSafeInteger(change.added_count) && change.added_count>=0 && change.added_count<=32 && [0,1].includes(change.scopes_created))return {target:change.target,added_count:change.added_count,scopes_created:change.scopes_created};
    if(value.profile==='brezygisk-unmount' && typeof change?.enabled_before==='boolean' && typeof change.enabled_after==='boolean' && change.enabled_before!==change.enabled_after)return {enabled_before:change.enabled_before,enabled_after:change.enabled_after};
    throw new Error('Stack plan has unsupported change details. Apply is blocked.');
  });
  if(value.profile==='hma-scope' && (new Set(changes.map(change=>change.target)).size!==changes.length || !changes.some(change=>change.added_count>0)) || value.profile==='brezygisk-unmount' && changes.length!==1)throw new Error('Stack plan has duplicate, absent or ambiguous changes. Apply is blocked.');
  return {id:value.id,profile:value.profile,changes};
}
const stackErrors={E_RECOVERY:'A stack write needs recovery, or another reset/transaction is unfinished. Inspect status and restore only the matching private backup.',E_ROLLED_BACK:'The stack write stopped and its previous files were restored. Inspect status before another change.',E_STALE:'Current stack files, code or review evidence changed. Build a fresh plan.',E_CAPABILITY:'The installed stack component or current Android user is unsupported.',E_SELECTION:'The explicit stack selections are not accepted.',E_NO_CHANGES:'The selected stack profile has no supported changes to apply.',E_BUSY:'Another operation is running. Let it finish; never remove its live lock.',E_IO:'A stack file operation stopped. Inspect the journal and private backup.',E_REQUEST:'Stack request arguments are unsupported.',E_FORMAT:'The stored stack plan or journal is unsupported or corrupt.',E_BACKUP:'The private stack backup is unavailable or failed integrity checks. Preserve the recovery evidence.',E_NOT_FOUND:'The reviewed stack operation is unavailable.'};
export function redactedStackError(response) {
  const code=Object.hasOwn(stackErrors,response.code)?response.code:'E_STACK';
  return {schema:1,ok:false,code,message:stackErrors[code] || 'Stack operation stopped. Inspect redacted capabilities and recovery state; private details are withheld.',time:'',data:{}};
}

// Compare only redacted configuration and user fields, never raw XML or identities.
export function evidenceBinding(data) {
  if(!data || typeof data!=='object')return null;
  const config=data.active || data.configuration;
  const user=data.device?.current_android_user ?? data.current_android_user;
  if(!config || typeof user!=='string' || !/^(0|[1-9][0-9]{0,5})$/.test(user))return null;
  if(data.stack_evidence_binding!==undefined && (typeof data.stack_evidence_binding!=='string' || !/^[a-f0-9]{64}$/.test(data.stack_evidence_binding)))return null;
  const files=[];
  for(const name of ['keybox.xml','security_patch.txt','target.txt']) {
    const file=config[name];
    if(!file || typeof file.exists!=='boolean')return null;
    if(!file.exists){files.push([name,false]);continue;}
    const m=file.metadata;
    if(!/^[a-f0-9]{64}$/.test(file.sha256) || !Number.isSafeInteger(file.size) || file.size<0 || !m || !Number.isSafeInteger(m.uid) || !Number.isSafeInteger(m.gid) || !Number.isSafeInteger(m.mode) || m.uid<0 || m.gid<0 || m.mode<0 || m.mode>511 || (m.selinux!==undefined && typeof m.selinux!=='string'))return null;
    files.push([name,true,file.sha256,file.size,m.uid,m.gid,m.mode,m.selinux || '']);
  }
  return JSON.stringify(data.stack_evidence_binding===undefined?[user,files]:[user,files,data.stack_evidence_binding]);
}
