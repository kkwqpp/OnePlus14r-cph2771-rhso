// Presentation helpers: no filesystem mutations, shell interpolation, or secret storage.
const commands = new Set(['status','diagnose','ingest','validate','plan','apply','verify','backups','rollback','api','watch','recovery','reset','trust']);
export function encodeRequest(command, args = {}) {
  if (!commands.has(command)) throw new Error('Unsupported command.');
  if (!args || Array.isArray(args) || typeof args !== 'object') throw new Error('Invalid arguments.');
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

// Compare only redacted configuration and user fields, never raw XML or identities.
export function evidenceBinding(data) {
  if(!data || typeof data!=='object')return null;
  const config=data.active || data.configuration;
  const user=data.device?.current_android_user ?? data.current_android_user;
  if(!config || typeof user!=='string' || !/^(0|[1-9][0-9]{0,5})$/.test(user))return null;
  const files=[];
  for(const name of ['keybox.xml','security_patch.txt','target.txt']) {
    const file=config[name];
    if(!file || typeof file.exists!=='boolean')return null;
    if(!file.exists){files.push([name,false]);continue;}
    const m=file.metadata;
    if(!/^[a-f0-9]{64}$/.test(file.sha256) || !Number.isSafeInteger(file.size) || file.size<0 || !m || !Number.isSafeInteger(m.uid) || !Number.isSafeInteger(m.gid) || !Number.isSafeInteger(m.mode) || m.uid<0 || m.gid<0 || m.mode<0 || m.mode>511 || (m.selinux!==undefined && typeof m.selinux!=='string'))return null;
    files.push([name,true,file.sha256,file.size,m.uid,m.gid,m.mode,m.selinux || '']);
  }
  return JSON.stringify([user,files]);
}
