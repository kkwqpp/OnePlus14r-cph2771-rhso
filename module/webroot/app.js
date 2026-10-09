// Bootstrap only. State, validation, rendering and workflows are implemented in Rust.
try {
  const [{exec},{ready},{start_ui}]=await Promise.all([
    import('./ksu.js'),import('./ui-core.js'),import('./rhso_webui.js')
  ]);
  await ready;
  start_ui(exec);
} catch {
  document.getElementById('notice').textContent='The Rust interface could not start. Reinstall a matching module or use /data/adb/modules/wallet_diagnostic/bin/walletdiag help through a root shell.';
  for(const control of document.querySelectorAll('button,input,select'))control.disabled=true;
}
