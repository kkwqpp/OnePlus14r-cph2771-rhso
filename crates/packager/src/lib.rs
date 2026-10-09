//! Deterministic, allowlisted release assembly. No tool installation or networking.
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write},
    path::{Component, Path, PathBuf},
};
use zip::{CompressionMethod, DateTime, ZipWriter, write::SimpleFileOptions};

pub const REQUIRED: &[&str] = &[
    "module.prop",
    "customize.sh",
    "action.sh",
    "uninstall.sh",
    "skip_mount",
    "webroot/index.html",
    "webroot/app.js",
    "webroot/ui-core.js",
    "webroot/style.css",
    "webroot/ksu.js",
    "webroot/rhso_webui.js",
    "webroot/rhso_webui_bg.wasm",
    "licenses/NOTICE.txt",
    "licenses/WalletDiagnostic-MIT.txt",
    "licenses/KernelSU-SDK-Apache-2.0.txt",
    "licenses/Android-NDK-r30-NOTICE.txt",
    "licenses/LLVM-r30-NOTICE.txt",
    "licenses/Rust-THIRD-PARTY-NOTICES.txt",
    "licenses/Rust-STD-MIT-APACHE-2.0.txt",
];
const IGNORED: &[&str] = &[
    "bin/walletdiag",
    "webroot/rhso_webui_bytes.js",
    "webroot/rhso_webui.d.ts",
    "webroot/rhso_webui_bg.wasm.d.ts",
    "licenses/Go-BSD-3-Clause.txt",
];
const DIRS: &[&str] = &["bin", "webroot", "licenses"];
const MAX_ASSET: usize = 32 * 1024 * 1024;
const MAX_BACKEND: usize = 128 * 1024 * 1024;
const MAX_TOTAL: usize = 192 * 1024 * 1024;

pub type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Debug)]
pub struct Options {
    pub backend: PathBuf,
    pub output: PathBuf,
    pub module: PathBuf,
}
#[derive(Debug)]
pub struct Package {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub entries: usize,
}
pub fn usage() -> &'static str {
    "Usage: rhso-packager --backend PATH --output PATH [--module PATH]\nThe default module directory is ./module. No tools are downloaded or installed."
}
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Options> {
    let mut it = args.into_iter();
    let mut backend = None;
    let mut output = None;
    let mut module = None;
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--backend" => &mut backend,
            "--output" => &mut output,
            "--module" => &mut module,
            _ => return Err("Unsupported packaging argument; use --help.".into()),
        };
        if slot.is_some() {
            return Err("Duplicate packaging argument.".into());
        }
        let value = it
            .next()
            .filter(|v| !v.is_empty() && !v.starts_with("--"))
            .ok_or("Packaging argument needs a path.")?;
        *slot = Some(PathBuf::from(value));
    }
    Ok(Options {
        backend: backend.ok_or("--backend is required.")?,
        output: output.ok_or("--output is required.")?,
        module: module.unwrap_or_else(|| PathBuf::from("module")),
    })
}
fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(o..o.checked_add(2).ok_or("ELF offset overflow.")?)
            .ok_or("Truncated ELF field.")?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(o..o.checked_add(4).ok_or("ELF offset overflow.")?)
            .ok_or("Truncated ELF field.")?
            .try_into()
            .unwrap(),
    ))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(o..o.checked_add(8).ok_or("ELF offset overflow.")?)
            .ok_or("Truncated ELF field.")?
            .try_into()
            .unwrap(),
    ))
}
fn range(b: &[u8], offset: u64, length: u64) -> Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or("ELF segment range overflow.")?;
    let start = usize::try_from(offset).map_err(|_| "ELF segment is outside the file.")?;
    let end = usize::try_from(end).map_err(|_| "ELF segment is outside the file.")?;
    b.get(start..end)
        .ok_or("ELF segment is outside the file.".into())
}
/// Verify the executable, not merely its magic or machine field.
pub fn validate_elf(b: &[u8]) -> Result<()> {
    if b.len() < 64
        || b.get(..7) != Some(&[0x7f, b'E', b'L', b'F', 2, 1, 1])
        || u16_at(b, 16)? != 3
        || u16_at(b, 18)? != 183
        || u32_at(b, 20)? != 1
        || u16_at(b, 52)? != 64
    {
        return Err("Backend must be a 64-bit little-endian AArch64 ELF PIE executable.".into());
    }
    let entry = u64_at(b, 24)?;
    let phoff = u64_at(b, 32)?;
    let phsize = u16_at(b, 54)?;
    let phnum = u16_at(b, 56)?;
    if phsize != 56 || phnum == 0 || phnum > 2048 || phoff < 64 {
        return Err("Unsupported ELF program-header table.".into());
    }
    range(b, phoff, (phsize as u64) * (phnum as u64))?;
    let (mut loads, mut interpreters, mut dynamics, mut pie, mut executable_entry) =
        (0, 0, 0, false, false);
    for i in 0..phnum {
        let off = usize::try_from(phoff + (i as u64) * 56).map_err(|_| "ELF offset overflow.")?;
        let kind = u32_at(b, off)?;
        let flags = u32_at(b, off + 4)?;
        let offset = u64_at(b, off + 8)?;
        let addr = u64_at(b, off + 16)?;
        let filesz = u64_at(b, off + 32)?;
        let memsz = u64_at(b, off + 40)?;
        let align = u64_at(b, off + 48)?;
        match kind {
            0x6474e551 if flags & 1 != 0 => {
                return Err("Backend requests an executable GNU stack.".into());
            }
            1 => {
                loads += 1;
                range(b, offset, filesz)?;
                if filesz > memsz
                    || align < 16384
                    || !align.is_power_of_two()
                    || offset % align != addr % align
                    || addr.checked_add(memsz).is_none()
                {
                    return Err("Every ELF LOAD segment must have valid bounds and at least 16KiB alignment/congruence.".into());
                }
                if flags & 3 == 3 {
                    return Err("ELF LOAD segment is both writable and executable.".into());
                }
                if flags & 1 == 1 && entry >= addr && entry < addr + memsz {
                    executable_entry = true;
                }
            }
            3 => {
                interpreters += 1;
                if range(b, offset, filesz)? != b"/system/bin/linker64\0" {
                    return Err(
                        "Backend must use the Android /system/bin/linker64 interpreter.".into(),
                    );
                }
            }
            2 => {
                dynamics += 1;
                let dynamic = range(b, offset, filesz)?;
                if dynamic.is_empty() || dynamic.len() % 16 != 0 {
                    return Err("ELF dynamic table is malformed.".into());
                }
                let mut terminated = false;
                for d in dynamic.chunks_exact(16) {
                    let tag = u64_at(d, 0)?;
                    let value = u64_at(d, 8)?;
                    if tag == 0 {
                        terminated = true;
                        break;
                    }
                    if tag == 0x6ffffffb && value & 0x08000000 != 0 {
                        pie = true;
                    }
                }
                if !terminated {
                    return Err("ELF dynamic table is unterminated.".into());
                }
            }
            _ => {}
        }
    }
    if loads == 0 || interpreters != 1 || dynamics != 1 || !pie || entry == 0 || !executable_entry {
        return Err("Backend lacks a complete Android PIE executable layout.".into());
    }
    Ok(())
}
fn reparse(m: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        m.file_type().is_symlink()
    }
}
fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "Current directory unavailable.")?
            .join(path)
    };
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return Err("Path escapes its root.".into());
                }
            }
            _ => out.push(c.as_os_str()),
        }
    }
    Ok(out)
}
fn check_ancestors(path: &Path, leaf_may_be_missing: bool) -> Result<()> {
    for (i, p) in path.ancestors().enumerate() {
        if p.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(p) {
            Ok(m) => {
                if reparse(&m) || m.file_type().is_symlink() {
                    return Err("A source/output path contains a symlink or reparse point.".into());
                }
                if i > 0 && !m.is_dir() {
                    return Err("A path parent is not a directory.".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && leaf_may_be_missing => {}
            Err(_) => return Err("A source/output path cannot be inspected.".into()),
        }
    }
    Ok(())
}
fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path).map_err(|_| "Required file is unavailable.")?;
    if !before.is_file()
        || reparse(&before)
        || before.file_type().is_symlink()
        || before.len() > limit as u64
    {
        return Err("Required file is not an accepted bounded regular file.".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Required file cannot be opened safely.")?;
    let opened = file
        .metadata()
        .map_err(|_| "Required file metadata unavailable.")?;
    if !opened.is_file() || reparse(&opened) {
        return Err("Required file changed its type during collection.".into());
    }
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Required file read failed.")?;
    let after =
        fs::symlink_metadata(path).map_err(|_| "Required file disappeared during collection.")?;
    if data.len() > limit
        || reparse(&after)
        || !after.is_file()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || opened.len() != data.len() as u64
    {
        return Err("Required file changed during collection or exceeded its limit.".into());
    }
    Ok(data)
}
fn scan(root: &Path, dir: &Path, seen: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|_| "Module directory cannot be read.")? {
        let entry = entry.map_err(|_| "Module entry cannot be read.")?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "Module entry metadata unavailable.")?;
        if reparse(&metadata) || metadata.file_type().is_symlink() {
            return Err("Module contains a symlink or reparse point.".into());
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "Module entry escapes its directory.")?
            .to_str()
            .ok_or("Module filenames must be UTF-8.")?
            .replace('\\', "/");
        if metadata.is_dir() {
            if !DIRS.contains(&relative.as_str()) {
                return Err(
                    "Module contains an unapproved directory; no archive was generated.".into(),
                );
            }
            scan(root, &path, seen)?;
        } else if metadata.is_file() {
            if !REQUIRED.contains(&relative.as_str()) && !IGNORED.contains(&relative.as_str()) {
                return Err("Module contains an unapproved file; private or unknown input is never packaged.".into());
            }
            seen.push(relative);
            if seen.len() > 128 {
                return Err("Module has too many files.".into());
            }
        } else {
            return Err("Module contains a special file.".into());
        }
    }
    Ok(())
}
pub fn embedded_wasm(wasm: &[u8]) -> Result<Vec<u8>> {
    if wasm.len() < 8 || wasm[..8] != [0, 97, 115, 109, 1, 0, 0, 0] {
        return Err("WebUI WASM header/version is invalid.".into());
    }
    Ok(format!("// Generated from rhso_webui_bg.wasm; no application policy.\nexport const wasmBase64 = \"{}\";\n",STANDARD.encode(wasm)).into_bytes())
}
/// Build-only helper: update one explicitly named source byte asset for browser tests.
pub fn embed_file(input: &Path, output: &Path) -> Result<()> {
    let input = absolute(input)?;
    let output = absolute(output)?;
    if output.file_name().and_then(|s| s.to_str()) != Some("rhso_webui_bytes.js")
        || same_tree(&output, &input)
    {
        return Err("Embedded WASM output must be the distinct rhso_webui_bytes.js asset.".into());
    }
    check_ancestors(&input, false)?;
    check_ancestors(&output, true)?;
    let wasm = read_regular(&input, MAX_ASSET)?;
    let bytes = embedded_wasm(&wasm)?;
    let parent = output.parent().ok_or("Byte asset parent unavailable.")?;
    fs::create_dir_all(parent).map_err(|_| "Byte asset directory creation failed.")?;
    check_ancestors(parent, false)?;
    write_atomic(&output, &bytes)
}
pub fn collect(module: &Path, backend: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let module = absolute(module)?;
    let backend = absolute(backend)?;
    check_ancestors(&module, false)?;
    check_ancestors(&backend, false)?;
    if !fs::metadata(&module)
        .map_err(|_| "Module directory unavailable.")?
        .is_dir()
    {
        return Err("Module path is not a directory.".into());
    }
    let mut seen = Vec::new();
    scan(&module, &module, &mut seen)?;
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for name in REQUIRED {
        if !seen.iter().any(|s| s == name) {
            return Err(format!("Required module asset is missing: {name}"));
        }
        let bytes = read_regular(&module.join(name), MAX_ASSET)?;
        if bytes.is_empty() && *name != "skip_mount" {
            return Err("A required module asset is empty.".into());
        }
        total = total
            .checked_add(bytes.len())
            .ok_or("Asset size overflow.")?;
        if total > MAX_TOTAL {
            return Err("Module assets exceed the package limit.".into());
        }
        if name.ends_with(".sh") || *name == "module.prop" {
            if bytes.contains(&b'\r') {
                return Err("Android shell/property files must use LF line endings.".into());
            }
            std::str::from_utf8(&bytes).map_err(|_| "Android text asset is not UTF-8.")?;
        }
        files.insert((*name).into(), bytes);
    }
    let prop = std::str::from_utf8(&files["module.prop"])
        .map_err(|_| "Module properties are not UTF-8.")?;
    for (key, expected) in [
        ("id=", "id=wallet_diagnostic"),
        ("version=", "version=v0.3.0"),
        ("versionCode=", "versionCode=4"),
    ] {
        let values: Vec<_> = prop.lines().filter(|l| l.starts_with(key)).collect();
        if values != [expected] {
            return Err("Module identity/version must match RHSO 0.3.0 code 4 without duplicate properties.".into());
        }
    }
    if !files["skip_mount"].is_empty() {
        return Err("skip_mount must be an empty marker.".into());
    }
    let executable = read_regular(&backend, MAX_BACKEND)?;
    validate_elf(&executable)?;
    total = total
        .checked_add(executable.len())
        .ok_or("Asset size overflow.")?;
    if total > MAX_TOTAL {
        return Err("Module assets exceed the package limit.".into());
    }
    files.insert("bin/walletdiag".into(), executable);
    let bytes = embedded_wasm(&files["webroot/rhso_webui_bg.wasm"])?;
    if total.checked_add(bytes.len()).is_none_or(|n| n > MAX_TOTAL) {
        return Err("Module assets exceed the package limit after WASM embedding.".into());
    }
    files.insert("webroot/rhso_webui_bytes.js".into(), bytes);
    Ok(files)
}
pub fn archive(files: BTreeMap<String, Vec<u8>>) -> Result<Package> {
    let entries = files.len();
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let date =
        DateTime::from_date_and_time(2000, 1, 1, 0, 0, 0).map_err(|_| "Fixed ZIP date invalid.")?;
    for (name, bytes) in files {
        let mode = if name == "bin/walletdiag" || name.ends_with(".sh") {
            0o755
        } else {
            0o644
        };
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(9))
            .last_modified_time(date)
            .unix_permissions(mode)
            .large_file(false);
        zip.start_file(&name, options)
            .map_err(|_| "ZIP entry creation failed.")?;
        zip.write_all(&bytes)
            .map_err(|_| "ZIP entry write failed.")?;
    }
    let bytes = zip
        .finish()
        .map_err(|_| "ZIP finalization failed.")?
        .into_inner();
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(Package {
        bytes,
        sha256,
        entries,
    })
}
fn output_name(path: &Path) -> Result<&str> {
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("Output ZIP filename is unavailable.")?;
    if name.len() > 128
        || !name.ends_with(".zip")
        || name.starts_with('.')
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    {
        return Err("Use a simple bounded .zip output filename.".into());
    }
    Ok(name)
}
fn same_tree(path: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        path.to_string_lossy()
            .to_lowercase()
            .starts_with(&(root.to_string_lossy().to_lowercase() + "\\"))
            || path
                .to_string_lossy()
                .eq_ignore_ascii_case(&root.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        path.starts_with(root)
    }
}
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    check_ancestors(path, true)?;
    if let Ok(m) = fs::symlink_metadata(path)
        && (!m.is_file() || reparse(&m))
    {
        return Err("Output is not a regular file.".into());
    }
    let parent = path.parent().ok_or("Output parent unavailable.")?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Output filename unavailable.")?;
    let temp = parent.join(format!(".{name}.rhso-{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(&temp).map_err(
        |_| "Temporary output could not be created; no existing temporary file is replaced.",
    )?;
    let result = (|| {
        file.write_all(data)
            .map_err(|_| "Temporary output write failed.")?;
        file.sync_all()
            .map_err(|_| "Temporary output sync failed.")?;
        drop(file);
        check_ancestors(path, true)?;
        fs::rename(&temp, path).map_err(|_| "Output replacement failed.")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
pub fn run(options: &Options) -> Result<Package> {
    let output = absolute(&options.output)?;
    let module = absolute(&options.module)?;
    let backend = absolute(&options.backend)?;
    let name = output_name(&output)?.to_owned();
    let sidecar = PathBuf::from(format!("{}.sha256", output.to_string_lossy()));
    if same_tree(&output, &module) || same_tree(&output, &backend) || same_tree(&sidecar, &backend)
    {
        return Err("Output must be outside module sources and differ from the backend.".into());
    }
    let parent = output.parent().ok_or("Output parent unavailable.")?;
    for p in [&output, &sidecar] {
        check_ancestors(p, true)?;
        if let Ok(m) = fs::symlink_metadata(p)
            && (!m.is_file() || reparse(&m))
        {
            return Err("Output or sidecar is not a regular file.".into());
        }
    }
    let files = collect(&module, &backend)?;
    let package = archive(files)?;
    fs::create_dir_all(parent).map_err(|_| "Output directory creation failed.")?;
    check_ancestors(parent, false)?;
    write_atomic(&output, &package.bytes)?;
    write_atomic(&sidecar, format!("{}  {name}\n", package.sha256).as_bytes())?;
    Ok(package)
}
