use crate::{
    error::{Error, Result},
    util,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
#[cfg(unix)]
use std::fs::File;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub mode: u32,
    pub uid: i32,
    pub gid: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selinux: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileState {
    pub exists: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    pub size: i64,
    pub metadata: Metadata,
}
pub fn valid_context(s: &str) -> bool {
    s.is_empty()
        || (s.len() <= 256
            && regex::Regex::new(r"^u:object_r:[a-zA-Z0-9_]+:s0(:c[0-9]+(,c[0-9]+)*)?\x00?$")
                .expect("constant regex")
                .is_match(s))
}
pub fn no_links(path: &Path) -> Result<()> {
    let mut p = Some(path);
    while let Some(v) = p {
        match fs::symlink_metadata(v) {
            Ok(m) => {
                let link = m.file_type().is_symlink();
                #[cfg(windows)]
                let link = {
                    use std::os::windows::fs::MetadataExt;
                    link || m.file_attributes() & 0x400 != 0
                };
                if link {
                    return Err(Error::new(
                        "E_PATH",
                        "Symbolic links are not accepted for private or active files.",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        p = v.parent();
    }
    Ok(())
}
pub fn bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    no_links(path)?;
    let m = fs::metadata(path)?;
    if !m.is_file() || m.len() > max as u64 {
        return Err(Error::new(
            "E_INPUT",
            "Expected a regular file within the size limit.",
        ));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut f = opts.open(path)?;
    let mut b = Vec::with_capacity(m.len() as usize);
    Read::by_ref(&mut f)
        .take(max as u64 + 1)
        .read_to_end(&mut b)?;
    if b.len() > max || b.len() as u64 != m.len() || f.metadata()?.len() != m.len() {
        return Err(Error::new(
            "E_INPUT",
            "Input changed while being read; stage it again.",
        ));
    }
    Ok(b)
}
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let b = bounded(path, 4 << 20)?;
    util::strict_json(&b)?;
    Ok(serde_json::from_slice(&b)?)
}
pub fn write_json<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    let mut b = serde_json::to_vec_pretty(v)?;
    b.push(b'\n');
    atomic_write(
        path,
        &b,
        &Metadata {
            mode: 0o600,
            uid: util::owner_id(),
            gid: util::owner_id(),
            selinux: String::new(),
        },
    )
}
pub fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
pub fn private_dir(path: &Path) -> Result<()> {
    no_links(path)?;
    fs::create_dir_all(path)?;
    set_metadata(
        path,
        &Metadata {
            mode: 0o700,
            uid: util::owner_id(),
            gid: util::owner_id(),
            selinux: String::new(),
        },
    )?;
    sync_dir(path)?;
    if let Some(p) = path.parent() {
        sync_dir(p)?;
    }
    Ok(())
}
pub fn atomic_write(path: &Path, b: &[u8], m: &Metadata) -> Result<()> {
    no_links(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("E_PATH", "A parent directory is required."))?;
    let tmp = parent.join(format!(".walletdiag-{}", util::new_id()?));
    let result = (|| {
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(b)?;
        f.sync_all()?;
        set_metadata(&tmp, m)?;
        f.sync_all()?;
        drop(f);
        no_links(path)?;
        fs::rename(&tmp, path)?;
        sync_dir(parent)
    })();
    let _ = fs::remove_file(&tmp);
    result
}
pub fn remove_file(path: &Path) -> Result<()> {
    no_links(path)?;
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    sync_dir(
        path.parent()
            .ok_or_else(|| Error::new("E_PATH", "A parent directory is required."))?,
    )
}
pub fn snapshot_file(path: &Path, max: usize) -> Result<FileState> {
    no_links(path)?;
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FileState::default()),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let b = bounded(path, max)?;
    Ok(FileState {
        exists: true,
        sha256: util::hash(&b),
        size: b.len() as i64,
        metadata: metadata(path)?,
    })
}
#[cfg(unix)]
fn cpath(path: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::new("E_PATH", "The path is invalid."))
}
#[cfg(unix)]
pub fn metadata(path: &Path) -> Result<Metadata> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path)?;
    let mut out = Metadata {
        mode: m.mode() & 0o777,
        uid: m.uid() as i32,
        gid: m.gid() as i32,
        selinux: String::new(),
    };
    let p = cpath(path)?;
    let name = c"security.selinux";
    let n = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        if matches!(e.raw_os_error(), Some(libc::ENODATA) | Some(libc::ENOTSUP)) {
            return Ok(out);
        }
        return Err(e.into());
    }
    if n > 256 {
        return Err(Error::new(
            "E_METADATA",
            "SELinux context exceeds its bound.",
        ));
    }
    let mut b = vec![0; n as usize];
    let n2 = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), b.as_mut_ptr().cast(), b.len()) };
    if n2 != n {
        return Err(Error::new(
            "E_METADATA",
            "SELinux metadata changed while reading.",
        ));
    }
    out.selinux = String::from_utf8(b)
        .map_err(|_| Error::new("E_METADATA", "SELinux metadata is invalid."))?;
    Ok(out)
}
#[cfg(not(unix))]
pub fn metadata(path: &Path) -> Result<Metadata> {
    let m = fs::metadata(path)?;
    Ok(Metadata {
        mode: if m.permissions().readonly() {
            0o400
        } else if m.is_dir() {
            0o700
        } else {
            0o600
        },
        uid: -1,
        gid: -1,
        selinux: String::new(),
    })
}
#[cfg(unix)]
pub fn set_metadata(path: &Path, m: &Metadata) -> Result<()> {
    let p = cpath(path)?;
    if unsafe { libc::chown(p.as_ptr(), m.uid as u32, m.gid as u32) } != 0
        || unsafe { libc::chmod(p.as_ptr(), m.mode as libc::mode_t) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if !m.selinux.is_empty()
        && unsafe {
            libc::setxattr(
                p.as_ptr(),
                c"security.selinux".as_ptr(),
                m.selinux.as_ptr().cast(),
                m.selinux.len(),
                0,
            )
        } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let got = metadata(path)?;
    if got.mode != m.mode
        || got.uid != m.uid
        || got.gid != m.gid
        || (!m.selinux.is_empty() && got.selinux != m.selinux)
    {
        return Err(Error::new(
            "E_METADATA",
            "Ownership, permissions or SELinux verification failed.",
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn set_metadata(path: &Path, m: &Metadata) -> Result<()> {
    let mut p = fs::metadata(path)?.permissions();
    p.set_readonly(m.mode & 0o200 == 0);
    fs::set_permissions(path, p)?;
    Ok(())
}
#[cfg(unix)]
pub fn enough_space(path: &Path, bytes: u64) -> Result<()> {
    let p = cpath(path)?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(p.as_ptr(), st.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let st = unsafe { st.assume_init() };
    if (st.f_bavail as u64).saturating_mul(st.f_frsize as u64) < bytes {
        return Err(Error::new(
            "E_SPACE",
            "Not enough free space for a complete backup and commit.",
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn enough_space(_path: &Path, _bytes: u64) -> Result<()> {
    Ok(())
}
pub fn pid_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        let n = unsafe { libc::kill(pid, 0) };
        n == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        pid as u32 == std::process::id()
    }
}
