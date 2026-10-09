pub mod api;
pub mod error;
pub mod fs;
pub mod inspect;
pub mod media_type;
pub mod network;
pub mod public_attestation;
pub mod request;
pub mod reset;
pub mod stack;
pub mod store;
pub mod transaction;
pub mod util;
use error::Result;
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
pub const VERSION: &str = "0.3.0";
pub const FILES: [&str; 3] = ["keybox.xml", "security_patch.txt", "target.txt"];
pub type Fault = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;
pub struct App {
    pub root: PathBuf,
    pub active: PathBuf,
    pub modules: PathBuf,
    pub shared_inbox: PathBuf,
    pub fake: bool,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub fault: Option<Fault>,
}
impl App {
    pub fn new(
        root: impl Into<PathBuf>,
        active: impl Into<PathBuf>,
        modules: impl Into<PathBuf>,
        fake: bool,
    ) -> Self {
        Self {
            root: root.into(),
            active: active.into(),
            modules: modules.into(),
            shared_inbox: PathBuf::from("/sdcard/keybox_inbox"),
            fake,
            clock: Arc::new(util::now),
            fault: None,
        }
    }
    pub fn now(&self) -> i64 {
        (self.clock)()
    }
    pub fn time(&self) -> String {
        util::time(self.now())
    }
    pub fn checkpoint(&self, name: &str) -> Result<()> {
        if let Some(f) = &self.fault {
            f(name)
        } else {
            Ok(())
        }
    }
    pub fn snapshot(&self) -> Result<BTreeMap<String, fs::FileState>> {
        let mut out = BTreeMap::new();
        fs::no_links(&self.active)?;
        for name in FILES {
            out.insert(
                name.into(),
                fs::snapshot_file(&self.active.join(name), 1 << 20)?,
            );
        }
        Ok(out)
    }
    pub fn valid_state(&self, s: &fs::FileState) -> bool {
        if !s.exists {
            return *s == fs::FileState::default();
        }
        util::valid_hash(&s.sha256)
            && s.size >= 0
            && s.size <= 1 << 20
            && s.metadata.mode <= 0o777
            && (self.fake || (s.metadata.uid >= 0 && s.metadata.gid >= 0))
            && s.metadata.uid <= 1 << 30
            && s.metadata.gid <= 1 << 30
            && fs::valid_context(&s.metadata.selinux)
    }
    pub fn with_lock<F: FnOnce() -> Result<Value>>(&self, f: F) -> Result<Value> {
        let _lock = self.lock()?;
        f()
    }
}
