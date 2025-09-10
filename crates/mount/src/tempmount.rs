use anyhow::{Context, Result};

use camino::Utf8Path;
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use fn_error_context::context;
use rustix::mount::{unmount, UnmountFlags};

pub struct TempMount {
    pub dir: tempfile::TempDir,
    pub fd: Dir,
}

impl TempMount {
    /// Mount device/partition on a tempdir which will be automatically unmounted on drop
    #[context("Mounting {dev}")]
    pub fn mount_dev(dev: &str) -> Result<Self> {
        let tempdir = tempfile::TempDir::new()?;

        let utf8path = Utf8Path::from_path(tempdir.path())
            .ok_or(anyhow::anyhow!("Failed to convert path to UTF-8 Path"))?;

        crate::mount(dev, utf8path)?;

        // There's a case here where if the following open fails, we won't unmount which should be
        // unlikely
        let fd = Dir::open_ambient_dir(tempdir.path(), ambient_authority())
            .with_context(|| format!("Opening {:?}", tempdir.path()))?;

        Ok(TempMount { dir: tempdir, fd })
    }
}

impl Drop for TempMount {
    fn drop(&mut self) {
        match unmount(self.dir.path(), UnmountFlags::DETACH) {
            Ok(_) => {}
            Err(e) => tracing::warn!("Failed to unmount tempdir: {e:?}"),
        }
    }
}
