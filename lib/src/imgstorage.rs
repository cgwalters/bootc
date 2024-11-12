//! # bootc-managed container storage
//!
//! The default storage for this project uses ostree, canonically storing all of its state in
//! `/sysroot/ostree`.
//!
//! This containers-storage: which canonically lives in `/sysroot/ostree/bootc`.

use std::collections::HashSet;
use std::io::Seek;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::str::FromStr as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use bootc_utils::{AsyncCommandRunExt, CommandRunExt, ExitStatusExt};
use camino::Utf8Path;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::cap_tempfile::TempDir;
use cap_std_ext::cmdext::CapStdExtCommandExt;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::keyfileext::KeyFileExt;
use ostree_ext::ostree;
use ostree_ext::ostree_prepareroot::Tristate;
use ostree_ext::repoext::RepoExt;
use std::os::fd::{AsFd, OwnedFd};
use tokio::process::Command as AsyncCommand;

use crate::fsverity;

// Pass only 100 args at a time just to avoid potentially overflowing argument
// vectors; not that this should happen in reality, but just in case.
const SUBCMD_ARGV_CHUNKING: usize = 100;

/// Global directory path which we use for podman to point
/// it at our storage. Unfortunately we can't yet use the
/// /proc/self/fd/N trick because it currently breaks due
/// to how the untar process is forked in the child.
pub(crate) const STORAGE_ALIAS_DIR: &str = "/run/bootc/storage";
/// We pass this via /proc/self/fd to the child process.
const STORAGE_RUN_FD: i32 = 3;

/// The path to the storage, relative to the physical system root.
pub(crate) const SUBPATH: &str = "ostree/bootc/storage";
/// The path to the "runroot" with transient runtime state; this is
/// relative to the /run directory
const RUNROOT: &str = "bootc/storage";
pub(crate) struct Storage {
    /// The root directory
    sysroot: Dir,
    /// The location of container storage
    storage_root: Dir,
    #[allow(dead_code)]
    /// Our runtime state
    run: Dir,
    /// Disallow using this across multiple threads concurrently; while we
    /// have internal locking in podman, in the future we may change how
    /// things work here. And we don't have a use case right now for
    /// concurrent operations.
    _unsync: std::cell::Cell<()>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PullMode {
    /// Pull only if the image is not present
    IfNotExists,
    /// Always check for an update
    #[allow(dead_code)]
    Always,
}

#[allow(unsafe_code)]
#[context("Binding storage roots")]
fn bind_storage_roots(cmd: &mut Command, storage_root: &Dir, run_root: &Dir) -> Result<()> {
    // podman requires an absolute path, for two reasons right now:
    // - It writes the file paths into `db.sql`, a sqlite database for unknown reasons
    // - It forks helper binaries, so just giving it /proc/self/fd won't work as
    //   those helpers may not get the fd passed. (which is also true of skopeo)
    // We create a new mount namespace, which also has the helpful side effect
    // of automatically cleaning up the global bind mount that the storage stack
    // creates.

    let storage_root = Arc::new(storage_root.try_clone().context("Cloning storage root")?);
    let run_root: Arc<OwnedFd> = Arc::new(run_root.try_clone().context("Cloning runroot")?.into());
    // SAFETY: All the APIs we call here are safe to invoke between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            use rustix::fs::{Mode, OFlags};
            // For reasons I don't understand, we can't just `mount("/proc/self/fd/N", "/path/to/target")`
            // but it *does* work to fchdir(fd) + mount(".", "/path/to/target").
            // I think it may be that mount doesn't like operating on the magic links?
            // This trick only works if we set our working directory to the target *before*
            // creating the new namespace too.
            //
            // I think we may be hitting this:
            //
            // "       EINVAL A bind operation (MS_BIND) was requested where source referred a mount namespace magic link (i.e., a /proc/pid/ns/mnt magic link or a bind mount to such a link) and the propagation type of the parent mount of target was
            // MS_SHARED, but propagation of the requested bind mount could lead to a circular dependency that might prevent the mount namespace from ever being freed."
            //
            // But...how did we avoid that circular dependency by using the process cwd?
            //
            // I tried making the mounts recursively private, but that didn't help.
            let oldwd = rustix::fs::open(
                ".",
                OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::RDONLY,
                Mode::empty(),
            )?;
            rustix::process::fchdir(&storage_root)?;
            rustix::thread::unshare(rustix::thread::UnshareFlags::NEWNS)?;
            rustix::mount::mount_bind(".", STORAGE_ALIAS_DIR)?;
            rustix::process::fchdir(&oldwd)?;
            Ok(())
        })
    };
    cmd.take_fd_n(run_root, STORAGE_RUN_FD);
    Ok(())
}

fn new_podman_cmd_in(storage_root: &Dir, run_root: &Dir) -> Result<Command> {
    let mut cmd = Command::new("podman");
    bind_storage_roots(&mut cmd, storage_root, run_root)?;
    let run_root = format!("/proc/self/fd/{}", STORAGE_RUN_FD);
    cmd.args(["--root", STORAGE_ALIAS_DIR, "--runroot", run_root.as_str()]);
    Ok(cmd)
}

impl Storage {
    /// Create a `podman image` Command instance prepared to operate on our alternative
    /// root.
    pub(crate) fn new_image_cmd(&self) -> Result<Command> {
        let mut r = new_podman_cmd_in(&self.storage_root, &self.run)?;
        // We want to limit things to only manipulating images by default.
        r.arg("image");
        Ok(r)
    }

    fn init_globals() -> Result<()> {
        // Ensure our global storage alias dir exists
        std::fs::create_dir_all(STORAGE_ALIAS_DIR)
            .with_context(|| format!("Creating {STORAGE_ALIAS_DIR}"))?;
        Ok(())
    }

    #[context("Creating imgstorage")]
    pub(crate) fn create(sysroot: &Dir, run: &Dir) -> Result<Self> {
        Self::init_globals()?;
        let subpath = Utf8Path::new(SUBPATH);
        // SAFETY: We know there's a parent
        let parent = subpath.parent().unwrap();
        if !sysroot
            .try_exists(subpath)
            .with_context(|| format!("Querying {subpath}"))?
        {
            let tmp = format!("{SUBPATH}.tmp");
            sysroot.remove_all_optional(&tmp).context("Removing tmp")?;
            sysroot
                .create_dir_all(parent)
                .with_context(|| format!("Creating {parent}"))?;
            sysroot.create_dir_all(&tmp).context("Creating tmpdir")?;
            let storage_root = sysroot.open_dir(&tmp).context("Open tmp")?;
            // There's no explicit API to initialize a containers-storage:
            // root, simply passing a path will attempt to auto-create it.
            // We run "podman images" in the new root.
            new_podman_cmd_in(&storage_root, &run)?
                .stdout(Stdio::null())
                .arg("images")
                .run()
                .context("Initializing images")?;
            drop(storage_root);
            sysroot
                .rename(&tmp, sysroot, subpath)
                .context("Renaming tmpdir")?;
            tracing::debug!("Created image store");
        }
        Self::open(sysroot, run)
    }

    #[context("Opening imgstorage")]
    pub(crate) fn open(sysroot: &Dir, run: &Dir) -> Result<Self> {
        tracing::trace!("Opening container image store");
        Self::init_globals()?;
        let storage_root = sysroot
            .open_dir(SUBPATH)
            .with_context(|| format!("Opening {SUBPATH}"))?;
        // Always auto-create this if missing
        run.create_dir_all(RUNROOT)
            .with_context(|| format!("Creating {RUNROOT}"))?;
        let run = run.open_dir(RUNROOT)?;
        Ok(Self {
            sysroot: sysroot.try_clone()?,
            storage_root,
            run,
            _unsync: Default::default(),
        })
    }

    #[context("Listing images")]
    pub(crate) async fn list_images(&self) -> Result<Vec<crate::podman::ImageListEntry>> {
        let mut cmd = self.new_image_cmd()?;
        cmd.args(["list", "--format=json"]);
        cmd.stdin(Stdio::null());
        // It's maximally convenient for us to just pipe the whole output to a tempfile
        let mut stdout = tempfile::tempfile()?;
        cmd.stdout(stdout.try_clone()?);
        // Allocate stderr, which is passed to the status checker
        let stderr = tempfile::tempfile()?;
        cmd.stderr(stderr.try_clone()?);

        // Spawn the child and wait
        AsyncCommand::from(cmd)
            .status()
            .await?
            .check_status(stderr)?;
        // Spawn a helper thread to avoid blocking the main thread
        // parsing JSON.
        tokio::task::spawn_blocking(move || -> Result<_> {
            stdout.seek(std::io::SeekFrom::Start(0))?;
            let stdout = std::io::BufReader::new(stdout);
            let r = serde_json::from_reader(stdout)?;
            Ok(r)
        })
        .await?
        .map_err(Into::into)
    }

    #[context("Pruning")]
    pub(crate) async fn prune_except_roots(&self, roots: &HashSet<&str>) -> Result<Vec<String>> {
        let all_images = self.list_images().await?;
        tracing::debug!("Images total: {}", all_images.len(),);
        let mut garbage = Vec::new();
        for image in all_images {
            if image
                .names
                .iter()
                .flatten()
                .any(|name| !roots.contains(name.as_str()))
            {
                garbage.push(image.id);
            }
        }
        tracing::debug!("Images to prune: {}", garbage.len());
        for garbage in garbage.chunks(SUBCMD_ARGV_CHUNKING) {
            let mut cmd = self.new_image_cmd()?;
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::null());
            cmd.arg("rm");
            cmd.args(garbage);
            AsyncCommand::from(cmd).run().await?;
        }
        Ok(garbage)
    }

    /// Return true if the image exists in the storage.
    pub(crate) async fn exists(&self, image: &str) -> Result<bool> {
        // Sadly https://docs.rs/containers-image-proxy/latest/containers_image_proxy/struct.ImageProxy.html#method.open_image_optional
        // doesn't work with containers-storage yet
        let mut cmd = AsyncCommand::from(self.new_image_cmd()?);
        cmd.args(["exists", image]);
        Ok(cmd.status().await?.success())
    }

    /// Fetch the image if it is not already present; return whether
    /// or not the image was fetched.
    pub(crate) async fn pull(&self, image: &str, mode: PullMode) -> Result<bool> {
        match mode {
            PullMode::IfNotExists => {
                if self.exists(image).await? {
                    tracing::debug!("Image is already present: {image}");
                    return Ok(false);
                }
            }
            PullMode::Always => {}
        };
        let mut cmd = self.new_image_cmd()?;
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.args(["pull", image]);
        let authfile = ostree_ext::globals::get_global_authfile(&self.sysroot)?
            .map(|(authfile, _fd)| authfile);
        if let Some(authfile) = authfile {
            cmd.args(["--authfile", authfile.as_str()]);
        }
        tracing::debug!("Pulling image: {image}");
        let mut cmd = AsyncCommand::from(cmd);
        cmd.run().await.context("Failed to pull image")?;
        Ok(true)
    }

    /// Copy an image from the default container storage (/var/lib/containers/)
    /// to this storage.
    #[context("Pulling from host storage: {image}")]
    pub(crate) async fn pull_from_host_storage(&self, image: &str) -> Result<()> {
        let mut cmd = Command::new("podman");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        // An ephemeral place for the transient state;
        let temp_runroot = TempDir::new(cap_std::ambient_authority())?;
        bind_storage_roots(&mut cmd, &self.storage_root, &temp_runroot)?;

        // The destination (target stateroot) + container storage dest
        let storage_dest = &format!(
            "containers-storage:[overlay@{STORAGE_ALIAS_DIR}+/proc/self/fd/{STORAGE_RUN_FD}]"
        );
        cmd.args(["image", "push", "--remove-signatures", image])
            .arg(format!("{storage_dest}{image}"));
        let mut cmd = AsyncCommand::from(cmd);
        cmd.run().await?;
        temp_runroot.close()?;
        Ok(())
    }
}

/// Ensure fsverity is enabled on all regular file objects in an OSTree repository.
pub(crate) async fn repo_enable_verity(repo: &ostree::Repo) -> Result<()> {
    let repo = repo.clone();
    tokio::task::spawn_blocking(move || {
        repo.traverse_regfile_objects::<(), _>(|name, f| {
            fsverity::ioctl::fs_ioc_enable_verity::<_, fsverity::Sha256HashValue>(f.as_fd())
                .with_context(|| format!("Enabling fsverity on object {name}"))?;
            Ok(std::ops::ControlFlow::Continue(()))
        })?;
        let (group, key) = crate::store::REPO_VERITY_CONFIG.split_once('.').unwrap();
        let config = repo.config();
        config.set_string(group, key, Tristate::Enabled.as_ref());
        repo.write_config(&config)?;
        Ok(())
    })
    .await?
}

/// Query the fsverity enablement state on an OSTree repository
pub(crate) fn repo_get_fsverity(repo: &ostree::Repo) -> Result<Tristate> {
    let config = repo.config();
    let (group, key) = crate::store::REPO_VERITY_CONFIG.split_once('.').unwrap();
    let r = config
        .optional_string(group, key)?
        .map(|v| Tristate::from_str(&v))
        .transpose()?
        .unwrap_or_default();
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    static_assertions::assert_not_impl_any!(Storage: Sync);
}
