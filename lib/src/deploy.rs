//! # Write deployments merging image with configmap
//!
//! Create a merged filesystem tree with the image and mounted configmaps.

use anyhow::{Context, Result};

use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::cap_tempfile;

use fn_error_context::context;
use glib::prelude::{Cast, ToVariant};
use ostree::{gio, glib};
use ostree_container::store::LayeredImageState;
use ostree_container::OstreeImageReference;
use ostree_ext::container as ostree_container;
use ostree_ext::ostree;
use ostree_ext::sysroot::SysrootLock;
use std::borrow::Cow;
use std::collections::HashMap;

use crate::spec::HostSpec;
use crate::spec::ImageReference;

// TODO use https://github.com/ostreedev/ostree-rs-ext/pull/493/commits/afc1837ff383681b947de30c0cefc70080a4f87a
const BASE_IMAGE_PREFIX: &str = "ostree/container/baseimage/bootc";
/// This is a temporary pointer used until a deployment is committed to
/// hold a strong reference to the base image.
const TMP_REF: &str = "tmp";

/// Set on an ostree commit if this is a derived commit
const BOOTC_DERIVED_KEY: &str = "bootc.derived";

/// Variant of HostSpec but required to be filled out
pub(crate) struct RequiredHostSpec<'a> {
    pub(crate) image: &'a ImageReference,
    pub(crate) configmaps: &'a Vec<String>,
}

impl<'a> RequiredHostSpec<'a> {
    /// Given a (borrowed) host specification, "unwrap" its internal
    /// options, giving a spec that is required to have a base container image.
    pub(crate) fn from_spec(spec: &'a HostSpec) -> Result<Self> {
        let image = spec
            .image
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing image in specification"))?;
        let configmaps = &spec.configmap;
        Ok(Self { image, configmaps })
    }
}

pub(crate) async fn cleanup(sysroot: &SysrootLock) -> Result<()> {
    let repo = sysroot.repo();
    let sysroot = sysroot.sysroot.clone();
    ostree_ext::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
        let cancellable = Some(cancellable);
        let repo = &repo;
        let txn = repo.auto_transaction(cancellable)?;
        let repo = txn.repo();

        // Regenerate our base references.  First, we delete the ones that exist
        for ref_entry in repo
            .list_refs_ext(
                Some(BASE_IMAGE_PREFIX),
                ostree::RepoListRefsExtFlags::NONE,
                cancellable,
            )
            .context("Listing refs")?
            .keys()
        {
            repo.transaction_set_refspec(ref_entry, None);
        }

        // Then, for each deployment which is derived (e.g. has configmaps) we synthesize
        // a base ref to ensure that it's not GC'd.
        for (i, deployment) in sysroot.deployments().into_iter().enumerate() {
            let commit = deployment.csum();
            if let Some(base) = get_base_commit(repo, &commit)? {
                repo.transaction_set_refspec(&format!("{BASE_IMAGE_PREFIX}/{i}"), Some(&base));
            }
        }

        Ok(())
    })
    .await
}

/// If commit is a bootc-derived commit (e.g. has configmaps), return its base.
#[context("Finding base commit")]
pub(crate) fn get_base_commit(repo: &ostree::Repo, commit: &str) -> Result<Option<String>> {
    let commitv = repo.load_commit(commit)?.0;
    let commitmeta = commitv.child_value(0);
    let commitmeta = &glib::VariantDict::new(Some(&commitmeta));
    let r = commitmeta.lookup::<String>(BOOTC_DERIVED_KEY)?;
    Ok(r)
}

/// If commit is a bootc-derived commit (e.g. has configmaps), return its base.
/// Otherwise, return the commit input unchanged.
#[context("Finding base commit")]
pub(crate) fn require_base_commit<'a>(
    repo: &ostree::Repo,
    commit: &'a str,
) -> Result<Cow<'a, str>> {
    let r = get_base_commit(repo, commit)?
        .map(Cow::Owned)
        .unwrap_or_else(|| Cow::Borrowed(commit));
    Ok(r)
}

/// Stage (queue deployment of) a fetched container image.
#[context("Staging")]
pub(crate) async fn stage(
    sysroot: &SysrootLock,
    stateroot: &str,
    image: &LayeredImageState,
    spec: &RequiredHostSpec<'_>,
) -> Result<()> {
    let repo = sysroot.repo();
    let merge_deployment = sysroot.merge_deployment(Some(stateroot));
    let origin = glib::KeyFile::new();
    let imgref = OstreeImageReference::from(spec.image.clone());
    let base_commit = require_base_commit(&repo, &image.merge_commit)?;
    origin.set_string(
        "origin",
        ostree_container::deploy::ORIGIN_CONTAINER,
        imgref.to_string().as_str(),
    );
    if spec.configmaps.is_empty() {
        let stateroot = Some(stateroot);
        let base_commit = image.get_commit().to_owned();
        let cancellable = gio::Cancellable::NONE;
        let _new_deployment = sysroot.stage_tree_with_options(
            stateroot,
            &base_commit,
            Some(&origin),
            merge_deployment.as_ref(),
            &Default::default(),
            cancellable,
        )?;
    } else {
        tracing::debug!("Configmaps to overlay: {}", spec.configmaps.len());
        // Create cloned data to pass into thread
        let configmaps = spec.configmaps.clone();
        let image_merge_commit = image.merge_commit.clone();
        let base_commit = base_commit.into_owned();
        let merge_commit =
            ostree_ext::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
                use rustix::fd::AsRawFd;
                let cancellable = Some(cancellable);
                let repo = &repo;
                let txn = repo.auto_transaction(cancellable)?;

                let tmp_baseref = format!("{BASE_IMAGE_PREFIX}/{TMP_REF}");
                txn.repo().transaction_set_ref(
                    None,
                    &tmp_baseref,
                    Some(image_merge_commit.as_str()),
                );
                drop(tmp_baseref);

                let devino = ostree::RepoDevInoCache::new();
                let repodir = Dir::reopen_dir(&repo.dfd_borrow())?;
                let repo_tmp = repodir.open_dir("tmp")?;
                let td = cap_tempfile::TempDir::new_in(&repo_tmp)?;

                let rootpath = "root";
                let checkout_mode = if repo.mode() == ostree::RepoMode::Bare {
                    ostree::RepoCheckoutMode::None
                } else {
                    ostree::RepoCheckoutMode::User
                };
                let mut checkout_opts = ostree::RepoCheckoutAtOptions {
                    mode: checkout_mode,
                    overwrite_mode: ostree::RepoCheckoutOverwriteMode::UnionFiles,
                    devino_to_csum_cache: Some(devino.clone()),
                    no_copy_fallback: true,
                    force_copy_zerosized: true,
                    process_whiteouts: false,
                    ..Default::default()
                };
                repo.checkout_at(
                    Some(&checkout_opts),
                    (*td).as_raw_fd(),
                    rootpath,
                    &base_commit,
                    cancellable,
                )
                .context("Checking out base commit")?;

                let sepolicy = ostree::SePolicy::new_at((*td).as_raw_fd(), cancellable)?;
                let mt = ostree::MutableTree::new();

                // Layer all configmaps
                checkout_opts.process_whiteouts = true;
                for name in configmaps {
                    crate::config::apply_configmap(repo, &mt, Some(&sepolicy), &name, cancellable)?;
                }

                let modifier =
                    ostree::RepoCommitModifier::new(ostree::RepoCommitModifierFlags::CONSUME, None);
                modifier.set_devino_cache(&devino);

                repo.write_dfd_to_mtree(
                    (*td).as_raw_fd(),
                    rootpath,
                    &mt,
                    Some(&modifier),
                    cancellable,
                )
                .context("Writing merged filesystem to mtree")?;

                let mut metadata = HashMap::new();
                metadata.insert(BOOTC_DERIVED_KEY, base_commit.to_variant());
                let metadata = metadata.to_variant();

                let merged_root = repo
                    .write_mtree(&mt, cancellable)
                    .context("Writing mtree")?;
                let merged_root = merged_root.downcast::<ostree::RepoFile>().unwrap();
                let merged_commit = repo
                    .write_commit(None, None, None, Some(&metadata), &merged_root, cancellable)
                    .context("Writing commit")?;
                txn.commit(cancellable)?;

                anyhow::Ok(merged_commit.to_string())
            })
            .await?;
        // TODO spawn once origin files are Send
        // let origin = origin.clone();
        // ostree_ext::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
        {
            let cancellable = gio::Cancellable::NONE;
            let _new_deployment = sysroot.stage_tree_with_options(
                Some(stateroot),
                merge_commit.as_str(),
                Some(&origin),
                merge_deployment.as_ref(),
                &Default::default(),
                cancellable,
            )?;
        }
    }
    crate::deploy::cleanup(sysroot).await?;
    println!("Queued for next boot: {imgref}");
    if let Some(version) = image
        .configuration
        .as_ref()
        .and_then(ostree_container::version_for_config)
    {
        println!("  Version: {version}");
    }
    println!("  Digest: {}", image.manifest_digest);
    ostree_container::deploy::remove_undeployed_images(sysroot).context("Pruning images")?;
    anyhow::Ok(())
}
