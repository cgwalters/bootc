use std::fmt::Display;
use std::process::Command;

use anyhow::{Context, Result};
use camino::Utf8Path;
use ostree::glib;
use ostree_container::OstreeImageReference;
use ostree_ext::container as ostree_container;
use ostree_ext::keyfileext::KeyFileExt;
use ostree_ext::ostree;
use serde::Serializer;

/// Parse an ostree origin file (a keyfile) and extract the targeted
/// container image reference.
pub(crate) fn get_image_origin(
    deployment: &ostree::Deployment,
) -> Result<(glib::KeyFile, Option<OstreeImageReference>)> {
    let origin = deployment
        .origin()
        .ok_or_else(|| anyhow::anyhow!("Missing origin"))?;
    let imgref = origin
        .optional_string("origin", ostree_container::deploy::ORIGIN_CONTAINER)
        .context("Failed to load container image from origin")?
        .map(|v| ostree_container::OstreeImageReference::try_from(v.as_str()))
        .transpose()?;
    Ok((origin, imgref))
}

/// Try to look for keys injected by e.g. rpm-ostree requesting machine-local
/// changes; if any are present, return `true`.
pub(crate) fn origin_has_rpmostree_stuff(kf: &glib::KeyFile) -> bool {
    // These are groups set in https://github.com/coreos/rpm-ostree/blob/27f72dce4f9b5c176ad030911c12354e2498c07d/rust/src/origin.rs#L23
    // TODO: Add some notion of "owner" into origin files
    for group in ["rpmostree", "packages", "overrides", "modules"] {
        if kf.has_group(group) {
            return true;
        }
    }
    false
}

/// Implement the `Serialize` trait for types that are `Display`.
/// https://stackoverflow.com/questions/58103801/serialize-using-the-display-trait
pub(crate) fn ser_with_display<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Display,
    S: Serializer,
{
    serializer.collect_str(value)
}

/// Convert a path to relative if it isn't already.
pub(crate) fn ensure_relative_path(p: &Utf8Path) -> &Utf8Path {
    p.as_str().trim_start_matches('/').into()
}

/// Run a command in the host mount namespace
#[allow(dead_code)]
pub(crate) fn run_in_host_mountns(cmd: &str) -> Command {
    let mut c = Command::new("nsenter");
    c.args(["-m", "-t", "1", "--", cmd]);
    c
}

/// Given a possibly tagged image like quay.io/foo/bar:latest and a digest 0ab32..., return
/// the digested form quay.io/foo/bar@sha256:0ab32...
#[allow(dead_code)]
pub(crate) fn digested_pullspec(image: &str, digest: &str) -> String {
    let image = image.rsplit_once(':').map(|v| v.0).unwrap_or(image);
    format!("{image}@{digest}")
}
