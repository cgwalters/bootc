//! # Controlling bootc-managed images
//!
//! APIs for operating on container images in the bootc storage.

use anyhow::{Context, Result};
use fn_error_context::context;
use ostree_ext::container::{ImageReference, Transport};

/// The name of the image we push to containers-storage if nothing is specified.
const IMAGE_DEFAULT: &str = "localhost/bootc";

#[context("Listing images")]
pub(crate) async fn list_entrypoint() -> Result<()> {
    let sysroot = crate::cli::get_locked_sysroot().await?;
    let repo = &sysroot.repo();

    let images = ostree_ext::container::store::list_images(repo).context("Querying images")?;

    for image in images {
        println!("{image}");
    }
    Ok(())
}

#[context("Pushing image")]
pub(crate) async fn push_entrypoint(
    transport: Transport,
    source: Option<&str>,
    target: Option<&str>,
) -> Result<()> {
    let sysroot = crate::cli::get_locked_sysroot().await?;

    let repo = &sysroot.repo();

    // If the target isn't specified, push to containers-storage + our default image
    let target = if let Some(target) = target {
        ImageReference {
            transport,
            name: target.to_owned(),
        }
    } else {
        ImageReference {
            transport: Transport::ContainerStorage,
            name: IMAGE_DEFAULT.to_string(),
        }
    };

    // If the source isn't specified, we use the booted image
    let source = if let Some(source) = source {
        ImageReference::try_from(source).context("Parsing source image")?
    } else {
        let status = crate::status::get_status_require_booted(&sysroot)?;
        // SAFETY: We know it's booted
        let booted = status.2.status.booted.unwrap();
        let booted_image = booted.image.unwrap().image;
        ImageReference {
            transport: Transport::try_from(booted_image.transport.as_str()).unwrap(),
            name: booted_image.image,
        }
    };
    let r =
        ostree_ext::container::store::export(repo, &source, &target, Default::default()).await?;

    println!("Pushed: {target} {r}");
    Ok(())
}
