# Build this project from source and write the updated content
# (i.e. /usr/bin/bootc and systemd units) to a new derived container
# image. See the `Justfile` for an example

# Note this is usually overridden via Justfile
ARG base=quay.io/centos-bootc/centos-bootc:stream10

# This first image captures a snapshot of the source code,
# note all the exclusions in .dockerignore.
FROM scratch as src
COPY . /src

# And this image only captures contrib/packaging separately
# to ensure we have more precise cache hits.
FROM scratch as packaging
COPY contrib/packaging /

# This image installs build deps, pulls in our source code, and installs updated
# bootc binaries in /out. The intention is that the target rootfs is extracted from /out
# back into a final stage (without the build deps etc) below.
FROM $base as buildroot
# Flip this off to disable initramfs code
ARG initramfs=1
# This installs our buildroot, and we want to cache it independently of the rest.
# Basically we don't want changing a .rs file to blow out the cache of packages.
RUN --mount=type=bind,from=packaging,target=/run/packaging /run/packaging/install-buildroot
# Now copy the rest of the source
COPY --from=src /src /src
WORKDIR /src
# See https://www.reddit.com/r/rust/comments/126xeyx/exploring_the_problem_of_faster_cargo_docker/
# We aren't using the full recommendations there, just the simple bits.
# First we download all of our Rust dependencies
RUN --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome cargo fetch

# We always do a "from scratch" build
# https://docs.fedoraproject.org/en-US/bootc/building-from-scratch/
# because this fixes https://github.com/containers/composefs-rs/issues/132
# NOTE: Until we have https://gitlab.com/fedora/bootc/base-images/-/merge_requests/317
#       this stage will end up capturing whatever RPMs we find at this time.
# NOTE: This is using the *stock* bootc binary, not the one we want to build from
#       local sources. We'll override it later.
# NOTE: All your base belong to me.
FROM $base as target-base
RUN /usr/libexec/bootc-base-imagectl build-rootfs --manifest=standard /target-rootfs

FROM scratch as base
COPY --from=target-base /target-rootfs/ /
COPY --from=src /src/hack/ /run/hack/
RUN cd /run/hack/ && ./provision-derived.sh
# Note we don't do any customization here yet
# Mark this as a test image
LABEL bootc.testimage="1"
# Otherwise standard metadata
LABEL containers.bootc 1
LABEL ostree.bootable 1
# https://pagure.io/fedora-kiwi-descriptions/pull-request/52
ENV container=oci
# Optional labels that only apply when running this image as a container. These keep the default entry point running under systemd.
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

# This layer contains things which aren't in the default image and may
# be used for sealing images in particular.
FROM base as tools
RUN <<EORUN
set -xeuo pipefail
. /usr/lib/os-release
case "${ID}${ID_LIKE:-}" in
  "*centos*")
    # Enable EPEL for sbsigntools
    dnf -y install epel-release
    ;;
esac
dnf -y install systemd-ukify sbsigntools
# And in the sealing case, we're going to inject and sign systemd-boot
# into the target image.
mkdir -p /out
cd /out
dnf -y download systemd-boot-unsigned
EORUN

# -------------
# external dependency cutoff point:
# NOTE: Every RUN instruction past this point should use `--network=none`; we want to ensure
# all external dependencies are clearly delineated.
# This is verified in `cargo xtask check-buildsys`.
# -------------

FROM buildroot as build
# Version for RPM build (optional, computed from git in Justfile)
ARG pkgversion
# For reproducible builds, SOURCE_DATE_EPOCH must be exported as ENV for rpmbuild to see it
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
# Build RPM directly from source, using cached target directory
RUN --network=none --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome RPM_VERSION="${pkgversion}" /src/contrib/packaging/build-rpm

# This image signs systemd-boot using our key, and writes the resulting binary into /out
FROM tools as sdboot-signed
# The secureboot key and cert are passed via Justfile
# We write the signed binary into /out
RUN --network=none \
    --mount=type=bind,from=tools,target=/run/sdboot-package \
    --mount=type=secret,id=secureboot_key \
    --mount=type=secret,id=secureboot_cert <<EORUN
set -xeuo pipefail
sdboot=$(ls /usr/lib/systemd/boot/efi/systemd-boot*.efi)
sdboot_bn=$(basename ${sdboot})
mkdir -p /out
rpm -Uvh /run/sdboot-package/out/*.rpm
# Sign with sbsign using db certificate and key
sbsign --key /run/secrets/secureboot_key \
       --cert /run/secrets/secureboot_cert \
       --output /out/${sdboot_bn} \
       /${sdboot}
ls -al /out/${sdboot_bn}
EORUN

# ----
# Unit and integration tests
# The section here (up until the last `FROM` line which acts as the default target)
# is non-default images for unit and source code validation.
# ----

# This "build" includes our unit tests
FROM build as units
# A place that we're more likely to be able to set xattrs
VOLUME /var/tmp
ENV TMPDIR=/var/tmp
RUN --network=none --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome make install-unit-tests

# This just does syntax checking
FROM buildroot as validate
RUN --network=none --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome make validate

# ----
# Final image assembly
# Common base for final images: configures variant, rootfs, and injects extra content
# ----
FROM base
# Install our built bootc package
RUN --network=none --mount=type=bind,from=packaging,target=/run/packaging \
    /run/packaging/install-rpm-and-setup /run/packages
ARG variant
RUN --network=none --mount=type=bind,from=packaging,target=/run/packaging \
    --mount=type=bind,from=sdboot-content,target=/run/sdboot-content \
    --mount=type=bind,from=sdboot-signed,target=/run/sdboot-signed \
    /run/packaging/configure-variant "${variant}"
ARG rootfs=""
RUN --network=none --mount=type=bind,from=packaging,target=/run/packaging /run/packaging/configure-rootfs "${variant}" "${rootfs}"
COPY --from=packaging /usr-extras/ /usr/
# And finally, test our linting
RUN --network=none bootc container lint --fatal-warnings
