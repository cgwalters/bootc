# Internals (rustdoc)

This section provides rustdoc API documentation for bootc's internal crates.
These are intended for developers working on bootc itself, not for external consumption.

## Core crates

- [bootc-lib](internals/bootc_lib/index.html) - Core bootc implementation
- [bootc](internals/bootc/index.html) - CLI frontend

## Supporting crates

- [ostree-ext](internals/ostree_ext/index.html) - Extension APIs for OSTree
- [bootc-mount](internals/bootc_mount/index.html) - Internal mount utilities
- [bootc-kernel-cmdline](internals/bootc_kernel_cmdline/index.html) - Kernel command line parsing
- [bootc-initramfs-setup](internals/bootc_initramfs_setup/index.html) - Initramfs setup code
- [etc-merge](internals/etc_merge/index.html) - /etc merge handling

## Utility crates

- [bootc-internal-utils](internals/bootc_internal_utils/index.html) - Internal utilities
- [bootc-internal-blockdev](internals/bootc_internal_blockdev/index.html) - Block device handling
- [bootc-sysusers](internals/bootc_sysusers/index.html) - systemd-sysusers implementation
- [bootc-tmpfiles](internals/bootc_tmpfiles/index.html) - systemd-tmpfiles implementation
