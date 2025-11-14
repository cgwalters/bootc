# Composefs Integration Plan

## Overview

This document outlines the plan for composefs integration in bootc. As of commit `87d1d391` (September 2025), composefs is enabled by default, representing a major milestone in the project's evolution toward a fully native composefs backend.

## Current Status

The core composefs backend implementation landed in PR #1444 (September 2025), providing a complete native backend with the `composefs-backend` feature. This implementation includes full support for both BLS (Boot Loader Specification) and systemd-boot/UKI boot configurations, along with deployment state tracking that stores composefs metadata. All core operations (`update`, `switch`, `rollback`, `status`) work with the composefs backend, and staged deployments are finalized through the `composefs-finalize-staged.service` systemd unit. The repository abstraction layer uses a `ComposefsRepository` trait to handle storage operations.

Recent enhancements in October 2025 focused on making composefs the default experience. The install logic now detects UKIs and automatically enables composefs, and when bootupd is absent, systemd-boot is installed by default. CLI options allow passing UKI addons, and end-to-end CI coverage validates the complete install and run workflow. The `install-to-existing-root` command gained composefs-specific options, and the finalize-staged service now starts automatically on update and switch operations. Target image references are stored in the composefs-backend state for proper tracking.

Documentation has been updated across the board, with comprehensive filesystem documentation covering composefs usage patterns, man pages reflecting the new functionality, and bootloader documentation explaining the integration details.

## Architecture

### Key Components

```
bootc/
├── crates/lib/src/bootc_composefs/
│   ├── boot.rs          # Boot entry management, UKI/BLS handling
│   ├── finalize.rs      # Staged deployment finalization
│   ├── repo.rs          # Repository abstraction layer
│   ├── rollback.rs      # Rollback operations
│   ├── state.rs         # Deployment state management
│   ├── status.rs        # Status reporting
│   ├── switch.rs        # Image switching
│   └── update.rs        # Update operations
├── composefs_consts.rs  # Constants and configuration
└── systemd/
    └── composefs-finalize-staged.service
```

### Storage Model

The composefs backend uses a different storage model than the traditional ostree approach. Composefs objects are stored in the repository with optional fsverity support. The state directory is located at `/sysroot/state/deploy`, with transient state (such as staged deployments) stored in `/run/composefs`. Boot entries are either BLS configs or UKI with the `composefs=` kernel parameter. Image metadata is stored with the deployment state, including the target image reference.

## Remaining Work

### Fsverity Upgrade Path

The current implementation has a known limitation when upgrading from `composefs.enabled = yes` to `composefs.enabled = verity`. Older objects that lack fsverity may fail at runtime after the upgrade because the system expects all objects to have fsverity enabled. We need migration logic that can re-verify existing objects during the upgrade process, with automatic detection and re-verification. The upgrade procedure should be documented clearly for users who want to enable this security feature on existing systems.

### Composefs Integrity Verification

Issue #1190 tracks the lack of a default mechanism to check the integrity of the upper composefs layer. While the lower layer can use fsverity, we need to design and implement verification for the upper layer as well. This should consider integration with measured boot and TPM for systems that require strong security guarantees. The security model and its guarantees need clear documentation so users understand what protection they're getting.

### Logically Bound Images Integration

Logically bound images currently use a separate storage mechanism, which means fsverity configuration for the bootc storage doesn't apply to them. We should either unify the storage mechanisms or add fsverity support specifically for bound images. The goal is ensuring a consistent security posture across all image types, with clear documentation about security boundaries and what's protected by fsverity.

### Mount Optimization

A TODO comment in `utils.rs` notes that future work should mount via composefs directly rather than the current approach. This optimization needs evaluation to determine the performance benefits, followed by implementation where it makes sense. Benchmarking will validate whether the changes improve boot time or reduce resource usage.

### UKI Addon Composefs Parameters

The boot code has a TODO noting that UKI addons might also have `composefs=` cmdline parameters. We need to parse and handle these parameters, ensuring proper precedence and merging when multiple sources provide composefs configuration. Test coverage should validate the various combinations.

### Ostree Integration Cleanup

A TODO in `install.rs` indicates that the EROFS superblock filename constant should move to ostree rather than being defined in bootc. This requires coordination with ostree upstream to determine the right location for these constants, then updating bootc to use the ostree-provided values.

### Testing and Quality

Integration test coverage should expand to handle edge cases, upgrade paths, and migration scenarios. A performance benchmarking suite would help catch regressions, and stress testing for concurrent operations would validate robustness under load.

### Performance Work

Profiling and optimization work should focus on boot time, memory footprint during operations, and repository operation efficiency. These improvements should be data-driven based on actual measurements.

### Observability and Documentation

Enhanced logging and diagnostics would help users troubleshoot issues. Metrics collection for operations could inform optimization work. Error messages should be reviewed to ensure they're helpful and actionable. Documentation gaps include a troubleshooting guide for common issues, a migration guide from ostree-only systems, and documentation of performance characteristics and tuning options.

## Testing Strategy

Current test coverage includes basic end-to-end install and run tests, integration tests specifically for the composefs-backend feature, and initramfs tests that validate composefs cmdline handling. However, we need additional coverage for upgrade paths (especially fsverity transitions), rollback scenarios with various failure modes, multi-boot configurations, performance regression detection, and security validation.

## Timeline Considerations

For the immediate next release, the priority is addressing the fsverity upgrade path, documenting known limitations clearly, and improving error messages for common issues. In the short term (1-2 releases), we should implement upper layer integrity verification, unify logically bound images storage, and expand test coverage. Long-term work includes performance optimizations, enhanced observability, and upstream coordination with ostree for integration cleanup.

## Migration Notes

For users, composefs is now enabled by default in new installations, though existing ostree-based systems continue to work without changes. An opt-in upgrade path is available, with the caveats noted in the fsverity upgrade section above. Fsverity functionality requires filesystem support, which is available in ext4, xfs, and btrfs.

For developers, the `composefs-backend` feature is now default-enabled. Storage operations should use the `ComposefsRepository` trait, and new features should follow the patterns established in the `bootc_composefs/` modules. When changing prepare-root.conf, remember that initramfs regeneration is required for the changes to take effect.

## References

Key commits in the composefs integration include `87d1d391` (enable composefs by default), `f4c678eb` (various enhancements including UKI detection and systemd-boot), `19e82be8` (merge PR #1444 adding the composefs backend), `a6d88617` (rename 'composefs-native' to 'composefs-backend'), and `26619ee4` (add composefs options to install-to-existing-root).

Related documentation can be found in docs/src/filesystem.md (comprehensive filesystem documentation), docs/src/bootloaders.md (bootloader integration), and docs/src/man/bootc.8.md (man page with composefs information).

External resources include the composefs project at https://github.com/composefs/composefs, the ostree composefs backend documentation at https://ostreedev.github.io/ostree/composefs/, and issue #1190 tracking upper layer integrity verification.

## Notes

This is a living document and should be updated as work progresses. The composefs integration represents a significant architectural evolution for bootc, moving toward a more native container-based storage model while maintaining compatibility with existing ostree-based deployments.
