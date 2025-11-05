use std assert
use tap.nu

tap begin "composefs integration smoke test"

# Detect composefs by checking if composefs field is present
let st = bootc status --json | from json
let is_composefs = ($st.status.booted.composefs? != null)

if not $is_composefs {
    # When not on composefs, run the full test including initialization
    bootc internals test-composefs
}

# These tests work on both composefs and non-composefs systems
bootc internals cfs --help
bootc internals cfs oci pull docker://busybox busybox
test -L /sysroot/composefs/streams/refs/busybox

tap ok
