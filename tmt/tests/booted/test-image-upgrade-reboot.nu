# number: 24
# tmt:
#   summary: Execute local upgrade tests
#   duration: 30m
#
# This test does:
# bootc image copy-to-storage
# podman build <from that image>
# bootc switch <into that image> --apply
# Verify we boot into the new image
#
use std assert
use tap.nu

# This code runs on *each* boot.
# Here we just capture information.
bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

# Parse the kernel commandline into a list.
# This is not a proper parser, but good enough
# for what we need here.
def parse_cmdline []  {
    open /proc/cmdline | str trim | split row " "
}

# Run on the first boot
def initial_build [] {
    tap begin "local image push + pull + upgrade"

    bootc image copy-to-storage

    # A simple derived container that adds a file
    "FROM localhost/bootc
RUN touch /usr/share/testing-bootc-upgrade-apply
" | save Dockerfile
    # Build it
    podman build -t localhost/bootc-derived .

    # Now, switch into the new image
    tmt-reboot -c "bootc switch --apply --transport containers-storage localhost/bootc-derived"

    # We cannot perform any other checks here since the system will be automatically rebooted
}

# Check we have the updated image
def second_boot [] {
    print "verifying second boot"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image localhost/bootc-derived

    # Verify the new file exists
    "/usr/share/testing-bootc-upgrade-apply" | path exists

    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
