# A simple nushell "library" for the

# This is a workaround for what must be a systemd bug
# that seems to have appeared in C10S
# TODO diagnose and fill in here
export def reboot [] {
    # Sometimes systemd daemons are still running old binaries and response "Access denied" when send reboot request
    # Force a full sync before reboot
    sync
    # Allow more delay for bootc to settle
    sleep 30sec

    tmt-reboot
}
