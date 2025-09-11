# Build the container image from current sources
build *ARGS:
    podman build --jobs=4 -t localhost/bootc {{ARGS}} .

# This container image has additional testing content and utilities
build-integration-test-image *ARGS:
    podman build --jobs=4 -t localhost/bootc-integration -f hack/Containerfile {{ARGS}} .
    # Keep these in sync with what's used in hack/lbi
    podman pull -q --retry 5 --retry-delay 5s quay.io/curl/curl:latest quay.io/curl/curl-base:latest registry.access.redhat.com/ubi9/podman:latest

# Only used by ci.yml right now
build-install-test-image: build-integration-test-image
    cd hack && podman build -t localhost/bootc-integration-install -f Containerfile.drop-lbis

# Run container integration tests
run-container-integration: build-integration-test-image
    podman run --rm localhost/bootc-integration bootc-integration-tests container

# These tests may spawn their own container images.
run-container-external-tests:
   ./tests/container/run localhost/bootc

unittest *ARGS:
    podman build --jobs=4 --target units -t localhost/bootc-units --build-arg=unitargs={{ARGS}} .

# Update all generated files (man pages and JSON schemas)
#
# This is the unified command that:
# - Auto-discovers new CLI commands and creates man page templates
# - Syncs CLI options from Rust code to existing man page templates  
# - Updates JSON schema files
#
# Use this after adding, removing, or modifying CLI options or schemas.
update-generated:
    cargo run -p xtask update-generated
