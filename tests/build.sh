#!/bin/bash
set -exuo pipefail

# This script basically builds bootc from source using the provided base image,
# then runs the target tests.

# If provided should be of the form fedora-42 or centos-10
target=${1:-}
build_args=()
if test -n "${target:-}"; then
    shift
    # Get OS info from TEST_OS env
    OS_ID=$(echo "$target" | cut -d '-' -f 1)
    OS_VERSION_ID=$(echo "$target" | cut -d '-' -f 2)

    # Base image
    case "$OS_ID" in
        "centos")
            BASE="quay.io/centos-bootc/centos-bootc:stream${OS_VERSION_ID}"
        ;;
        "fedora")
            BASE="quay.io/fedora/fedora-bootc:${OS_VERSION_ID}"
        ;;
        *) echo "Unknown OS: ${OS_ID}" 1>&2; exit 1
        ;;
    esac
    build_args+=("--build-arg=base=$BASE")
fi

just build ${build_args[@]}
just build-integration-test-image

# Host builds will have this already, but we use it as a general dumping space
# for output artifacts
mkdir -p target
just build-disk-image localhost/bootc-integration target/bootc-integration-test.qcow2
