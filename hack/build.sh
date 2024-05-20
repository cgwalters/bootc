#!/bin/bash
set -xeu
. /usr/lib/os-release
case $ID in
  centos|rhel) dnf config-manager --set-enabled crb;;
  fedora) dnf -y install dnf-utils ;;
esac
dnf -y builddep bootc
