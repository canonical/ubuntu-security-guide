#!/bin/bash
#
# Ubuntu Security Guide
# Copyright (C) 2025 Canonical Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.


# project, source, data dirs
SCRIPT_DIR=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
PROJECT_DIR=${SCRIPT_DIR}/..
UBUNTU_RELEASE=${1:-noble}

build_container() {
    ubuntu_release=$1

    # setup.cfg is needed on jammy due to setuptools<61.0
    jammy_setup_cfg=$(mktemp -p "${PROJECT_DIR}")
    cat > "$jammy_setup_cfg" <<EOF
[metadata]
name = usg
version = 22.04.12

[options]
packages = find:
package_dir =
    = src
include_package_data = True

[options.packages.find]
where = src
EOF

    # release-specific vars
    case "$ubuntu_release" in
        "noble")
            base_img="ubuntu:24.04"
            oscap_deps="openscap-scanner"
            product="ubuntu2404"
            pre_commands=""
            post_commands=""
            ;;
        "jammy")
            base_img="ubuntu:22.04"
            oscap_deps="libopenscap8"
            product="ubuntu2204"
            pre_commands="COPY $(basename $jammy_setup_cfg) /root/usg/setup.cfg"  # install setup.cfg
            post_commands="RUN sed 's/2404/2204/g' -i /etc/usg.conf /usr/share/usg/legacy/usg"  # fix product
            ;;
        *)
            echo "Product $PRODUCT not supported."
            exit 1
    esac
    img_name=usg_test_$product


    echo "Building image $img_name..."
    podman build -t $img_name -f - ${PROJECT_DIR} >/dev/null  <<EOF
FROM $base_img

RUN apt update

# runtime deps
RUN apt install -y $oscap_deps python3 bash-completion bsdextrautils

# built/testing deps
RUN apt install -y python3-pytest python3-yaml python3-coverage python3-lxml python3-requests pybuild-plugin-pyproject python3-setuptools

# tools
RUN apt install -y vim-tiny less 

# copy project dir
COPY ./ /root/usg/

# run pre-install fixes
$pre_commands

# copy test benchmark data
RUN cp -r /root/usg/tests/data/$product/expected/benchmarks/ /usr/share/usg-benchmarks/

# install usg module, wrapper, config, and bash completion
RUN cd /root/usg \
    && rm -rf .pybuild /usr/share/usg \
    && pybuild --install-dir /usr/share/usg --dest-dir / 2>/root/pybuild.log \
    && cp -r ./src/legacy /usr/share/usg \
    && cp ./src/cli/usg /usr/sbin/usg \
    && mkdir -p /var/lib/usg \
    && chmod 0700 /var/lib/usg \
    && cp ./conf/usg.conf /etc/usg.conf \
    && mkdir -p /etc/logrotate.d \
    && cp ./conf/logrotate.d/usg /etc/logrotate.d/ \
    && cp ./debian/usg.bash-completion /usr/share/bash-completion/completions/usg

# run post-install fixes
$post_commands

WORKDIR /root/usg

CMD ["bash", "--login"]
EOF

    rm -f $jammy_setup_cfg

    if [[ $? -ne 0 ]]; then
        echo "Error creating container"
        exit 1
    fi
}

run_cmd() {
    podman run --rm $img_name "${@}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    build_container $UBUNTU_RELEASE
    echo "Starting shell on container... "
    echo "Run 'usg'"
    echo
    podman run -it --rm $img_name
fi
