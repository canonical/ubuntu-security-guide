#!/bin/bash

# project, source, data dirs
SCRIPT_DIR=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
PROJECT_DIR=${SCRIPT_DIR}/..

echo "Initializing container..."
podman build -t usg_test_image -f - ${PROJECT_DIR} >/dev/null  <<EOF
FROM ubuntu:24.04

RUN apt update > /dev/null

# runtime deps
RUN apt install -y openscap-scanner python3 bash-completion bsdextrautils > /dev/null

# built/testing deps
RUN apt install -y python3-pytest python3-yaml python3-coverage python3-lxml python3-requests pybuild-plugin-pyproject

# tools
RUN apt install -y vim-tiny less 

# copy project dir
COPY ./ /root/usg/

# copy test benchmark data
RUN cp -r /root/usg/tools/tests/data/expected/benchmarks/ /usr/share/usg-benchmarks/

# install usg module, wrapper, config, and bash completion
RUN cd /root/usg \
    && rm -rf .pybuild \
    && pybuild --install-dir /usr/share/usg --dest-dir / \
    && cp -r /root/usg/src/legacy /usr/share/usg \
    && cp /root/usg/sbin/usg /sbin/usg \
    && mkdir -p /var/lib/usg \
    && chmod 0700 /var/lib/usg \
    && cp /root/usg/etc/usg.conf /etc/usg.conf \
    && cp /root/usg/debian/usg.bash-completion /usr/share/bash-completion/completions/usg
    
WORKDIR /root/usg

EOF
if [[ $? -ne 0 ]]; then
    echo "Error creating container"
    exit 1
fi

echo "Starting shell on container... "
echo "Run 'usg'"
echo
podman run -it usg_test_image /bin/bash --login
