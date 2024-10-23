#!/bin/bash

# This script builds CaC content, runs the USG build script,
# and creates the deb package with umt
#
# It runs the CaC/USG build in a LXC container thus it requires
# that LXD is installed and initialized.
# $ sudo snap install lxd
# $ sudo lxd init --minimal
#

set -Eeuo pipefail

CAC_DIR=ComplianceAsCode-content
USG_DIR=ubuntu-security-guide
BUILD_DIR=build
LXD_BUILD_IMAGE="ubuntu:22.04"
CAC_DEPS="cmake make python3-jinja2 python3-yaml xsltproc expat libxml2-utils"
USG_DEPS="python3-lxml python3-ruamel.yaml libopenscap8"
ALLOWED_CAC_BRANCHES="focal jammy"

LOG_NAME=log.$(date -Is)

confirm_last_commit() {
    echo
    git log -1 --stat
    echo
    echo ">>>> Does the above last commit look ok? [y/N]"
    read a
    if [[ "$a" != "y" ]]; then
        echo "Exiting..."
        exit 1
    fi
}

h1() {
    echo -e "\n=============== $@ ===============\n" >&2
}

err() {
    echo -e "\nERROR: $@\n" >&2
    exit 1
}

check_status() {
    branch=$1; remote=$2

    s=$(git status --porcelain)
    if [[ -n "$s" ]]; then
        err "Uncommited changes in ${PWD}:\n$s"
        return 1
    fi

    git fetch "${remote}" --quiet
    s=$(git diff-index "${remote}/${branch}")
    if [[ -n "$s" ]]; then
        err "Local branch ${branch} is not same as ${remote}/${branch}\n$s"
        return 1
    fi
}


# script starts here
if [[ $# != 2 ]]; then
    echo "Usage: $0 usg_version build_product"
    exit 1
fi

usg_version=$1
build_product=$2

if [[ ! -d "${CAC_DIR}/.git" || ! -d "${USG_DIR}/.git" ]]; then
    err "\
This script should be executed in a directory containing these repositories:

${CAC_DIR}
${USG_DIR}"
fi

if [[ ! -w "${CAC_DIR}" || ! -w "${USG_DIR}" || -e "${BUILD_DIR}" ]]; then
    err "\
Build exists... To force rebuild:
$ chmod +w -R $(realpath $(dirname ${BASH_SOURCE[0]}))
$ rm -rf ${BUILD_DIR}
"
fi

cac_branch=$(cd "${CAC_DIR}" && git rev-parse --abbrev-ref HEAD)
usg_branch=$(cd "${USG_DIR}" && git rev-parse --abbrev-ref HEAD)

if ! echo "${ALLOWED_CAC_BRANCHES}" | grep -wq "${cac_branch}"; then
    err "CaC branch name is '${cac_branch}' but should be in '${ALLOWED_CAC_BRANCHES}'"
fi

if [[ "${usg_branch}" != "${usg_version}-dev" ]]; then
    err "USG branch name is '${usg_branch}' but should be '${usg_version}-dev'"
fi

# log all output to file
exec &> >(tee "${LOG_NAME}")

h1 "Sanity checking and cleaning repos"
pushd "${CAC_DIR}" >/dev/null
check_status ${cac_branch} internal
confirm_last_commit
git clean -fxd
popd >/dev/null

pushd "${USG_DIR}" >/dev/null
check_status ${usg_branch} origin
confirm_last_commit
git clean -fxd
popd >/dev/null


h1 "Launching build host"
build_host="usg-${cac_branch}"
lxc rm --force "${build_host}" >/dev/null || true
lxc launch "${LXD_BUILD_IMAGE}" "${build_host}"


h1 "Installing dependencies and setting up build user"
lxc exec "${build_host}" -- bash <<EOF
apt update
apt -y upgrade
apt -y install ${CAC_DEPS} ${USG_DEPS}
useradd builduser -u 1234 -m -s /bin/bash
EOF


h1 "Copying files"
tar -czf tmp.tar.gz --exclude=".git" "${CAC_DIR}" "${USG_DIR}"
lxc file push --uid 1234 tmp.tar.gz "${build_host}/"
rm -f tmp.tar.gz


h1 "Building CaC content and USG data"
lxc exec "${build_host}" -- bash <<EOF
set -Eeuo pipefail

sudo -i -u builduser -- bash <<EOC

mkdir build && cd build
tar -xvf /tmp.tar.gz

pushd ${CAC_DIR}
export ADDITIONAL_CMAKE_OPTIONS="-DSSG_SCE_ENABLED:BOOL=ON"
./build_product -j4 "${build_product}" -o'5.11'
popd

pushd ${USG_DIR}
python3 tools/build.py
popd

tar -czf /tmp/builds.tar.gz ./
EOC

EOF


h1 "Fetching build data..."
mkdir -p "${BUILD_DIR}"
lxc file pull "${build_host}/tmp/builds.tar.gz" "${BUILD_DIR}/"
tar -xf "${BUILD_DIR}/builds.tar.gz" -C "${BUILD_DIR}"
sha256sum builds.tar.gz | tee SHA256SUM
echo ok


h1 "Building debian package (see ${LOGNAME}.umt)"
pushd "${BUILD_DIR}/${USG_DIR}" >/dev/null
umt build -f -s --skip-maintainer >> "${LOGNAME}.umt"
popd >/dev/null
# TODO create test script with the correct paths based on a template


h1 "Locking dirs..."
chmod -w -R "${CAC_DIR}" "${USG_DIR}" "${BUILD_DIR}"


h1 "Cleaning up"
lxc rm --force "${build_host}" || true


cat <<EOF

Done!  Don't forget to:

1. Sign the deb package
2. Test the deb package
3. Open a PR for next USG release, describing the changes:
   https://github.com/canonical/ubuntu-security-guide/compare/${cac_branch}...${usg_branch}
4. Push tags to internal CaC and USG:

cd ${CAC_DIR}
git tag -f 'usg-${usg_version}'
git push -f --tags"

cd ${USG_DIR}"
git tag -f 'v${usg_version}'
git push -f --tags"

EOF
