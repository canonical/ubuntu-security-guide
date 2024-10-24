#!/bin/bash

help="
This script builds CaC content, runs the USG build script,
and creates the usg/usg-benchmarks-N deb packages with umt.

It should be run in a directory which contains both
ComplianceAsCode-content and ubuntu-security-guide repositories,
both in correct respective branches (e.g. focal and 20.04.20-dev,
focal and 20.04.21-dev, jammy and 22.04.8-dev, ...).

Requirements:
 - LXD installed and initialled
   (sudo snap install lxd; sudo lxd init --mininal)
 - ComplianceAsCode-Content repository in cwd
 - ubuntu-security-guide repository in cwd
 - umt (see Security Team BuildEnv instructions)
 - access to github via ssh

Usage: $0 usg_version build_product
    
Args:
- usg_version: refers to the to-be-relased version of USG
               (20.04.20 if 20.04.19 is the last release) and should
               be the same as the version in the name of the
               development branch of ubuntu-security-guide
               (e.g. 20.04.20-dev).

- build_product: CaC product that should be built
                 (ubuntu2004, ubuntu2204, ...)
"

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
    echo "$help"
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
$ chmod +w -R "${CAC_DIR}" "${USG_DIR}"
$ rm -rf ${BUILD_DIR}
"
fi

v=$(grep "^version=" "${USG_DIR}/tools/build_config.ini" | awk -F= '{print $2}' || echo None)
if [[ "${usg_version}" != "${v}" ]]; then
    err "USG version in ${USG_DIR}/tools/build_config.ini is $v but should be '${usg_version}'"
fi

t=$(grep "^target=" "${USG_DIR}/tools/build_config.ini" | awk -F= '{print $2}' || echo None)
if [[ "${build_product}" != "${t}" ]]; then
    err "Build product (target) in ${USG_DIR}/tools/build_config.ini is $t but should be '${build_product}'"
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
if lxc info "${build_host}" &>/dev/null; then
    lxc rm --force "${build_host}"
fi
lxc launch "${LXD_BUILD_IMAGE}" "${build_host}"
sleep 3


h1 "Installing dependencies and setting up build user"
lxc exec "${build_host}" -- bash <<EOF
set -Eeuo pipefail

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
pushd "${BUILD_DIR}" >/dev/null
lxc file pull "${build_host}/tmp/builds.tar.gz" ./
tar -xf builds.tar.gz
sha256sum builds.tar.gz | tee SHA256SUM
popd >/dev/null


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
