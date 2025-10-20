#!/bin/bash

set -e

SCRIPT_DIR=$(dirname $(readlink -f $0))

echo "Generating mock profiles, controls, datastreams"

for cac_tag in $(grep -H cac_tag: "${SCRIPT_DIR}"/../*yml | awk '{print $4}')
do
    echo "Processing ${cac_tag}"
    cp -r "${SCRIPT_DIR}/data_template/ComplianceAsCode-content" "${SCRIPT_DIR}/${cac_tag}"
done
