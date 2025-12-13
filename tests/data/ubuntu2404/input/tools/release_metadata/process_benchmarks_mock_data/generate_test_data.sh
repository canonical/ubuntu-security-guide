#!/bin/bash

set -e

SCRIPT_DIR=$(dirname $(readlink -f $0))
cd "$SCRIPT_DIR"

echo "Generating mock profiles, controls, datastreams"
for cac_tag in $(grep -H cac_tag: "${SCRIPT_DIR}"/../*yml | awk '{print $4}')
do
    echo "Processing ${cac_tag}"
    ln -sf "./data_template/ComplianceAsCode-content" "./${cac_tag}"
done
