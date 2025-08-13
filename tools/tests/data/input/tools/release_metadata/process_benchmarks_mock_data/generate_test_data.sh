#!/bin/bash

set -e

SCRIPT_DIR=$(dirname $(readlink -f $0))

echo "Generating mock profiles, controls, datastreams"

for cac_tag in $(grep cac_tag: "${SCRIPT_DIR}"/../*yml | awk '{print $4}')
do
    echo "Processing ${cac_tag}"
    cp -r "${SCRIPT_DIR}/data_template" "${SCRIPT_DIR}/${cac_tag}"
done
