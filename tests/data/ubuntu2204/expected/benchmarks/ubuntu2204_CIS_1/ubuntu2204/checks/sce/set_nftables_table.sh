#!/bin/bash
#
#

tbl_output=$(nft list tables)
if [ -z "${tbl_output}" ]; then
    exit ${XCCDF_RESULT_FAIL}
fi

exit ${XCCDF_RESULT_PASS}
