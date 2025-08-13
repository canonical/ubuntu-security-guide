#!/usr/bin/env python3

import base64
import json
import yaml
import hashlib
import logging
import tempfile
import sys
import gzip
from pathlib import Path
import argparse
import shutil
import requests
from typing import List, Dict, Any

from generate_tailoring_file import generate_tailoring_file, validate_tailoring_file

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
OUTPUT_JSON_NAME = "benchmarks.json"
CAC_RELEASE_GZ_NAME = "ssg-{}-ds.xml.gz"
CAC_TAILORING_NAME = "{}-tailoring.xml"

class BenchmarkProcessingError(Exception):
    pass

def find_release_upgrade_paths(
        all_releases: List[Dict[str, Any]]
    ) -> None:
    # Search through release graph and map upgrade_paths
    #
    # For each release, these items are added to the object, in-place:
    # - compatible: list of releases which are compatible with the current release (starting at the nearest parent breaking release and ending at latest compatible release)
    # - latest_compatible: reference to the latest compatible release:
    #      - the latest release in a branch (B1, D2, or H in below graph) or
    #      - the latest release which precede a breaking release (F in below graph)
    # - next_breaking: reference to the next breaking release, if any
    #
    # E.g. looking at below graph, the function would map this to the release objects, into the dictionary "upgrade_paths":
    #
    #   A:  {"compatible": (A, B, B1),     "latest_compatible": B1, "next_breaking": C    },
    #   B:  {"compatible": (A, B, B1),     "latest_compatible": B1, "next_breaking": C    },
    #   B1: {"compatible": (A, B, B1),     "latest_compatible": B1, "next_breaking": C    },
    #   C:  {"compatible": (C, D, D1, D2), "latest_compatible": D2, "next_breaking": E    },
    #   D2: {"compatible": (C, D, D1, D2), "latest_compatible": D2, "next_breaking": E    },
    #   F:  {"compatible": (E, F),         "latest_compatible": F,  "next_breaking": G    },
    #   H:  {"compatible": (G, H),         "latest_compatible": H,  "next_breaking": None }
    #
    # (D,D1,E,G not shown)
    #
    #
    #    H (latest)
    #    |
    #    G (breaking)
    #  --|--
    #    F
    #    |
    #    E (breaking)
    #  --|--
    #    D - D1 - D2
    #    |
    #    C (breaking)
    #  --|--
    #    B - B1
    #    |
    #    A (initial)
    #
    #
    # The release graph must have:
    # - a main branch containing breaking and non-breaking releases and ending with the latest release
    # - side branching only prior to a breaking release (e.g. at B, D, and F in above graph)
    # - side branches which can contain only *non-breaking* releases
    #
    logger.debug("Entered get_release_upgrade_paths()")

    # initialize new vars
    for release in all_releases:
        release.update({
            "upgrade_paths": {
                "compatible": [],
                "latest_compatible": None,
                "next_breaking": None,
                }})

    # find initial release
    initial_release = None
    for release in all_releases:
        if not release["parent_tag"]:
            if initial_release:
                raise BenchmarkProcessingError(
                    f"Error - found two initial releases (without parent_tag): "
                    f"{release['cac_tag']}, {initial_release['cac_tag']}"
                    )
            initial_release = release
    logger.debug(f"Found initial release: {initial_release['cac_tag']}")

    # initialize the search queue and upgrade paths
    queue = [initial_release,]
    initial_release["upgrade_paths"].update({
        "compatible": [initial_release,]
        })

    # search
    while queue:
        release = queue.pop()
        cac_tag = release['cac_tag']

        logger.debug(f"Looking for children of {cac_tag}")

        # get children of release
        children = [r for r in all_releases if r["parent_tag"] == cac_tag]

        if len(children) > 2:
            raise BenchmarkProcessingError(
                f"Error - release {cac_tag} has more than two children."
                )

        # count number of children which are breaking releases and ensure the count is 1
        nbreaking = [c["breaking_release"] for c in children].count(True)
        if len(children) == 2 and nbreaking != 1:
            raise BenchmarkProcessingError(
                f"Error - release {cac_tag} has two children out of which {nbreaking} "
                f"are breaking. Exactly 1 should be breaking."
                )

        # add child releases to queue and create upgrade path lists
        for i, child in enumerate(children):
            child_cac_tag = child['cac_tag']
            logger.debug(f"Found child ({i+1} of {len(children)}) of {cac_tag}: {child_cac_tag}.")

            # add child to search queue
            queue.insert(0, child)

            # if child is a breaking release
            if child["breaking_release"]:
                logger.debug(f"Release {child_cac_tag} is breaking.")
                # sanity check that the tailoring version for a breaking release is exactly 1 greater than the parent
                if child["tailoring_version"] != release["tailoring_version"] + 1:
                    raise BenchmarkProcessingError(
                        f"Error - tailoring_version of breaking child {child['cac_tag']} "
                        f"should be exactly 1 greater than its parent {release['cac_tag']}"
                        )
                # reset the compatible upgrade path for the child
                child["upgrade_paths"]["compatible"] = [child,]
                # set the child as the next_breaking for the parent
                release["upgrade_paths"]["next_breaking"] = child

            # else, the child is non-breaking
            else:
                logger.debug(f"Release {child_cac_tag} is non-breaking.")
                # sanity check that the tailoring version for a non-breaking release is the same as the parent
                if child["tailoring_version"] != release["tailoring_version"]:
                    raise BenchmarkProcessingError(
                        f"Error - tailoring_version of non-breaking child {child['cac_tag']} "
                        f"should be same as parent {release['cac_tag']}"
                        )
                # add the child to the compatible upgrade path of the parent
                release["upgrade_paths"]["compatible"].append(child)
                # copy the compatible upgrade path of the parent to the child
                child["upgrade_paths"]["compatible"] = release["upgrade_paths"]["compatible"]


        # if the release has no children or one child which is a breaking release
        # mark it as the latest compatible release for all releases in its compatible upgrade path
        if not children or (len(children) == 1 and nbreaking == 1):
            logger.debug(f"Release {cac_tag} is latest compatible in its branch.")

            # set latest compatible release for all releases in the compatible upgrade path
            for r in release["upgrade_paths"]["compatible"]:
                r["upgrade_paths"]["latest_compatible"] = release


    # Now that we have all the upgrade paths and references to "latest_compatible" releases,
    # set "next_breaking" for all the releases in the compatible upgrade path
    for release in all_releases:
        if release["upgrade_paths"]["next_breaking"]: # the release is a parent of a breaking release
            for r in release["upgrade_paths"]["compatible"]:
                r["upgrade_paths"]["next_breaking"] = release["upgrade_paths"]["next_breaking"]

    # Debug print
    logger.debug("--- Listing upgrade paths and candidates")
    for release in all_releases:
        logger.debug(f"Release: {release['cac_tag']}")
        logger.debug("Non-breaking compatible upgrade path:")
        for j, r in enumerate(release["upgrade_paths"]["compatible"]):
            logger.debug(f"  {j+1}: {r['cac_tag']}")
        latest_compatible = release["upgrade_paths"]["latest_compatible"]
        logger.debug(f"Latest compatible: {latest_compatible['cac_tag']}")
        if release["upgrade_paths"]["next_breaking"]:
            next_breaking = release["upgrade_paths"]["next_breaking"]
            next_breaking_lc = next_breaking["upgrade_paths"]["latest_compatible"]
            logger.debug(f"Next breaking: {next_breaking['cac_tag']}")
            logger.debug(f"Next breaking (latest_compatible): {next_breaking_lc['cac_tag']}")
        else:
            logger.debug("Next breaking: None (latest)")
        logger.debug("---")


def process_yaml(
        yaml_data: Dict[str, Any],
        templates_dir: Path,
        github_pat_token: str,
        test_data_dir: Path,
        work_dir: Path
    ) -> List[Dict[str, Any]]:
    # Process CaC release yaml configuration file

    # - generate benchmark IDs used in USG
    # - for each latest "active" release in each branch:
    #   - map compatibility with older releases
    #   - generate complete breaking upgrade path
    #   - download release datastream
    #   - generate tailoring files and whatever else is needed
    # - return "benchmarks" list containing metadata, file lists and checksums

    # Initial iteration over the releases:
    # - initialize several empty fields and generate benchmark_id
    logger.debug("Entered process_yaml()")

    all_releases = sorted(yaml_data["benchmark_releases"], key = lambda x: x["usg_version"] + x['cac_tag'])
    for release in all_releases:
        b_data = {}
        b_data.update(yaml_data["general"])
        b_data.update(release["benchmark_data"])
        benchmark_id = "{}_{}_{}".format(
                b_data["product"],
                b_data["benchmark_type"],
                release["tailoring_version"]
                )
        b_data.update({
            "benchmark_id": benchmark_id,
            "compatible_versions": [],
            "breaking_upgrade_path": [],
            "is_latest": False
            })
        release["benchmark_data"] = b_data

    # Traverse release graph and find all upgrade paths
    find_release_upgrade_paths(all_releases)

    # Extract only active releases (latest in any side branch or latest preceding a breaking release)
    active_releases = [r for r in all_releases if r == r["upgrade_paths"]["latest_compatible"]]
    active_releases.sort(key = lambda r: r["benchmark_data"]["benchmark_id"])
    logger.debug("Found these active releases (latest in any side branch or latest preceding a breaking release):")
    for r in active_releases:
        logger.debug(f"{r['cac_tag']} (id: {r["benchmark_data"]["benchmark_id"]})")

    # Quick sanity check for tailoring versions (should be all from 1 to max())
    tailoring_versions = sorted([r["tailoring_version"] for r in active_releases])
    tailoring_versions_good = list(range(1, max(tailoring_versions)+1))
    if tailoring_versions != tailoring_versions_good:
        raise BenchmarkProcessingError(
            f"Corrupt release file. Found tailoring versions {tailoring_versions}. "
            f"Should be {tailoring_versions_good}"
            )

    # For each active release
    # - find all superseded compatible releases and mark their benchmark_id as compatible to the latest release
    # - find all superseeding breaking releases and generate the breaking_upgrade_path
    # - fetch datastream, generate tailoring files, generate checksums
    benchmarks_metadata = []
    for release in active_releases:
        cac_tag = release["cac_tag"]
        b_data = release["benchmark_data"]
        benchmark_id = b_data["benchmark_id"]
        next_breaking_release = release["upgrade_paths"]["next_breaking"]

        logger.debug(f"Processing active release {release['cac_tag']}")

        # get superseded compatible releases
        b_data["compatible_versions"] = _get_superseded_compatible(release)

        if next_breaking_release is not None:
            b_data["breaking_upgrade_path"] = _get_breaking_upgrade_path(release, all_releases)
        else:
            logger.debug(f"Release {cac_tag} is the latest release.")
            b_data["is_latest"] = True

        # Get the actual benchmark data and files
        _process_benchmark_files(release, work_dir, templates_dir, github_pat_token, test_data_dir)

        benchmarks_metadata.append(b_data)

    logger.debug("--- Listing benchmarks")
    for b in benchmarks_metadata:
        logger.debug(f"Benchmark: {b['benchmark_id']}")

    logger.debug("Exiting process_yaml()")

    return benchmarks_metadata


def _get_superseded_compatible(
        release: Dict[str, Any],
    ) -> List[str]:
    # Return the list of releases which are superseded by the given release and
    # which are compatible with it (non-breaking)
    logger.debug(f"From _get_superseded_compatible({release['cac_tag']})")

    compatible_versions = set()
    for r in release["upgrade_paths"]["compatible"]:
        if r != release:
            benchmark_version = r["benchmark_data"]["version"]
            logger.debug(f"Found superseded release with benchmark version: {benchmark_version} (cac_tag: {r['cac_tag']}).")
            if benchmark_version == release["benchmark_data"]["version"]:
                logger.debug("benchmark version is the same as active release. Not adding it to list of compatible_versions")
            else:
                logger.debug(f"Adding the release with benchmark version {benchmark_version} to list of compatible_versions in benchmark in release {release['cac_tag']}")
                compatible_versions.add(benchmark_version)
    return sorted(list(compatible_versions))


def _get_breaking_upgrade_path(
        release: Dict[str, Any],
        all_releases: List[Dict[str, Any]]
    ) -> List[str]:
    # return the list of all breaking releases superseding given releases

    logger.debug(f"From _get_breaking_upgrade_path({release['cac_tag']})")

    def _get_breaking_list(
        r: Dict[str, Any]
        ) -> List[Dict[str, Any]]:
        # recursive search for successive breaking releases
        # returns succession in reverse order (from newest to oldest release)
        if r["upgrade_paths"]["next_breaking"]:
            for r_next in all_releases:
                if r_next == r["upgrade_paths"]["next_breaking"]:
                    yield from _get_breaking_list(r_next)
        yield r

    next_breaking = release["upgrade_paths"]["next_breaking"]
    next_breaking_latest_compatible = next_breaking["upgrade_paths"]["latest_compatible"]

    logger.debug(f"Release can be upgraded to the next breaking release with version: "
                 f"{next_breaking_latest_compatible['benchmark_data']['version']} "
                 f"({next_breaking_latest_compatible['cac_tag']})")

    breaking_succession = list(_get_breaking_list(next_breaking))[::-1]

    logger.debug(f"Printing full upgrade path for release {release['cac_tag']}:")
    breaking_upgrade_path = []
    for i, breaking_release in enumerate(breaking_succession):
        breaking_latest_compatible = breaking_release["upgrade_paths"]["latest_compatible"]
        breaking_cac_tag = breaking_latest_compatible["cac_tag"]
        breaking_benchmark_version = breaking_latest_compatible["benchmark_data"]["version"]
        breaking_upgrade_path.append(breaking_benchmark_version)
        logger.debug(f"  {i+1}: {breaking_benchmark_version} ({breaking_cac_tag})")
    return breaking_upgrade_path


def _request_url(
        url: str,
        headers: Dict[str, str]
    ) -> requests.Response:
    # request a URL, exit on error, return the response
    r = requests.get(url, headers=headers)
    logger.debug(f"Requesting {url}...")
    if r.status_code == 401:
        raise BenchmarkProcessingError(
            f"Failed to authenticate when requesting {url}. "
            f"Likely bad PAT token. Response: {r.text}"
            )
    elif r.status_code != 200:
        raise BenchmarkProcessingError(
            f"Failed to get {url}. Response: {r.text}"
            )
    logger.debug(f"Status code: {r.status_code}. Response headers: {r.headers}")
    return r


def _download_github_release_datastream(
        cac_tag: str,
        github_pat_token: str,
        download_dir: Path
    ) -> None:
    # download release datastream from Github

    logger.debug(f"From _download_github_release_datastream({cac_tag})")
    logger.info(f"Downloading datastream for {cac_tag} from Github to {download_dir}...")

    # get datastream asset information based on the release tag
    url = f"https://api.github.com/repos/canonical/ComplianceAsCode-content/releases/tags/{cac_tag}"
    headers = {
            "Authorization": f"Bearer {github_pat_token}",
            "Accept": "application/vnd.github+json"
            }
    r = _request_url(url, headers)
    datastream_url, datastream_name = [(asset["url"],asset["name"]) for asset in r.json()["assets"] if "xml.gz" in asset["name"]][0]
    
    # download datastream asset
    headers = {
            "Authorization": f"Bearer {github_pat_token}",
            "Accept": "application/octet-stream"
            }
    r = _request_url(datastream_url, headers)
    ds_path = download_dir / datastream_name
    open(ds_path, "wb").write(r.content)
    logger.debug(f"Downloaded datastream from Github to {ds_path}")
    logger.debug("Exiting _download_github_release_datastream()")


def _download_github_release_profiles(
        cac_tag: str,
        cac_commit: str,
        product: str,
        github_pat_token: str,
        download_dir: Path
    ) -> None:
    # download profile and control files from Github corresponding to the release tag

    logger.debug(f"From _download_github_release_profiles({cac_tag})")
    logger.info(f"Downloading files for {cac_tag} from Github to {download_dir}...")
    headers = {
            "Authorization": f"Bearer {github_pat_token}",
            "Accept": "application/vnd.github+json"
            }
    # get tag hash based on tag name
    url = f"https://api.github.com/repos/canonical/ComplianceAsCode-content/git/refs/tags/{cac_tag}"
    r = _request_url(url, headers)
    tag_hash = r.json()["object"]["sha"]
    
    # get commit hash associated with the tag
    url = f"https://api.github.com/repos/canonical/ComplianceAsCode-content/git/tags/{tag_hash}"
    r = _request_url(url, headers)
    commit_hash = r.json()["object"]["sha"]
    
    # sanity check that the commit hash is the same as the one in the yaml file
    if cac_commit != commit_hash:
        raise BenchmarkProcessingError(
            f"Commit hash {commit_hash} for tag {cac_tag} does not match the one in the yaml file {cac_commit}"
            )

    # get profile files information based on the commit hash
    url = f"https://api.github.com/repos/canonical/ComplianceAsCode-content/contents/products/{product}/profiles?ref={commit_hash}"
    r = _request_url(url, headers)
    profile_files = r.json()

    # get control files information based on the commit hash
    url = f"https://api.github.com/repos/canonical/ComplianceAsCode-content/contents/controls?ref={commit_hash}"
    r = _request_url(url, headers)
    # TODO: in principle the control files could be named anything.
    # Here we assume they follow the naming convention of the product.
    control_files = [c for c in r.json() if product in c["path"]]

    # download profile and control files
    for file in profile_files + control_files:
        name, path, url = file["name"], file["path"], file["url"]
        logger.debug(f"Downloading file {name} from {url}...")
        r = _request_url(url, headers)
        
        full_path = download_dir / "ComplianceAsCode-content" / path
        full_path.parent.mkdir(parents=True, exist_ok=True)

        open(full_path, "wb").write(base64.b64decode(r.json()["content"]))
        logger.debug(f"Downloaded file {name} to {full_path}")

    logger.debug("Exiting _download_github_release_profiles()") 
    

def _process_benchmark_files(
        release: Dict[str, Any],
        work_dir: Path,
        templates_dir: Path,
        github_pat_token: str,
        pre_downloaded_data_dir: Path | None
    ) -> None:
    # fetch datastream, generate tailoring files, generate checksums

    cac_tag = release["cac_tag"]
    b_data = release["benchmark_data"]
    benchmark_id = b_data["benchmark_id"]

    logger.debug(f"From _process_benchmark_files({cac_tag})")

    # Fetch release data into temp directory or use test data
    with tempfile.TemporaryDirectory() as download_dir:
        logger.debug(f"Using temporary directory: {download_dir}")
        download_dir = Path(download_dir)
        if pre_downloaded_data_dir:
            release_dir = pre_downloaded_data_dir / cac_tag
            if not release_dir.exists():
                raise BenchmarkProcessingError(
                    f"Data directory {cac_tag} does not exist in {pre_downloaded_data_dir}. "
                    f"Check the pre-downloaded-data-dir argument. "
                    f"Ensure the directory structure matches the one used in tools/tests/data/input/"
                    )
            logger.debug(f"Copying test data from {release_dir} to {download_dir}")
            shutil.copytree(release_dir, download_dir, dirs_exist_ok=True)
        else:
            logger.debug(f"Downloading data from Github to {download_dir}")
            _download_github_release_datastream(cac_tag, github_pat_token, download_dir)
            _download_github_release_profiles(cac_tag, release["cac_commit"], b_data["product"], github_pat_token, download_dir)

        # create benchmark directory (e.g. ubuntu2404_CIS_2)
        output_benchmark_dir = work_dir / benchmark_id
        output_benchmark_dir.mkdir(parents=True, exist_ok=True)

        # Copy datastream gz to benchmark directory
        datastream_gz_filename = CAC_RELEASE_GZ_NAME.format(b_data["product"])
        datastream_gz_downloaded_path = download_dir / datastream_gz_filename
        datastream_gz_path = output_benchmark_dir / datastream_gz_filename
        try:
            shutil.copy(datastream_gz_downloaded_path, datastream_gz_path)
        except Exception as e:
            raise BenchmarkProcessingError(
                f"Failed to copy datastream gz from {datastream_gz_downloaded_path} to {datastream_gz_path}: {e}"
                )

        # Verify integrity of datastream gz
        with open(datastream_gz_path, "rb") as f:
            digest = hashlib.file_digest(f, "sha256")
            if digest.hexdigest() != release["cac_release_gz_sha256"]:
                raise BenchmarkProcessingError(f"Corrupted release file {datastream_gz_path} for release {cac_tag}")
            logger.debug(f"Integrity check OK for {datastream_gz_path}")

        # Set metadata for datastream
        b_data["data_files"] = {
                "datastream_gz": {
                    "path": str(datastream_gz_path.relative_to(work_dir)),
                    "sha256": release["cac_release_gz_sha256"]
                }}

        # Generate tailoring files
        logger.debug("Generating tailoring files for benchmark {benchmark_id}...")
        tailoring_files_dir = output_benchmark_dir / "tailoring"
        tailoring_files_dir.mkdir(parents=True, exist_ok=True)

        # Unpack datastream used for generating tailoring files
        unpacked_datastream_path = tempfile.mktemp(suffix=".datastream.xml", dir=download_dir)
        logger.debug(f"Unpacking datastream to {unpacked_datastream_path}...")
        with gzip.open(datastream_gz_path, "rb") as ds_gz:
            with open(unpacked_datastream_path, "wb") as ds:
                shutil.copyfileobj(ds_gz, ds)

        # Generate tailoring files
        b_data["tailoring_files"] = {}
        for profile_id in b_data["profiles"]:
            logger.info(f"Generating tailoring file for profile {profile_id} in benchmark {benchmark_id}...")
            
            profile_path = download_dir / "ComplianceAsCode-content" / "products" / \
                           b_data["product"] / "profiles" / f"{profile_id}.profile"
            tailoring_template_path = templates_dir / "tailoring" / f"{profile_id}-tailoring.xml"
            output_tailoring_path = tailoring_files_dir / f"{profile_id}-tailoring.xml"
            logger.debug(
                f"Calling generate_tailoring_file() with profile {profile_path} "
                f"and tailoring template: {tailoring_template_path}"
                )
            if not profile_path.exists():
                raise BenchmarkProcessingError(
                    f"Profile {profile_id} not found in {download_dir}/ComplianceAsCode-content/products/{b_data['product']}/profiles"
                    )
            if not tailoring_template_path.exists():
                raise BenchmarkProcessingError(
                    f"Tailoring template {tailoring_template_path} not found in {templates_dir}/tailoring"
                    )

            tailor_doc = generate_tailoring_file(profile_path, unpacked_datastream_path, tailoring_template_path, benchmark_id)

            logger.debug(f"Writing tailoring file to {output_tailoring_path}")
            tailor_doc.write(output_tailoring_path, pretty_print=True, xml_declaration=True, encoding="UTF-8")

            logger.debug("Validating tailoring file")
            validate_tailoring_file(output_tailoring_path)

            logger.debug(f"Calculating sha256 hash of {output_tailoring_path}")
            with open(output_tailoring_path, "rb") as f:
                digest = hashlib.file_digest(f, "sha256")
            b_data["tailoring_files"][profile_id] = {
                "file": str(output_tailoring_path.relative_to(work_dir)),
                "sha256": digest.hexdigest()
                }
            logger.debug(f"Calculated sha256 hash: {digest.hexdigest()}")
            logger.info(f"Successfully generated tailoring file {output_tailoring_path}")



def log_upgrade_paths(benchmarks: List[Dict[str, Any]]) -> None:
    # print out clean upgrade paths
    logger.info("--- Benchmark upgrade paths ---")
    for i, b in enumerate(sorted(benchmarks, key=lambda x: x["benchmark_id"])):
        compatible_versions = [x for x in b["compatible_versions"] if x != b["benchmark_id"]] or []
        compatible_versions = ", ".join(compatible_versions)

        logger.info(f"Benchmark id/version: {b['benchmark_id']}/{b['version']}")
        if compatible_versions:
            logger.info(f"Automatically replaces deprecated versions: {compatible_versions}")

        logger.info("Upgrade path:")
        upgrade_path = b["breaking_upgrade_path"]
        if upgrade_path:
            for j, benchmark_id in enumerate(upgrade_path):
                logger.info(f"{j+1}: {benchmark_id}")
        else:
            logger.info("None, this is the latest release!")

    logger.info("----------------------------")


def process_benchmarks(
        benchmark_yaml_files: List[Path],
        templates_dir: Path,
        github_pat_token: str,
        pre_downloaded_data_dir: Path,
        out_dir: Path
        ) -> None:
    # Parse yaml files, do some basic validation, call process_yaml() for each, write output json

    if out_dir.exists() and list(out_dir.rglob("*.xml")):
        raise BenchmarkProcessingError(
            f"Benchmark directory {out_dir} is not empty. "
            f"Remove the old data and re-run the script."
            )

    logger.info(f"Schema version is: {SCHEMA_VERSION}")
    benchmarks_json_data = {
            "version": SCHEMA_VERSION,
            "benchmarks": [],
            }

    with tempfile.TemporaryDirectory() as work_dir:
        work_dir = Path(work_dir).resolve()

        # parse and process benchmark yaml files
        for benchmark_yaml in sorted(benchmark_yaml_files):

            logger.info(f"Processing yaml - {benchmark_yaml}")
            with open(benchmark_yaml) as f:
                yaml_data = yaml.safe_load(f.read())

            # sanity checks
            for k in ["general", "benchmark_releases"]:
                if not yaml_data.get(k):
                    raise BenchmarkProcessingError(f"Error: Key {k} not found in {benchmark_yaml}.")

            for k in ["backend", "benchmark_type", "product"]:
                if not yaml_data["general"].get(k):
                    raise BenchmarkProcessingError(f"Error: Key general.{k} not found in {benchmark_yaml}.")

            # process yaml and add benchmarks metadata to the json data
            if yaml_data["general"]["backend"] == "openscap":
                benchmarks_metadata = process_yaml(
                    yaml_data,
                    templates_dir,
                    github_pat_token,
                    pre_downloaded_data_dir,
                    work_dir
                    )
            else:
                raise BenchmarkProcessingError(f"Unsupported backend {yaml_data['backend']} in {benchmark_yaml}")
            benchmarks_json_data["benchmarks"].extend(benchmarks_metadata)
            log_upgrade_paths(benchmarks_metadata)

        logger.info(f"Copying benchmark files and folders to {out_dir}")
        shutil.copytree(work_dir, out_dir, dirs_exist_ok=True)

    logger.info(f"Writing json - {OUTPUT_JSON_NAME}")
    with open(out_dir / OUTPUT_JSON_NAME, "w") as f:
        f.write(json.dumps(benchmarks_json_data, indent=2))

    # calc hash of json
    with open(out_dir / OUTPUT_JSON_NAME, "rb") as f:
        digest = hashlib.file_digest(f, "sha256")
    logger.info(f"sha256({OUTPUT_JSON_NAME}): {digest.hexdigest()}")


def get_pat_token():
    while True:
        pat = input("Please input your Github personal access token (PAT): ")
        if pat:
            return pat
        logger.error("PAT cannot be empty. Please try again.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--benchmark-yaml-files", type=Path, required=True, nargs="+")
    parser.add_argument("-o", "--output-dir", type=Path, required=True)
    parser.add_argument("-t", "--templates-dir", type=Path, required=True)
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("--pre-downloaded-data-dir", type=Path, help="Data dir containing pre-downloaded data (also used for testing)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)
       # formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
       # logger.setFormatter(formatter)

    if args.pre_downloaded_data_dir is not None:
        logger.warning(f"Using pre-downloaded data from {args.pre_downloaded_data_dir}")
        github_pat_token = None
    else:
        github_pat_token = get_pat_token()
    
    try:
        process_benchmarks(
            args.benchmark_yaml_files,
            args.templates_dir,
            github_pat_token,
            args.pre_downloaded_data_dir,
            args.output_dir
            )
    except BenchmarkProcessingError as e:
        logger.error(f"Error processing benchmarks: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(e)
        sys.exit(1)

    logger.info("Done!")

if __name__ == "__main__":
    main()
