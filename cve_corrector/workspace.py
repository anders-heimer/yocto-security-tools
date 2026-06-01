# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Devtool workspace setup and CVE branch preparation."""
from pathlib import Path
from typing import Optional

from .bitbake_ops import cleanup_workspace, find_mirror_repo, get_build_path
from .git_ops import checkout_version, copy_missing_files_from_devtool, deduce_repo_from_patches
from .ptest import enable_ptest
from .state import DevtoolError, GitError, MetadataError
from .utils import logger, run_cmd, run_cmd_capture

# Branch names to check when determining the devtool workspace base ref
_DEVTOOL_BASE_BRANCHES = ('main', 'master', 'devtool-base')


def setup_devtool_workspace(
        recipe: str, clean: bool, skip_ptest: bool
) -> tuple[Path, Optional[str]]:
    """Setup devtool workspace for recipe modification.

    Args:
        recipe: Name of the recipe to modify
        clean: If True, clean existing workspace before starting
        skip_ptest: If True, skip ptest enablement

    Returns:
        Tuple of (workspace_path, version) where version may be None
    """
    build_path = get_build_path()

    if clean:
        logger.info("Cleaning up workspace")
        cleanup_workspace(str(build_path))

    if not skip_ptest:
        logger.info("Enabling ptest")
        enable_ptest()

    logger.info("Running devtool modify %s", recipe)
    ret = run_cmd(['devtool', 'modify', recipe])
    if ret != 0:
        result = run_cmd_capture(['devtool', 'status'])
        if recipe not in result.stdout:
            logger.error("devtool modify failed")
            raise DevtoolError("devtool modify failed")
        logger.info("Recipe %s already in workspace, continuing...", recipe)

    logger.debug("Getting version from bitbake")
    result = run_cmd_capture(['bitbake-getvar', 'PV', '-r', recipe])
    version = None
    for line in result.stdout.splitlines():
        if line.startswith('PV='):
            version = line.split('=', 1)[1].strip('"')
            logger.info("Recipe version: %s", version)
            break
    if not version:
        logger.warning("Could not get version from bitbake")

    workspace_path = build_path / 'workspace' / 'sources' / recipe
    if not workspace_path.exists():
        logger.error("Workspace not found: %s", workspace_path)
        raise MetadataError("Metadata error")

    logger.debug("Working in: %s", workspace_path)
    return workspace_path, version


def setup_upstream_remote(workspace_path: Path, mirror_path: Optional[Path],
                          mirror_dir: Optional[Path], recipe: str,
                          hash_details: list[dict],
                          series: Optional[list[dict]] = None,
                          references: Optional[list[dict]] = None) -> Optional[str]:
    """Configure upstream git remote and fetch references.

    Returns:
        Mirror directory name when a local mirror is used, or None.
    """
    mirror_name = None
    if not mirror_path and mirror_dir:
        mirror_path = find_mirror_repo(mirror_dir, recipe, hash_details)
        if mirror_path:
            logger.info("Found mirror for %s: %s", recipe, mirror_path)
    if mirror_path:
        mirror_name = mirror_path.stem

    if mirror_path:
        upstream_url: Optional[str] = str(mirror_path.absolute())
    else:
        logger.info("Deducing upstream repo from hash details")
        urls = [d['url'] for d in hash_details if d.get('url')]
        if not urls and series:
            urls = [s['pull_url'] for s in series if s.get('pull_url')]
            if urls:
                logger.info("Deducing upstream repo from series pull_url")
        upstream_url = deduce_repo_from_patches(urls)
        if not upstream_url and references:
            logger.info("Falling back to references for upstream deduction")
            ref_urls = [r['url'] for r in references if r.get('url')]
            upstream_url = deduce_repo_from_patches(ref_urls)
        if upstream_url:
            logger.info("Deduced upstream: %s", upstream_url)
        else:
            logger.warning("Could not deduce upstream repo")
            return None

    logger.info("Adding upstream remote: %s", upstream_url)
    assert upstream_url is not None
    result = run_cmd_capture(['git', 'remote'], cwd=workspace_path)
    if 'upstream' not in result.stdout:
        run_cmd(['git', 'remote', 'add', 'upstream', upstream_url], cwd=workspace_path)
    else:
        logger.debug("Upstream remote already exists, skipping...")

    logger.info("Fetching upstream references")
    if run_cmd(['git', 'fetch', 'upstream', '--tags', '--progress'], cwd=workspace_path) != 0:
        raise GitError("Git operation failed")

    return mirror_name


def prepare_cve_branch(workspace_path: Path, version: Optional[str],
                       cve_id: str, subproject: Optional[str] = None) -> tuple[bool, list[str]]:
    """Checkout recipe version and prepare branch for CVE fix.

    Returns:
        Tuple of (version_checkout_ok, skipped_commits).
    """
    checkout_ok = True
    if version:
        logger.info("Checking out version %s", version)
        result = run_cmd_capture(['git', 'branch', '--list', cve_id], cwd=workspace_path)
        if result.stdout.strip():
            logger.debug("Branch %s already exists, checking out...", cve_id)
            run_cmd(['git', 'checkout', cve_id], cwd=workspace_path)
        elif not checkout_version(workspace_path, version, cve_id,
                                  subproject=subproject):
            logger.warning("Version checkout failed, will try format-patch fallback...")
            run_cmd(['git', 'checkout', '-b', cve_id], cwd=workspace_path)
            checkout_ok = False

    logger.info("Cherry-picking devtool commits")
    base_branch = None
    for candidate in _DEVTOOL_BASE_BRANCHES:
        result = run_cmd_capture(['git', 'rev-parse', '--verify', candidate],
                                 cwd=workspace_path)
        if result.returncode == 0:
            base_branch = candidate
            break
    if not base_branch:
        logger.error("Failed to find base branch (main/master/devtool-base)")
        raise GitError("Git operation failed")
    commit_list = run_cmd_capture(
        ['git', 'rev-list', '--reverse', f'{base_branch}..devtool'],
        cwd=workspace_path)
    if commit_list.returncode != 0:
        logger.error("Failed to list devtool commits")
        raise GitError("Git operation failed")
    skipped = []
    for commit in commit_list.stdout.strip().splitlines():
        if run_cmd(['git', 'cherry-pick', commit], cwd=workspace_path) != 0:
            subj = run_cmd_capture(['git', 'log', '-1', '--format=%s', commit],
                                   cwd=workspace_path)
            skipped.append(f"{commit[:12]} {subj.stdout.strip()}")
            logger.warning("Skipping devtool commit: %s", subj.stdout.strip())
            run_cmd_capture(['git', 'cherry-pick', '--abort'], cwd=workspace_path)
    if skipped:
        logger.info("Skipped %s devtool commit(s) that failed to apply:", len(skipped))
        for entry in skipped:
            logger.info("  - %s", entry)

    copy_missing_files_from_devtool(workspace_path)

    logger.debug("Creating tag original-version at current position")
    run_cmd_capture(['git', 'tag', '-f', 'original-version'], cwd=workspace_path)
    return checkout_ok, skipped
