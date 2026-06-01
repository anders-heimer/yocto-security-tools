# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Cherry-pick and series application logic for CVE corrector."""
import tempfile
from pathlib import Path
from typing import Optional

from .git_ops import (
    detect_strip_level,
    get_repo_subdir,
    git_clean_workspace,
    is_bad_object,
    try_cherry_pick,
)
from .meta_layer import write_cve_status
from .state import AlreadyAppliedError, GitError, PatchError, WorkflowState, save_progress
from .utils import logger, run_cmd, run_cmd_capture


def handle_empty_cherry_pick(state: WorkflowState) -> None:
    """Write CVE_STATUS when cherry-pick produces no changes."""
    if not state.meta_layer:
        return
    subject = run_cmd_capture(
        ['git', 'log', '-1', '--format=%s', state.commit_hash],
        cwd=state.workspace_path
    ).stdout.strip()
    reason = (f"Upstream fix ({state.commit_hash[:12]}: {subject}) produces "
              f"no changes — code already matches the fixed version")
    write_cve_status(state.meta_layer, state.recipe, state.cve_id,
                     reason, skip_confirm=state.skip_confirm)


def cherry_pick_to_devtool(state: WorkflowState) -> None:
    """Cherry-pick CVE commits onto devtool branch via format-patch + git am."""
    logger.info("Cherry-picking commits to devtool branch")
    subdir = get_repo_subdir(state.workspace_path)

    with tempfile.TemporaryDirectory() as patch_dir:
        fmt_result = run_cmd_capture(
            ['git', 'format-patch', '-o', patch_dir,
             f'original-version..{state.cve_id}'],
            cwd=state.workspace_path)
        if fmt_result.returncode != 0:
            raise PatchError(f"format-patch failed: {fmt_result.stderr}")
        patches = sorted(Path(patch_dir).glob('*.patch'))
        if not patches:
            logger.info("format-patch produced no patches — fix already in tree")
            handle_empty_cherry_pick(state)
            raise AlreadyAppliedError("format-patch produced no patches")
        logger.info("Generated %s patch(es) for devtool", len(patches))

        strip_level = detect_strip_level(patches)
        if strip_level == 1 and subdir:
            strip_level = 2
        logger.info("Monorepo subdir: %s, strip level: %s", subdir, strip_level)

        git_clean_workspace(state.workspace_path, remove_ignored=True)
        if run_cmd(['git', 'checkout', 'devtool'],
                   cwd=state.workspace_path) != 0:
            save_progress(state, 'cherry_pick_to_devtool')
            raise GitError("Failed to checkout devtool branch")

        am_cmd = ['git', 'am', f'-p{strip_level}']
        am_result = run_cmd_capture(
            am_cmd + [str(p) for p in patches],
            cwd=state.workspace_path)
        if am_result.returncode != 0:
            logger.warning("git am failed, retrying with --3way: %s", am_result.stderr)
            run_cmd(['git', 'am', '--abort'], cwd=state.workspace_path)
            am_result = run_cmd_capture(
                am_cmd + ['--3way'] + [str(p) for p in patches],
                cwd=state.workspace_path)
        if am_result.returncode != 0:
            logger.error("git am --3way failed: %s", am_result.stderr)
            run_cmd(['git', 'am', '--abort'], cwd=state.workspace_path)
            save_progress(state, 'cherry_pick_to_devtool')
            raise PatchError(f"git am --3way failed: {am_result.stderr}")


def apply_series(workspace_path: Path,
                 series: list[dict]) -> tuple[bool, Optional[str], Optional[dict]]:
    """Apply PR series commits using batch cherry-pick.

    Returns:
        Tuple of (success, last_commit_hash, best_partial_series)
    """
    logger.info("Found %s pull request series", len(series))
    best_series = None
    max_applied = 0

    for idx, pr_series in enumerate(series, 1):
        pull_url = pr_series.get('pull_url', '')
        commits = pr_series.get('commits', [])
        valid = [c for c in commits if not is_bad_object(workspace_path, c)]
        skipped = len(commits) - len(valid)
        if skipped:
            logger.warning("  Skipping %s bad object(s) in series", skipped)
        if not valid:
            logger.warning("[%s/%s] No valid commits in series from %s", idx, len(series), pull_url)
            continue
        logger.info("[%s/%s] Trying PR series from %s", idx, len(series), pull_url)

        result = run_cmd(['git', 'cherry-pick'] + valid, cwd=workspace_path)

        if result == 0:
            logger.info("✓ Successfully applied all %s commits from PR series", len(valid))
            return True, valid[-1], None

        cherry_pick_head = workspace_path / '.git' / 'CHERRY_PICK_HEAD'
        cherry_pick_in_progress = cherry_pick_head.exists()
        if cherry_pick_in_progress:
            failed_hash = cherry_pick_head.read_text().strip()[:40]
            try:
                failed_idx = valid.index(failed_hash)
                applied_commits = valid[:failed_idx]
                remaining_commits = valid[failed_idx + 1:]
                if len(applied_commits) > max_applied:
                    max_applied = len(applied_commits)
                    best_series = {
                        'pull_url': pull_url, 'commits': valid,
                        'applied_commits': applied_commits,
                        'failed_at': failed_hash,
                        'remaining_commits': remaining_commits
                    }
            except ValueError:
                # CHERRY_PICK_HEAD not in our list — count applied via git log
                log_result = run_cmd_capture(
                    ['git', 'log', '--oneline', 'original-version..HEAD'],
                    cwd=workspace_path)
                if log_result.returncode == 0:
                    applied_count = len(log_result.stdout.strip().splitlines())
                    if applied_count > max_applied:
                        max_applied = applied_count
                        best_series = {
                            'pull_url': pull_url, 'commits': valid,
                            'applied_commits': valid[:applied_count],
                            'failed_at': failed_hash,
                            'remaining_commits': valid[applied_count:]
                        }
            run_cmd(['git', 'cherry-pick', '--abort'], cwd=workspace_path)

        run_cmd(['git', 'reset', '--hard', 'original-version'], cwd=workspace_path)

    return False, None, best_series


def apply_single_commits(workspace_path: Path, hashes: list[str],
                         subproject: Optional[str] = None) -> tuple[bool, Optional[str]]:
    """Apply individual fix commits until one succeeds."""
    logger.info("Attempting %s commit(s)", len(hashes))
    result = run_cmd_capture(['git', 'log', '--oneline', '-10'], cwd=workspace_path)
    for commit_hash in hashes:
        if commit_hash[:8] in result.stdout:
            logger.info("Commit %s already applied, skipping...", commit_hash[:8])
            return True, commit_hash

    for idx, commit_hash in enumerate(hashes, 1):
        if is_bad_object(workspace_path, commit_hash):
            logger.warning("[%s/%s] Skipping %s (bad object)", idx, len(hashes), commit_hash[:8])
            continue
        logger.info("[%s/%s] Trying %s...", idx, len(hashes), commit_hash[:8])
        if try_cherry_pick(workspace_path, commit_hash, subproject=subproject):
            logger.info("✓ Success")
            return True, commit_hash
        logger.debug("✗ Failed")
        run_cmd(['git', 'cherry-pick', '--abort'], cwd=workspace_path)

    return False, None


def find_least_conflict_commit(workspace_path: Path,
                               hashes: list[str]) -> tuple[Optional[str], float]:
    """Find commit that produces the fewest merge conflicts."""
    logger.info("All cherry-picks failed, finding commit with least conflicts")
    min_conflicts = float('inf')
    best_hash = None

    for commit_hash in hashes:
        if is_bad_object(workspace_path, commit_hash):
            continue
        run_cmd(['git', 'cherry-pick', commit_hash], cwd=workspace_path)
        result = run_cmd_capture(
            ['git', 'diff', '--name-only', '--diff-filter=U'], cwd=workspace_path)
        conflict_count = len(result.stdout.splitlines())
        if conflict_count < min_conflicts:
            min_conflicts = conflict_count
            best_hash = commit_hash
        run_cmd(['git', 'cherry-pick', '--abort'], cwd=workspace_path)

    return best_hash, min_conflicts
