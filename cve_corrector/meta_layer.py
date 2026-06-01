# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Meta-layer git operations for CVE corrector.

Handles committing patches and CVE_STATUS entries to the meta-layer,
staging files, restoring devtool-modified content, and exporting patches.
"""
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from .bitbake_ops import get_build_path
from .git_ops import get_git_user_info
from .recipe_ops import _append_src_uri_entries
from .utils import logger, run_cmd, run_cmd_capture


def _export_commit_patch(meta_layer: Path) -> None:
    """Export the latest commit as a patch file under BBPATH/patches/."""
    patches_dir = get_build_path() / 'patches'
    patches_dir.mkdir(parents=True, exist_ok=True)
    result = run_cmd_capture(
        ['git', 'format-patch', '-1', 'HEAD', '-o', str(patches_dir)],
        cwd=meta_layer)
    if result.returncode == 0 and result.stdout.strip():
        logger.info("Exported patch: %s", result.stdout.strip())
    else:
        logger.warning("Failed to export patch via git format-patch")


def create_layer_commit(meta_layer: Optional[Path], recipe: str, cve_id: str,
                        ptest_output: Optional[str] = None, skip_confirm: bool = False,
                        hash_details: Optional[list] = None,
                        series_state: Optional[dict] = None,
                        used_commits: Optional[list] = None) -> bool:
    """Create git commit in meta-layer with updated recipe and patch.

    Returns:
        True if a commit was created, False otherwise.
    """
    if not meta_layer or not meta_layer.exists():
        logger.warning("Meta-layer path invalid: %s", meta_layer)
        return False

    author, email = get_git_user_info()
    commit_msg = f"{recipe}: fix {cve_id}\n\nBackport patch to fix {cve_id}.\n"
    commit_msg += f"https://nvd.nist.gov/vuln/detail/{cve_id}\n\n"

    # Add upstream fix references — prefer PR link, fall back to commit URLs
    pull_url = (series_state or {}).get('pull_url', '')
    if pull_url:
        commit_msg += f"Upstream fix:\n  {pull_url}\n\n"
    elif hash_details:
        if used_commits:
            used_set = set(used_commits)
            urls = dict.fromkeys(d['url'] for d in hash_details
                                 if d.get('url') and d.get('hash') in used_set)
        else:
            urls = dict.fromkeys(d['url'] for d in hash_details if d.get('url'))
        if urls:
            commit_msg += "Upstream fix:\n"
            for url in urls:
                commit_msg += f"  {url}\n"
            commit_msg += "\n"

    if ptest_output:
        logger.info("Ptest Results:")
        logger.info(ptest_output)
        commit_msg += f"Tested with ptest:\n{ptest_output}\n\n"

    commit_msg += f"Signed-off-by: {author} <{email}>\n"

    logger.info("Commit Message:")
    logger.info(commit_msg)

    if not skip_confirm:
        response = input("\nCreate commit with this message? [Y/n]: ").strip().lower()
        if response and response != 'y':
            logger.info("Commit cancelled.")
            return False

    # Restore any files that devtool finish deleted from the working tree
    deleted_wt = run_cmd_capture(
        ['git', 'diff', '--relative', '--name-only', '--diff-filter=D'],
        cwd=meta_layer).stdout.strip().splitlines()
    if deleted_wt:
        logger.warning("Restoring %s file(s) deleted by devtool finish", len(deleted_wt))
        for f in deleted_wt:
            logger.debug("  restoring: %s", f)
            run_cmd(['git', 'checkout', 'HEAD', '--', f], cwd=meta_layer)

    # Stage only new and modified files in the recipe directory
    changed = run_cmd_capture(
        ['git', 'diff', '--relative', '--name-only'],
        cwd=meta_layer).stdout.strip().splitlines()
    untracked = run_cmd_capture(
        ['git', 'ls-files', '--others', '--exclude-standard'],
        cwd=meta_layer).stdout.strip().splitlines()

    # Restore existing .patch files that devtool merely regenerated
    for f in changed:
        if not f.endswith('.patch'):
            continue
        diff = run_cmd_capture(
            ['git', 'diff', '-I', r'^From ', '-I', r'^index ', '--', f],
            cwd=meta_layer).stdout.strip()
        if not diff:
            logger.debug("Restoring unchanged patch: %s", f)
            run_cmd(['git', 'checkout', 'HEAD', '--', f], cwd=meta_layer)

    # Restore .bb/.inc files that devtool rewrote with duplicate SRC_URI,
    # then append only the new file:// entries
    new_patches = set(
        Path(f).name for f in untracked
        if f.endswith('.patch') and f'/{recipe}/' in f
    )
    if new_patches:
        for f in changed:
            if (f.endswith('.bb') or f.endswith('.inc')) and f'/{recipe}' in f:
                run_cmd(['git', 'checkout', 'HEAD', '--', f], cwd=meta_layer)

        target = None
        for pattern in (f'**/{recipe}*.inc', f'**/{recipe}*.bb',
                        f'**/{recipe}*.bbappend'):
            for candidate in sorted(meta_layer.glob(pattern)):
                try:
                    if 'file://' in candidate.read_text(encoding='utf-8'):
                        target = candidate
                        break
                except OSError:
                    continue
            if target:
                break
        if target:
            _append_src_uri_entries(target, sorted(new_patches))
            logger.info("Added %s new SRC_URI entry/entries to %s",
                        len(new_patches), target.name)

    # Re-read changed files after restoring
    changed = run_cmd_capture(
        ['git', 'diff', '--relative', '--name-only'],
        cwd=meta_layer).stdout.strip().splitlines()

    recipe_prefix = 'recipes-'
    to_stage = [f for f in changed + untracked
                if recipe_prefix in f and f'/{recipe}/' in f]
    if to_stage:
        run_cmd(['git', 'add', '--'] + to_stage, cwd=meta_layer)
    else:
        logger.warning("No recipe files to stage")

    logger.info("Creating commit")
    with NamedTemporaryFile('w', delete=False, encoding='utf-8') as f:
        f.write(commit_msg)
        msg_file = f.name

    try:
        rc = run_cmd(['git', 'commit', '-F', msg_file], cwd=meta_layer)
        if rc != 0:
            logger.warning("git commit failed (nothing to commit?)")
            return False
        logger.info("Created commit")
    finally:
        Path(msg_file).unlink()

    _export_commit_patch(meta_layer)
    return True


def _map_cve_status_reason(reason: str) -> str:
    """Map a human-readable reason to the correct CVE_STATUS keyword.

    Uses Yocto CVE_CHECK_STATUSMAP values:
    - fixed-version: fix already present via version or backport
    - not-applicable-platform: platform-specific, doesn't affect this target
    - not-applicable-config: requires config/feature not enabled
    - cpe-incorrect: CVE doesn't actually apply to this component
    """
    lower = reason.lower()
    if any(kw in lower for kw in ('already', 'matches the fixed', 'no net changes',
                                   'backport', 'patched')):
        return 'fixed-version'
    if any(kw in lower for kw in ('platform', 'architecture', 'target')):
        return 'not-applicable-platform'
    if any(kw in lower for kw in ('config', 'feature', 'disabled', 'not enabled')):
        return 'not-applicable-config'
    if any(kw in lower for kw in ('cpe', 'wrong component', 'different package',
                                   'not present', 'does not apply')):
        return 'cpe-incorrect'
    # Default for generic not-applicable conclusions
    return 'not-applicable-config'


def write_cve_status(meta_layer: Optional[Path], recipe: str, cve_id: str,
                     reason: str, skip_confirm: bool = False) -> bool:
    """Append a CVE_STATUS line to the recipe's .bb or .bbappend in the meta-layer.

    Returns:
        True if the CVE_STATUS was written and committed, False otherwise.
    """
    from .recipe_ops import _find_recipe_file

    if not meta_layer or not meta_layer.exists():
        logger.warning("Meta-layer path invalid: %s", meta_layer)
        return False

    status_line = f'CVE_STATUS[{cve_id}] = "{_map_cve_status_reason(reason)}: {reason}"'

    recipe_file = _find_recipe_file(meta_layer, recipe)
    if not recipe_file:
        logger.warning("No .bb or .bbappend found for %s in %s", recipe, meta_layer)
        return False

    content = recipe_file.read_text(encoding='utf-8')
    if cve_id in content:
        logger.info("CVE_STATUS for %s already in %s", cve_id, recipe_file)
        return True

    if not content.endswith('\n'):
        content += '\n'
    content += status_line + '\n'
    recipe_file.write_text(content, encoding='utf-8')
    logger.info("Wrote CVE_STATUS for %s to %s", cve_id, recipe_file)

    author, email = get_git_user_info()
    commit_msg = (
        f"{recipe}: mark {cve_id} as not applicable\n\n"
        f"{reason}\n\n"
        f"Signed-off-by: {author} <{email}>\n"
    )

    if not skip_confirm:
        print(f"\nCVE_STATUS line:\n  {status_line}")
        print(f"File: {recipe_file}")
        response = input("Create commit? [Y/n]: ").strip().lower()
        if response and response != 'y':
            logger.info("Commit cancelled.")
            return False

    run_cmd(['git', 'add', str(recipe_file)], cwd=meta_layer)

    with NamedTemporaryFile('w', delete=False, encoding='utf-8') as f:
        f.write(commit_msg)
        msg_file = f.name
    try:
        rc = run_cmd(['git', 'commit', '-F', msg_file], cwd=meta_layer)
        if rc != 0:
            logger.warning("git commit failed")
            return False
        logger.info("Created CVE_STATUS commit for %s", cve_id)
    finally:
        Path(msg_file).unlink()

    _export_commit_patch(meta_layer)
    return True
