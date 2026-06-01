# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Ptest operations for CVE corrector."""
import re
import sys
from typing import Optional

from .bitbake_ops import get_build_path
from .state import BuildPreexistingError
from .utils import logger, run_cmd, run_cmd_capture


def enable_ptest() -> None:
    """Enable ptest in local.conf if not already enabled."""
    build_path = get_build_path()
    local_conf = build_path / 'conf' / 'local.conf'
    result_distro = run_cmd_capture(['bitbake-getvar', 'DISTRO_FEATURES'], cwd=build_path)
    logger.debug("Current DISTRO_FEATURES: %s", result_distro.stdout.strip())
    if 'ptest' not in result_distro.stdout:
        logger.info("ptest not in DISTRO_FEATURES, appending to local.conf")
        with open(local_conf, 'a', encoding='utf-8') as f:
            f.write('DISTRO_FEATURES:append = " ptest"\n')
    else:
        logger.debug("ptest already in DISTRO_FEATURES, skipping")


def check_ptest_in_recipe(recipe: str) -> bool:
    """Check if ptest is enabled for recipe."""
    result = run_cmd_capture(['bitbake-getvar', '-r', recipe, "PTEST_ENABLED"])
    return 'PTEST_ENABLED="1"' in result.stdout


def run_ptest(recipe: str, build_timeout: int = 7200,
              test_timeout: int = 3600) -> Optional[str]:
    """Run ptest and return results summary.

    Args:
        recipe: Recipe name to test.
        build_timeout: Timeout in seconds for image build (default 2h).
        test_timeout: Timeout in seconds for testimage run (default 1h).
    """
    if not check_ptest_in_recipe(recipe):
        print(f"Recipe {recipe} does not have ptest enabled")
        return None

    build_path = get_build_path()
    local_conf = build_path / 'conf' / 'local.conf'

    # Save original content for cleanup
    _original_conf = local_conf.read_text() if local_conf.exists() else None

    result_inherit = run_cmd_capture(
        ['bitbake-getvar', 'IMAGE_CLASSES', '-r', 'core-image-minimal'])
    if 'testimage' not in result_inherit.stdout and local_conf.exists():
        with open(local_conf, 'a', encoding='utf-8') as f:
            f.write('\n## Added by CVE corrector (test-only, auto-removed)\n')
            f.write('\nTEST_RUNQEMUPARAMS += "slirp nographic"\n')
            # WARNING: These features weaken security. They are required
            # for automated testimage/ptest execution only.
            f.write('\nEXTRA_IMAGE_FEATURES += "allow-empty-password empty-root-password allow-root-login"\n')
            f.write('IMAGE_CLASSES += "testimage"\n')
            f.write('SERIAL_CONSOLES = "115200;ttyS0"\n')
            f.write('TEST_QEMUBOOT_TIMEOUT = "60"\n')
            f.write('QB_MEM = "-m 2048"\n')
            f.write('TEST_SUITES += "ping ssh ptest"\n')

    result_suites = run_cmd_capture(
        ['bitbake-getvar', 'TEST_SUITES', '-r', 'core-image-minimal'])
    if 'ptest' not in result_suites.stdout:
        with open(local_conf, 'a', encoding='utf-8') as f:
            f.write('\n## Added by CVE corrector - ptest suite\n')
            f.write('TEST_SUITES += "ping ssh ptest"\n')

    content = local_conf.read_text()
    lines = content.splitlines(keepends=True)
    updated = False
    for i, line in enumerate(lines):
        if line.startswith('CORE_IMAGE_EXTRA_INSTALL'):
            lines[i] = f'CORE_IMAGE_EXTRA_INSTALL = "{recipe}-ptest openssh-sshd"\n'
            updated = True
            break
    if updated:
        local_conf.write_text(''.join(lines))
    else:
        with open(local_conf, 'a', encoding='utf-8') as f:
            f.write(f'CORE_IMAGE_EXTRA_INSTALL = "{recipe}-ptest openssh-sshd"\n')

    print("Building test image...")
    try:
        if run_cmd(['bitbake', 'core-image-minimal'], timeout=build_timeout) != 0:
            print("bitbake build failed", file=sys.stderr)
            raise BuildPreexistingError("Test image build failed")

        print("Running testimage...")
        rc = run_cmd(['bitbake', 'core-image-minimal', '-c', 'testimage'],
                     timeout=test_timeout)
    finally:
        # Restore original local.conf to remove insecure test features
        if _original_conf is not None:
            local_conf.write_text(_original_conf)

    if rc == -1:
        print(f"testimage timed out after {test_timeout}s", file=sys.stderr)
        return None

    ptest_logs = list((build_path / 'tmp-glibc').glob(
        f'work/*/core-image-minimal/*/testimage/ptest_log/{recipe}'))
    if not ptest_logs:
        ptest_logs = list((build_path / 'tmp').glob(
            f'work/*/core-image-minimal/*/testimage/ptest_log/{recipe}'))
    if ptest_logs:
        content = sorted(ptest_logs)[-1].read_text()
        passed = content.count('PASSED:')
        failed = content.count('FAILED:')
        skipped = content.count('SKIPPED:')
        failing = [line.split('FAILED:')[1].strip()
                   for line in content.splitlines() if 'FAILED:' in line]
        summary = f"PASSED: {passed}, FAILED: {failed}, SKIPPED: {skipped}"
        if failing:
            summary += '\nFailing cases:\n' + '\n'.join(f'  {c}' for c in failing)
        return summary
    return None


def compare_ptest_results(before: str, after: str) -> bool:
    """Compare ptest results, return True if failures did not increase."""
    before_match = re.search(r'PASSED: (\d+), FAILED: (\d+)', before)
    after_match = re.search(r'PASSED: (\d+), FAILED: (\d+)', after)
    if before_match and after_match:
        return int(after_match.group(2)) <= int(before_match.group(2))
    return True
