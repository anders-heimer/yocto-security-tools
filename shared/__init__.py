# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Shared utilities for yocto-security-tools."""
import os

# Canonical allowlist of environment variables passed to git subprocesses.
# Import this in any module that builds a filtered git environment.
GIT_ENV_ALLOWLIST: frozenset[str] = frozenset({
    'PATH', 'HOME', 'USER', 'LOGNAME', 'TERM', 'LANG', 'LANGUAGE',
    'TMPDIR', 'TMP', 'TEMP', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
    # Yocto/BitBake
    'BBPATH', 'BUILDDIR', 'SDKMACHINE', 'MACHINE', 'DISTRO',
    # Git
    'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_NAME',
    'GIT_COMMITTER_EMAIL', 'GIT_SSH',
    'SSH_AUTH_SOCK', 'SSH_AGENT_PID',
    # Proxy
    'http_proxy', 'https_proxy', 'no_proxy',
    'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
})


def build_git_env() -> dict[str, str]:
    """Build a minimal, safe environment for git subprocesses.

    Filters the current environment through GIT_ENV_ALLOWLIST and sets
    overrides to prevent interactive prompts from blocking automation.
    """
    env = {k: v for k, v in os.environ.items()
           if k in GIT_ENV_ALLOWLIST or k.startswith('LC_')}
    env.update({
        'GIT_EDITOR': 'true',
        'GIT_TERMINAL_PROMPT': '0',
        'GIT_PAGER': 'cat',
        'EDITOR': 'true',
        'VISUAL': 'true',
    })
    return env
