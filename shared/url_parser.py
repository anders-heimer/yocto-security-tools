# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""URL parsing utilities for extracting commit hashes and PR commits.

This module is the single source of truth for URL-to-hash/series parsing,
used by both cve_metadata_extractor (with caching) and cve_corrector/cve_agent
(direct CLI use).
"""
import re
from typing import Optional

HASH_RE = re.compile(r'[0-9a-fA-F]{7,40}')

IGNORED_URL_PATTERNS = [
    'marc.info', 'NEWS.html#', '/blob/', 'bugzilla', 'viewtopic',
    'bugreport', 'hg.mozilla.org', 'bounties', 'bugs.launchpad.net',
    'hackerone', 'lore.kernel.org', 'jvn.jp', 'forum', 'gist', 'lapis',
    'access', 'user-attachments', 'advisory', 'issues', 'reddit',
]

_PR_RE = re.compile(r'https://github\.com/([^/]+)/([^/]+)/pull/(\d+)')


def extract_commit_hash(url: str) -> Optional[str]:
    """Extract a commit hash from a URL.

    Skips URLs matching ignored patterns and pure-numeric matches.

    Args:
        url: URL string potentially containing a commit hash.

    Returns:
        Hash string if found, None otherwise.
    """
    if any(p in url for p in IGNORED_URL_PATTERNS):
        return None
    match = HASH_RE.search(url)
    if match:
        h = match.group(0)
        if h.isdigit():
            return None
        return h
    return None


def fetch_github_pr_commits(pr_url: str,
                            token: Optional[str] = None) -> list[str]:
    """Fetch commit SHAs from a GitHub pull request via the API.

    Args:
        pr_url: GitHub PR URL (e.g. https://github.com/owner/repo/pull/123).
        token: GitHub API token. If None, reads from GITHUB_TOKEN env var.

    Returns:
        Ordered list of commit SHA strings. Empty list on failure.
    """
    import os  # pylint: disable=import-outside-toplevel

    import requests  # pylint: disable=import-outside-toplevel

    clean_url = pr_url.split('#')[0]
    match = _PR_RE.match(clean_url)
    if not match:
        return []

    owner, repo, pr_number = match.groups()
    api_url = (f'https://api.github.com/repos/{owner}/{repo}'
               f'/pulls/{pr_number}/commits')

    if token is None:
        token = os.getenv('GITHUB_TOKEN')
    if not token:
        print("  WARNING: GITHUB_TOKEN not set, skipping PR series extraction")
        return []

    print(f"  Fetching PR commits from {clean_url}...")
    try:
        commits: list[str] = []
        page = 1
        while True:
            response = requests.get(
                api_url, headers={'Authorization': f'token {token}'},
                params={'per_page': 100, 'page': page}, timeout=30)
            response.raise_for_status()
            page_commits = response.json()
            if not page_commits:
                break
            commits.extend(c['sha'] for c in page_commits)
            if len(page_commits) < 100:
                break
            page += 1
        print(f"  Found {len(commits)} commits in PR")
        return commits
    except requests.RequestException as e:
        print(f"  Failed to fetch PR commits: {e}")
        return []


def parse_fix_url(url: str) -> dict:
    """Parse a fix URL into hashes, hash_details, and series.

    Auto-detects commit URLs vs PR URLs.

    Args:
        url: GitHub commit URL or PR URL.

    Returns:
        Dict with keys: hashes, hash_details, series.

    Raises:
        ValueError: If no hash or PR commits could be extracted.
    """
    clean_url = url.split('#')[0]

    # PR URL
    if _PR_RE.match(clean_url):
        commits = fetch_github_pr_commits(url)
        if not commits:
            raise ValueError(
                f"Could not extract commits from PR: {url}")
        return {
            'hashes': commits,
            'hash_details': [{'hash': h, 'url': clean_url, 'source': 'cli'}
                             for h in commits],
            'series': [{'pull_url': clean_url, 'commits': commits}],
        }

    # Commit URL
    commit_hash = extract_commit_hash(url)
    if commit_hash:
        return {
            'hashes': [commit_hash],
            'hash_details': [{'hash': commit_hash, 'url': url,
                              'source': 'cli'}],
            'series': [],
        }

    raise ValueError(f"Could not extract commit hash from URL: {url}")
