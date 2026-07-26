"""
untrusted_sources.py

Loads the competition-provided list of untrusted GitHub Actions contexts
from untrusted_data.csv. Replaces the hardcoded list in Gate 5.
"""

import csv
from pathlib import Path
from functools import lru_cache


@lru_cache(maxsize=1)
def load_untrusted_sources(csv_path: str) -> tuple:
    path = Path(csv_path)
    if not path.exists():
        print(f"[!] untrusted_data.csv not found at {csv_path}. Using built-in list.")
        return tuple(_BUILTIN_FALLBACK)

    sources = []
    with open(path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            source = (row.get('untrusted_input') or row.get('context') or '').strip()
            if source:
                sources.append(source)

    print(f"[*] Loaded {len(sources)} untrusted sources from {path.name}")
    return tuple(sources)


def is_tainted_expression(expression_text: str, untrusted_sources: tuple):
    """Returns (is_tainted: bool, matched_source: str | None)"""
    for source in untrusted_sources:
        if source in expression_text:
            return True, source
    return False, None


_BUILTIN_FALLBACK = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.commits[*].message",
    "github.event.commits[*].author.email",
    "github.event.commits[*].author.name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.head_commit.committer.email",
    "github.event.head_commit.committer.name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
    "github.event.issue.pull_request",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages[*].page_name",
]