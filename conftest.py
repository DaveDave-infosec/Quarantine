"""
Runner shims for the gltest direct runner.

These fix test-runner defects only. They do not touch the contracts and they
do not change anything a test asserts.
"""

import os as _os
import sys

import pytest

_orig_unlink = _os.unlink


def _safe_unlink(path, *a, **k):
    # Windows cannot unlink a temp file the runner still holds open on stdin.
    try:
        return _orig_unlink(path, *a, **k)
    except PermissionError:
        return None


_os.unlink = _safe_unlink


@pytest.fixture(autouse=True)
def _reset_contract_cache():
    # every test deploys fresh contracts, so clear the runner's cached class
    m = sys.modules.get("genlayer.gl.genvm_contracts")
    if m is not None:
        m.known_contract = None
    yield
