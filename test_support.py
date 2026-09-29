"""Helpers for integration tests that require a real Linux PDF sandbox."""
from __future__ import annotations

from functools import lru_cache, wraps
import os
import unittest

import pdf_worker
from audit_contract import IntakeError


@lru_cache(maxsize=1)
def _sandbox_available() -> bool:
    try:
        pdf_worker.check_worker_isolation()
        return True
    except IntakeError:
        return False


def require_pdf_sandbox(testcase: unittest.TestCase) -> None:
    if _sandbox_available():
        return
    message = "Bubblewrap namespace and filesystem isolation is unavailable"
    if os.environ.get("TRC_REQUIRE_PDF_SANDBOX") == "1":
        testcase.fail(message + " (required by CI)")
    testcase.skipTest(message)


def requires_pdf_sandbox(test_method):
    @wraps(test_method)
    def wrapped(testcase, *args, **kwargs):
        require_pdf_sandbox(testcase)
        return test_method(testcase, *args, **kwargs)
    return wrapped
