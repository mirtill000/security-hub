import contextlib
import io
import os
import shutil
import tempfile
import unittest

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="securityhub-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, *parts: str) -> str:
        return os.path.join(self.tmp, *parts)


@contextlib.contextmanager
def silenced():
    """Swallow the console output of the modules (they print progress and summaries)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err
