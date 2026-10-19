"""Fail before evaluation if the expected container boundaries are missing.

This Linux-only smoke check is run by the evaluation image, not by host pytest.
It verifies selected runtime controls; it is not a proof of sandbox security.
"""

import errno
import os
import platform
import tempfile
from importlib.metadata import version
from pathlib import Path


def main() -> None:
    """Check effective permissions and print versions for reproducibility."""
    if os.getuid() == 0:
        raise RuntimeError("Evaluation must run as a non-root user")

    # A unique probe avoids touching an existing project file even if misconfigured.
    try:
        with tempfile.NamedTemporaryFile(dir="/app", prefix="boundary-check-"):
            pass
    except OSError as exc:
        if exc.errno != errno.EROFS:
            raise RuntimeError("Expected a read-only project filesystem") from exc
    else:
        raise RuntimeError("Project filesystem is writable")

    with tempfile.TemporaryDirectory() as directory:
        canary = Path(directory) / "write-check"
        canary.write_text("temporary writes work", encoding="utf-8")
        if canary.read_text(encoding="utf-8") != "temporary writes work":
            raise RuntimeError("Temporary storage failed its write/read check")

    status = dict(line.split(":", 1) for line in
                  Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if int(status["CapEff"].strip(), 16) != 0 or status["NoNewPrivs"].strip() != "1":
        raise RuntimeError("Expected no effective capabilities and no new privileges")
    interfaces = {line.split(":", 1)[0].strip() for line in
                  Path("/proc/net/dev").read_text().splitlines() if ":" in line}
    if interfaces != {"lo"}:
        raise RuntimeError(f"Expected only loopback networking; got {interfaces}")

    print(f"Python {platform.python_version()}; "
          f"RestrictedPython {version('RestrictedPython')}; pytest {version('pytest')}")
    print("Container checks passed: non-root, read-only project, writable temp, "
          "no capabilities, no new privileges, loopback only.")


if __name__ == "__main__":
    main()
