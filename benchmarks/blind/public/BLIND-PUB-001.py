"""Public blind scanner-evaluation fixture. Do not execute or deploy."""

import subprocess


def diagnostic(target: str) -> bytes:
    return subprocess.run(
        ["/usr/bin/dig", target],
        check=True,
        capture_output=True,
    ).stdout
