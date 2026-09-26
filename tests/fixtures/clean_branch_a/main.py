# MIT License — TrustGate fixture: clean_branch_a
# No third-party imports, no suspicious license headers.

import os
import sys
import json


def greet(name: str) -> str:
    return f"Hello, {name}!"


if __name__ == "__main__":
    print(greet("world"))
