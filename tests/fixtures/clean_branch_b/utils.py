# MIT License — TrustGate fixture: clean_branch_b
# Uses only stdlib; requests is a real PyPI package (not hallucinated).

import re
import pathlib
import requests  # real package on PyPI


def find_urls(text: str):
    return re.findall(r"https?://\S+", text)


def read_file(p: str) -> str:
    return pathlib.Path(p).read_text(errors="ignore")
