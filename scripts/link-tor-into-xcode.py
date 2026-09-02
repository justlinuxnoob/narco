#!/usr/bin/env python3
"""Add the tor framework to every build configuration in an Xcode project.

Merges rather than inserts. A second FRAMEWORK_SEARCH_PATHS in a block that
already has one is a duplicate key, and Xcode takes the last — which would drop
ours silently and leave the link failing exactly as before.

Matched line-wise, not by balanced parentheses: these values contain
`$(inherited)` and `$(SRCROOT)`, so a `[^)]*` pattern stops at the first `)`
inside a variable reference and never sees the setting at all.
"""
import re
import sys

pbx, xcf = sys.argv[1], sys.argv[2]
add = {
    "FRAMEWORK_SEARCH_PATHS": f'"{xcf}/ios-arm64", "{xcf}/ios-arm64_x86_64-simulator"',
    "OTHER_LDFLAGS": '"-framework", "tor"',
}

s = open(pbx).read()
blocks = s.count("buildSettings = {")


def merge(setting: str, additions: str, body: str) -> str:
    pat = re.compile(rf"^([ \t]*){setting} = (.+);[ \t]*$", re.M)
    m = pat.search(body)
    if not m:
        return f'\n\t\t\t\t{setting} = ("$(inherited)", {additions});' + body
    indent, value = m.group(1), m.group(2).strip()
    if value.startswith("(") and value.endswith(")"):
        merged = value[:-1].rstrip().rstrip(",") + f", {additions})"
    else:
        merged = f"({value}, {additions})"
    return pat.sub(lambda _: f"{indent}{setting} = {merged};", body, count=1)


def patch(m: re.Match) -> str:
    body = m.group(1)
    for setting, additions in add.items():
        body = merge(setting, additions, body)
    return "buildSettings = {" + body + "};"


s = re.sub(r"buildSettings = \{(.*?)\};", patch, s, flags=re.S)
open(pbx, "w").write(s)

out = open(pbx).read()
for setting, needle in (("FRAMEWORK_SEARCH_PATHS", "ios-arm64"), ("OTHER_LDFLAGS", '"tor"')):
    hits = [ln for ln in out.splitlines() if setting in ln and needle in ln]
    assert len(hits) == blocks, f"{setting}: {len(hits)} of {blocks} build configurations"

for i, b in enumerate(re.findall(r"buildSettings = \{(.*?)\};", out, re.S), 1):
    for setting in add:
        n = len(re.findall(rf"^[ \t]*{setting} = ", b, re.M))
        assert n == 1, f"block {i}: {setting} appears {n} times"

print(f"linked tor into all {blocks} build configurations, no duplicate keys")
