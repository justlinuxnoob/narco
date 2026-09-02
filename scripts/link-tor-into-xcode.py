#!/usr/bin/env python3
r"""Add the tor framework to every build configuration in an Xcode project.

Merges rather than inserts. A second FRAMEWORK_SEARCH_PATHS in a block that
already has one is a duplicate key, and Xcode takes the last — which would drop
ours silently and leave the link failing exactly as before.

Two shapes have to be handled and both occur in a generated project: a list,
which Xcode may spread over several lines, and a bare scalar. Matching only
single lines misses the multi-line form and appends a duplicate key — which is
the failure this is meant to prevent.

Not matched by balanced parentheses either: these values contain `$(inherited)`
and `$(SRCROOT)`, so a `[^)]*` pattern stops at the first `)` inside a variable
reference and never sees the setting at all. `\);` is the reliable terminator,
since a `)` inside a variable reference is never followed by a semicolon.
"""
import re
import sys

pbx, xcf = sys.argv[1], sys.argv[2]
# One path, not two. Putting both slices on the search path made the linker
# take whichever came first, and it does not skip an architecture that does not
# match — it stops with "building for iOS-simulator, but linking in object file
# built for iOS". $(PLATFORM_NAME) is iphoneos or iphonesimulator, so the
# caller arranges the slices under those names and Xcode picks.
add = {
    "FRAMEWORK_SEARCH_PATHS": f'"{xcf}/$(PLATFORM_NAME)"',
    "OTHER_LDFLAGS": '"-framework", "tor"',
}

s = open(pbx).read()
blocks = s.count("buildSettings = {")


def merge(setting: str, additions: str, body: str) -> str:
    # Already applied. Checked on the value, not the key: running twice
    # otherwise appends the same path again, which is harmless to the build but
    # makes "idempotent" untrue and the test that asserts it meaningless.
    if additions in body:
        return body

    # A list, possibly spanning lines.
    lst = re.compile(rf"^([ \t]*){setting} = \((.*?)\);", re.M | re.S)
    m = lst.search(body)
    if m:
        indent, inner = m.group(1), m.group(2).strip().rstrip(",")
        merged = f"{indent}{setting} = ({inner}, {additions});"
        return lst.sub(lambda _: merged, body, count=1)

    # A bare scalar on one line.
    scalar = re.compile(rf"^([ \t]*){setting} = ([^(\n][^;]*);[ \t]*$", re.M)
    m = scalar.search(body)
    if m:
        indent, value = m.group(1), m.group(2).strip()
        merged = f"{indent}{setting} = ({value}, {additions});"
        return scalar.sub(lambda _: merged, body, count=1)

    return f'\n\t\t\t\t{setting} = ("$(inherited)", {additions});' + body


def patch(m: re.Match) -> str:
    body = m.group(1)
    for setting, additions in add.items():
        body = merge(setting, additions, body)
    return "buildSettings = {" + body + "};"


s = re.sub(r"buildSettings = \{(.*?)\};", patch, s, flags=re.S)
open(pbx, "w").write(s)

out = open(pbx).read()
configs = re.findall(r"buildSettings = \{(.*?)\};", out, re.S)
assert len(configs) == blocks, f"{len(configs)} blocks after, {blocks} before"

for i, b in enumerate(configs, 1):
    # Checked per block rather than per line: Xcode writes lists across several
    # lines, so the setting name and the value it gained are not on one line.
    assert "$(PLATFORM_NAME)" in b, f"block {i}: tor search path missing"
    assert '"-framework", "tor"' in b, f"block {i}: tor ldflag missing"
    for setting in add:
        n = len(re.findall(rf"^[ \t]*{setting} = ", b, re.M))
        assert n == 1, f"block {i}: {setting} appears {n} times"

print(f"linked tor into all {blocks} build configurations, no duplicate keys")
