#!/usr/bin/env python3
"""Collect distribution notices from the Go sources used for Hop's iOS slices."""

import argparse
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "XrayBridge" / "Acknowledgments.txt"
NOTICE = re.compile(r"(?:licen[cs]e|copying|copyright|notice|patents|unlicense)(?:$|[-_.].*)", re.I)
# Some upstream packages carry separate third-party licenses inside the
# compiled sources (e.g. quic-go's AVL tree and Go's FreeBSD math routines).
LICENSE_TERMS = re.compile(
    rb"redistribution and use|permission is hereby granted|permission to use, copy|"
    rb"the software is provided|redistributions in binary form|this software is provided|"
    rb"licensed under the Apache License|this (?:program|library) is free software", re.I,
)
COMMENTS = re.compile(rb"/\*.*?\*/|(?:^[ \t]*//[^\n]*(?:\n|$))+", re.S | re.M)


def go(bridge, *args, **env):
    return subprocess.check_output(
        ["go", *args], cwd=bridge,
        env={**os.environ, "GOWORK": "off", "GOFLAGS": "", **env}, text=True,
    ).strip()


def section(title, content):
    lines = content.strip("\n").splitlines()
    return f"{title}\n{'=' * len(title)}\n\n" + "\n".join(line.rstrip() for line in lines) + "\n"


def document(title, path):
    return section(title, path.read_text(encoding="utf-8"))


def acknowledgments(bridge):
    goroot = Path(go(bridge, "env", "GOROOT"))
    goversion = go(bridge, "env", "GOVERSION")
    required = re.search(r"^go (\S+)$", (bridge / "go.mod").read_text(), re.MULTILINE)
    if not required or goversion != "go" + required[1]:
        raise SystemExit("Use the exact Go toolchain specified by XrayBridge/go.mod")
    go_dirs = {goroot}
    modules = {}
    sources = {}
    row = ('{{.Dir}}\t{{if .Module}}{{.Module.Path}}\t{{.Module.Version}}\t{{.Module.Dir}}{{end}}\t'
           '{{range .GoFiles}}{{.}}|{{end}}{{range .CgoFiles}}{{.}}|{{end}}{{range .CFiles}}{{.}}|{{end}}'
           '{{range .CXXFiles}}{{.}}|{{end}}{{range .HFiles}}{{.}}|{{end}}{{range .SFiles}}{{.}}|{{end}}')
    for arch in ["arm64", "amd64"]:
        packages = go(
            bridge, "list", "-mod=readonly", "-deps", "-f", row, ".", "golang.org/x/mobile/bind/seq",
            GOOS="ios", GOARCH=arch, CGO_ENABLED="1",
        )
        for line in packages.splitlines():
            directory, module = line.split("\t", 1)
            module, files = module.rsplit("\t", 1)
            path = Path(directory)
            if module:
                name, version, source = module.split("\t")
                source = Path(source)
                if source.resolve() == bridge:
                    continue
                if not version:
                    raise SystemExit(f"Missing module version for {name}")
                label = name + " " + version
                modules[label] = source
            else:
                label, source = goversion, goroot
                go_dirs.add(path)
                go_dirs.update(p for p in path.parents if goroot in p.parents)
            for file in filter(None, files.split("|")):
                filename = path / file
                sources[f"{label} / {filename.relative_to(source)}"] = filename

    sections = [
        "Hop acknowledgments\n\nHop source, including changes to Xray-core, is available at "
        "https://github.com/6a6179/Hop. Each release identifies its source commit.\n",
        document("Routing data", ROOT / "Geodata" / "NOTICE.txt"),
        document("Hop", ROOT / "LICENSE"),
    ]
    # Go ships some vendored standard-library packages with additional notices.
    std_notices = {
        p.relative_to(goroot): p
        for directory in go_dirs for p in directory.iterdir() if p.is_file() and NOTICE.fullmatch(p.name)
    }
    license_name = Path("LICENSE")
    if license_name not in std_notices:
        # Homebrew keeps GOROOT in libexec and installs Go's LICENSE at the keg root.
        keg_license = goroot.parent / license_name
        homebrew_layout = goroot.name == "libexec" and (goroot.parent / "INSTALL_RECEIPT.json").is_file()
        if not homebrew_layout or not keg_license.is_file():
            raise SystemExit(f"Go toolchain license is missing for GOROOT {goroot}")
        std_notices[license_name] = keg_license
    sections.extend(document(f"{goversion} / {name}", path) for name, path in sorted(std_notices.items()))
    for module, source in sorted(modules.items()):
        # Include secondary licenses and package-specific exceptions as well as
        # the root license. Missing upstream notices must fail the release check.
        notices = sorted(
            p for p in source.rglob("*")
            if p.is_file() and (NOTICE.fullmatch(p.name) or p.name.lower().endswith(".license"))
        )
        if not any(p.parent == source and p.name.lower().startswith(("licen", "copying", "unlicense")) for p in notices):
            raise SystemExit(f"No top-level license found for {module}")
        sections.extend(document(f"{module} / {p.relative_to(source)}", p) for p in notices)
    for title, filename in sorted(sources.items()):
        data = filename.read_bytes()
        if LICENSE_TERMS.search(data):
            for block in COMMENTS.findall(data):
                if LICENSE_TERMS.search(block):
                    sections.append(section(title, block.decode("utf-8")))
    return "\n".join(sections).encode("utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--bridge-directory", type=Path, default=ROOT / "XrayBridge")
    args = parser.parse_args()
    expected = acknowledgments(args.bridge_directory.resolve())
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != expected:
            raise SystemExit(f"Stale {OUTPUT.name}. Run scripts/generate-acknowledgments.py.")
    else:
        OUTPUT.write_bytes(expected)
