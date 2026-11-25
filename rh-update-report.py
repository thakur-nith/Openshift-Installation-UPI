#!/usr/bin/env python3
"""Show which installed Red Hat operators have newer versions in a mirrored catalog.
Usage: python3 rh-update-report.py <catalog dir, e.g. .../operator-catalogs/redhat-operator-index/<hash>>"""
import json, glob, re, sys

INSTALLED = {  # package: (subscription channel, installed version)
    "cluster-logging":                 ("stable-6.3",  "6.3.0"),
    "loki-operator":                   ("stable-6.3",  "6.3.0"),
    "cluster-observability-operator":  ("stable",      "1.2.2"),
    "openshift-cert-manager-operator": ("stable-v1",   "1.17.0"),
    "metallb-operator":                ("stable",      "4.18.0-202508201347"),
    "kubernetes-nmstate-operator":     ("stable",      "4.18.0-202508271223"),
    "kubevirt-hyperconverged":         ("stable",      "4.18.13"),
    "openstack-operator":              ("stable-v1.0", "1.0.13"),
}

def vkey(v):
    core, _, pre = v.partition("-")
    nums = tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.]", core))
    return (nums, pre == "", pre)          # release sorts after its pre-release, as in semver

def load(pkg_dir):
    dec, objs = json.JSONDecoder(), []
    for f in glob.glob(pkg_dir + "/*.json"):
        s, i = open(f).read(), 0
        while True:
            while i < len(s) and s[i].isspace(): i += 1
            if i >= len(s): break
            o, i = dec.raw_decode(s, i); objs.append(o)
    return objs

root = sys.argv[1].rstrip("/")
print(f"{'OPERATOR':34} {'CHANNEL':12} {'INSTALLED':22} {'NEWEST IN CHANNEL':22} NEWER VERSIONS")
for pkg, (ch, inst) in INSTALLED.items():
    objs = load(f"{root}/catalog-config/configs/{pkg}")
    if not objs:
        print(f"{pkg:34} {ch:12} {inst:22} {'NOT IN CATALOG':22}"); continue
    ver = {o["name"]: p["value"]["version"] for o in objs if o.get("schema") == "olm.bundle"
           for p in o.get("properties", []) if p.get("type") == "olm.package"}
    chan = next((o for o in objs if o.get("schema") == "olm.channel" and o["name"] == ch), None)
    if not chan:
        print(f"{pkg:34} {ch:12} {inst:22} {'CHANNEL MISSING':22}"); continue
    vs = sorted({ver[e["name"]] for e in chan["entries"] if e["name"] in ver}, key=vkey)
    newer = [v for v in vs if vkey(v) > vkey(inst)]
    head = vs[-1] if vs else "-"
    flag = f"{len(newer)}: " + ", ".join(newer[-3:]) + (" ..." if len(newer) > 3 else "") if newer else "none (up to date)"
    print(f"{pkg:34} {ch:12} {inst:22} {head:22} {flag}")
    others = sorted(o["name"] for o in objs if o.get("schema") == "olm.channel" and o["name"] != ch)
    if others: print(f"{'':34} other channels: {', '.join(others)}")
