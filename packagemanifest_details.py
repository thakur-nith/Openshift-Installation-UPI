#!/usr/bin/env python3
"""
pm_details.py - Extract useful details from OpenShift/OLM PackageManifests.

Fetches all packagemanifests with ONE `oc get ... -o json` call (fast), then
filters and reports locally. It can also read a saved JSON dump instead, so it
works offline or on a bastion without cluster access.

Per package:
  Package name, display name, provider, catalog source (+ display name,
  publisher, namespace), default channel, deprecation (if any)
Per channel:
  Channel name, current CSV, version, container image, capabilities,
  categories, suggested namespace, supported install modes, skipRange,
  min Kube version, created-at, repository, all CSV entries in the channel,
  owned CRDs (name / version / kind), required CRDs, API services,
  alm-examples (apiVersion / kind of the sample CRs), related images.

Examples:
  ./pm_details.py                                   # all packages, text report
  ./pm_details.py pulp-operator                     # one or more packages
  ./pm_details.py -f packages.txt                   # names from a file (one per line)
  ./pm_details.py -c redhat-operators               # only one catalog source
  ./pm_details.py --default-only                    # only the default channel
  ./pm_details.py -o csv  > pm.csv                  # one row per channel
  ./pm_details.py -o crd-csv > crds.csv             # one row per owned CRD
  ./pm_details.py -o json > pm.json                 # cleaned structured JSON
  ./pm_details.py --images-only | sort -u           # every image (for mirroring)
  oc get packagemanifests -n openshift-marketplace -o json > all.json
  ./pm_details.py -i all.json pulp-operator         # offline
"""

import argparse
import csv
import json
import shutil
import subprocess
import sys

# ----------------------------------------------------------------------------
# Data collection
# ----------------------------------------------------------------------------

def run_oc(namespace, cli):
    cmd = [cli, "get", "packagemanifests", "-o", "json"]
    cmd += ["-A"] if namespace == "all" else ["-n", namespace]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit(f"ERROR: '{cli}' not found in PATH")
    except subprocess.CalledProcessError as e:
        sys.exit(f"ERROR running {' '.join(cmd)}:\n{e.stderr.strip()}")
    return json.loads(out.stdout)


def load_input(path):
    with open(path) as fh:
        data = json.load(fh)
    # Accept a List, or a single PackageManifest object
    if data.get("kind") == "PackageManifest":
        return {"items": [data]}
    return data


# ----------------------------------------------------------------------------
# Parsing helpers
# ----------------------------------------------------------------------------

def parse_alm_examples(raw):
    """alm-examples is a JSON string listing sample CRs. Return [(apiVersion, kind, name)]."""
    if not raw:
        return []
    try:
        items = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if isinstance(items, dict):
        items = [items]
    out = []
    for it in items if isinstance(items, list) else []:
        if isinstance(it, dict):
            out.append({
                "apiVersion": it.get("apiVersion", ""),
                "kind": it.get("kind", ""),
                "name": (it.get("metadata") or {}).get("name", ""),
            })
    return out


def parse_channel(ch):
    d = ch.get("currentCSVDesc") or {}
    ann = d.get("annotations") or {}
    crds = d.get("customresourcedefinitions") or {}
    apis = d.get("apiservicedefinitions") or {}

    install_modes = [m.get("type") for m in d.get("installModes") or [] if m.get("supported")]

    related = []
    for ri in d.get("relatedImages") or []:
        # relatedImages is a list of strings in PackageManifest; be tolerant of dicts
        related.append(ri.get("image") if isinstance(ri, dict) else ri)

    entries = [
        {"name": e.get("name", ""), "version": e.get("version", "")}
        for e in ch.get("entries") or []
    ]

    return {
        "channel": ch.get("name", ""),
        "currentCSV": ch.get("currentCSV", ""),
        "displayName": d.get("displayName", ""),
        "version": d.get("version", ""),
        "containerImage": ann.get("containerImage", ""),
        "capabilities": ann.get("capabilities", ""),
        "categories": ann.get("categories", ""),
        "suggestedNamespace": ann.get("operatorframework.io/suggested-namespace", ""),
        "operatorHubUI": ann.get("operators.operatorframework.io/operator-hub-ui", ""),
        "infrastructureFeatures": ann.get("operators.openshift.io/infrastructure-features", ""),
        "validSubscription": ann.get("operators.openshift.io/valid-subscription", ""),
        "skipRange": ann.get("olm.skipRange", ""),
        "createdAt": ann.get("createdAt", ""),
        "repository": ann.get("repository", ""),
        "support": ann.get("support", ""),
        "minKubeVersion": d.get("minKubeVersion", ""),
        "installModes": install_modes,
        "keywords": d.get("keywords") or [],
        "links": [f"{l.get('name','')}: {l.get('url','')}" for l in d.get("links") or []],
        "maintainers": [f"{m.get('name','')} <{m.get('email','')}>" for m in d.get("maintainers") or []],
        "description": (d.get("description") or "").strip(),
        "ownedCRDs": [
            {"name": c.get("name", ""), "version": c.get("version", ""),
             "kind": c.get("kind", ""), "displayName": c.get("displayName", "")}
            for c in crds.get("owned") or []
        ],
        "requiredCRDs": [
            {"name": c.get("name", ""), "version": c.get("version", ""), "kind": c.get("kind", "")}
            for c in crds.get("required") or []
        ],
        "ownedAPIServices": [
            f"{a.get('group','')}/{a.get('version','')} {a.get('kind','')}"
            for a in apis.get("owned") or []
        ],
        "nativeAPIs": [
            f"{a.get('group','') or 'core'}/{a.get('version','')} {a.get('kind','')}"
            for a in d.get("nativeAPIs") or []
        ],
        "almExamples": parse_alm_examples(ann.get("alm-examples")),
        "relatedImages": [r for r in related if r],
        "entries": entries,
        "deprecation": (ch.get("deprecation") or {}).get("message", ""),
    }


def parse_package(item, default_only=False):
    md = item.get("metadata") or {}
    st = item.get("status") or {}
    prov = st.get("provider") or {}
    default = st.get("defaultChannel", "")
    channels = [parse_channel(c) for c in st.get("channels") or []]
    if default_only:
        channels = [c for c in channels if c["channel"] == default]
    # default channel first, rest alphabetical
    channels.sort(key=lambda c: (c["channel"] != default, c["channel"]))
    return {
        "package": st.get("packageName") or md.get("name", ""),
        "namespace": md.get("namespace", ""),
        "catalogSource": st.get("catalogSource", ""),
        "catalogSourceDisplayName": st.get("catalogSourceDisplayName", ""),
        "catalogSourcePublisher": st.get("catalogSourcePublisher", ""),
        "catalogSourceNamespace": st.get("catalogSourceNamespace", ""),
        "provider": prov.get("name", ""),
        "providerURL": prov.get("url", ""),
        "defaultChannel": default,
        "deprecation": (st.get("deprecation") or {}).get("message", ""),
        "channelCount": len(st.get("channels") or []),
        "channels": channels,
    }


# ----------------------------------------------------------------------------
# Output formats
# ----------------------------------------------------------------------------

def _wrap(text, width=100, indent="      "):
    import textwrap
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent)


def print_text(pkgs, show_desc, show_images, show_entries):
    line = "=" * 100
    for p in pkgs:
        print(line)
        print(f"Package:                   {p['package']}")
        print(f"Provider:                  {p['provider']}" + (f"  ({p['providerURL']})" if p['providerURL'] else ""))
        print(f"Catalog Source:            {p['catalogSource']}"
              + (f"  [{p['catalogSourceDisplayName']}]" if p['catalogSourceDisplayName'] else ""))
        print(f"Catalog Source Publisher:  {p['catalogSourcePublisher']}")
        print(f"Catalog Source Namespace:  {p['catalogSourceNamespace']}")
        print(f"Default Channel:           {p['defaultChannel']}")
        print(f"Channels ({p['channelCount']}):              "
              + ", ".join(c["channel"] for c in p["channels"]))
        if p["deprecation"]:
            print(f"DEPRECATED:                {p['deprecation']}")

        for c in p["channels"]:
            tag = "  (default)" if c["channel"] == p["defaultChannel"] else ""
            print("-" * 100)
            print(f"  Channel:              {c['channel']}{tag}")
            if c["deprecation"]:
                print(f"    DEPRECATED:         {c['deprecation']}")
            print(f"    Current CSV:        {c['currentCSV']}")
            print(f"    Display Name:       {c['displayName']}")
            print(f"    Version:            {c['version']}")
            print(f"    Container Image:    {c['containerImage']}")
            print(f"    Capabilities:       {c['capabilities']}")
            print(f"    Categories:         {c['categories']}")
            print(f"    Install Modes:      {', '.join(c['installModes'])}")
            if c["suggestedNamespace"]:
                print(f"    Suggested NS:       {c['suggestedNamespace']}")
            if c["skipRange"]:
                print(f"    Skip Range:         {c['skipRange']}")
            if c["minKubeVersion"]:
                print(f"    Min Kube Version:   {c['minKubeVersion']}")
            if c["createdAt"]:
                print(f"    Created At:         {c['createdAt']}")
            if c["repository"]:
                print(f"    Repository:         {c['repository']}")
            if c["infrastructureFeatures"]:
                print(f"    Infra Features:     {c['infrastructureFeatures']}")
            if c["validSubscription"]:
                print(f"    Valid Subscription: {c['validSubscription']}")

            print(f"    Owned CRDs ({len(c['ownedCRDs'])}):")
            for crd in c["ownedCRDs"]:
                print(f"      - {crd['name']:<55} {crd['version']:<10} {crd['kind']}")
            if c["requiredCRDs"]:
                print(f"    Required CRDs ({len(c['requiredCRDs'])}):")
                for crd in c["requiredCRDs"]:
                    print(f"      - {crd['name']:<55} {crd['version']:<10} {crd['kind']}")
            if c["ownedAPIServices"]:
                print("    Owned API Services:")
                for a in c["ownedAPIServices"]:
                    print(f"      - {a}")
            if c["almExamples"]:
                print(f"    Sample CRs / alm-examples ({len(c['almExamples'])}):")
                for ex in c["almExamples"]:
                    print(f"      - apiVersion: {ex['apiVersion']:<40} kind: {ex['kind']:<25} name: {ex['name']}")
            if show_entries and c["entries"]:
                print(f"    CSVs in channel ({len(c['entries'])}):")
                for e in c["entries"]:
                    print(f"      - {e['name']}" + (f"  ({e['version']})" if e['version'] else ""))
            if show_images and c["relatedImages"]:
                print(f"    Related Images ({len(c['relatedImages'])}):")
                for img in c["relatedImages"]:
                    print(f"      - {img}")
            if show_desc and c["description"]:
                print("    Description:")
                print(_wrap(c["description"].replace("\n", " ")))
    print(line)
    print(f"Total packages: {len(pkgs)}")


CSV_FIELDS = [
    "package", "provider", "catalogSource", "catalogSourceNamespace", "defaultChannel",
    "channel", "isDefault", "currentCSV", "version", "containerImage", "capabilities",
    "categories", "installModes", "suggestedNamespace", "skipRange", "minKubeVersion",
    "createdAt", "ownedCRDCount", "ownedCRDs", "requiredCRDs", "almExampleKinds",
    "entryCount", "relatedImageCount", "deprecation",
]


def write_csv(pkgs):
    w = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDS)
    w.writeheader()
    for p in pkgs:
        for c in p["channels"]:
            w.writerow({
                "package": p["package"],
                "provider": p["provider"],
                "catalogSource": p["catalogSource"],
                "catalogSourceNamespace": p["catalogSourceNamespace"],
                "defaultChannel": p["defaultChannel"],
                "channel": c["channel"],
                "isDefault": c["channel"] == p["defaultChannel"],
                "currentCSV": c["currentCSV"],
                "version": c["version"],
                "containerImage": c["containerImage"],
                "capabilities": c["capabilities"],
                "categories": c["categories"],
                "installModes": ";".join(c["installModes"]),
                "suggestedNamespace": c["suggestedNamespace"],
                "skipRange": c["skipRange"],
                "minKubeVersion": c["minKubeVersion"],
                "createdAt": c["createdAt"],
                "ownedCRDCount": len(c["ownedCRDs"]),
                "ownedCRDs": ";".join(f"{x['name']}/{x['version']}" for x in c["ownedCRDs"]),
                "requiredCRDs": ";".join(f"{x['name']}/{x['version']}" for x in c["requiredCRDs"]),
                "almExampleKinds": ";".join(f"{x['apiVersion']}/{x['kind']}" for x in c["almExamples"]),
                "entryCount": len(c["entries"]),
                "relatedImageCount": len(c["relatedImages"]),
                "deprecation": c["deprecation"] or p["deprecation"],
            })


def write_crd_csv(pkgs):
    fields = ["package", "catalogSource", "channel", "currentCSV", "crdName", "crdVersion", "kind", "displayName"]
    w = csv.DictWriter(sys.stdout, fieldnames=fields)
    w.writeheader()
    for p in pkgs:
        for c in p["channels"]:
            for crd in c["ownedCRDs"]:
                w.writerow({
                    "package": p["package"], "catalogSource": p["catalogSource"],
                    "channel": c["channel"], "currentCSV": c["currentCSV"],
                    "crdName": crd["name"], "crdVersion": crd["version"],
                    "kind": crd["kind"], "displayName": crd["displayName"],
                })


def print_summary(pkgs):
    rows = [("PACKAGE", "CATALOG", "DEFAULT", "CURRENT CSV (default)", "CHANNELS", "CRDS")]
    for p in pkgs:
        dc = next((c for c in p["channels"] if c["channel"] == p["defaultChannel"]), None)
        rows.append((
            p["package"], p["catalogSource"], p["defaultChannel"],
            dc["currentCSV"] if dc else "-", str(p["channelCount"]),
            str(len(dc["ownedCRDs"])) if dc else "-",
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        print("  ".join(v.ljust(widths[i]) for i, v in enumerate(r)))


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Extract details from OpenShift PackageManifests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[1] if "Examples:" in __doc__ else "",
    )
    ap.add_argument("packages", nargs="*", help="package names to include (default: all)")
    ap.add_argument("-f", "--file", help="file with package names, one per line (# comments ok)")
    ap.add_argument("-n", "--namespace", default="openshift-marketplace",
                    help="namespace to query, or 'all' (default: openshift-marketplace)")
    ap.add_argument("-c", "--catalog", action="append",
                    help="only this catalog source (repeatable), e.g. redhat-operators")
    ap.add_argument("-i", "--input", help="read a saved 'oc get packagemanifests -o json' file instead of the cluster")
    ap.add_argument("-o", "--output", default="text",
                    choices=["text", "summary", "csv", "crd-csv", "json"], help="output format")
    ap.add_argument("--default-only", action="store_true", help="only show the default channel")
    ap.add_argument("--desc", action="store_true", help="include the operator description (text mode)")
    ap.add_argument("--images", action="store_true", help="include related images (text mode)")
    ap.add_argument("--entries", action="store_true", help="list every CSV in each channel (text mode)")
    ap.add_argument("--images-only", action="store_true",
                    help="print only image references (container + related), one per line")
    ap.add_argument("--cli", default=None, help="CLI to use (default: oc, falls back to kubectl)")
    args = ap.parse_args()

    # Wanted package names
    wanted = set(args.packages)
    if args.file:
        with open(args.file) as fh:
            for ln in fh:
                ln = ln.split("#", 1)[0].strip()
                if ln:
                    # tolerate "packagemanifest.packages.operators.coreos.com/foo" style lines
                    wanted.add(ln.split("/")[-1].split()[0])

    # Load data
    if args.input:
        data = load_input(args.input)
    else:
        cli = args.cli or ("oc" if shutil.which("oc") else "kubectl")
        data = run_oc(args.namespace, cli)

    items = data.get("items") or []
    if wanted:
        items = [i for i in items
                 if (i.get("metadata") or {}).get("name") in wanted
                 or (i.get("status") or {}).get("packageName") in wanted]
    if args.catalog:
        cats = set(args.catalog)
        items = [i for i in items if (i.get("status") or {}).get("catalogSource") in cats]

    pkgs = [parse_package(i, args.default_only) for i in items]
    pkgs.sort(key=lambda p: (p["package"], p["catalogSource"]))

    if wanted:
        found = {p["package"] for p in pkgs}
        missing = sorted(wanted - found)
        if missing:
            print(f"WARNING: not found: {', '.join(missing)}", file=sys.stderr)

    if not pkgs:
        sys.exit("No matching packagemanifests found.")

    if args.images_only:
        for p in pkgs:
            for c in p["channels"]:
                for img in [c["containerImage"], *c["relatedImages"]]:
                    if img:
                        print(img)
        return

    if args.output == "text":
        print_text(pkgs, args.desc, args.images, args.entries)
    elif args.output == "summary":
        print_summary(pkgs)
    elif args.output == "csv":
        write_csv(pkgs)
    elif args.output == "crd-csv":
        write_crd_csv(pkgs)
    elif args.output == "json":
        json.dump(pkgs, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
