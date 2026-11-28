#!/usr/bin/env python3
"""
csv_details.py - Report useful details from OLM ClusterServiceVersions (CSVs).

Reads CSVs live from the cluster (one `oc get csv -o json` call) or from a saved
JSON/YAML file, and reports what matters for day-2 / production work:

  Identity     name, namespace, version, provider, maturity, capabilities
  Status       phase, reason, message, last transition, unmet requirements
  Upgrade      replaces, skips, olm.skipRange, maxOpenShiftVersion, min kube
  OLM          OperatorGroup, operator namespace, target namespaces, install modes,
               cleanup setting, finalizers
  Subscription (live) channel, source catalog, approval, state, installed vs
               current CSV -> shows pending upgrades
  APIs         owned / required CRDs, API services, webhooks, sample CRs
  Workload     deployments, replicas, containers, images, resources, probes,
               node placement, service accounts
  Images       container + relatedImages (mirroring list)
  RBAC         namespaced + cluster permissions per service account, with
               wildcard / high-risk rules flagged
  Drift (live) running Deployment images/readiness vs what the CSV declares

Copied CSVs (the read-only copies OLM puts in every namespace for AllNamespaces
operators) are skipped by default; use --include-copied to see them.

Examples:
  ./csv_details.py                              # all CSVs, all namespaces, text report
  ./csv_details.py -o summary                   # one line per CSV
  ./csv_details.py hspc                         # name contains "hspc"
  ./csv_details.py -n example example-operator  # one namespace
  ./csv_details.py --not-succeeded -o summary   # anything not healthy
  ./csv_details.py --live hspc                  # + Subscription and Deployment drift
  ./csv_details.py --rbac hspc                  # include full RBAC rules
  ./csv_details.py -o images | sort -u          # every image, for mirroring
  ./csv_details.py -o csv > csvs.csv            # spreadsheet, one row per CSV
  ./csv_details.py -o json > csvs.json
  oc get csv -A -o json > all-csv.json && ./csv_details.py -i all-csv.json
  ./csv_details.py -i example-operator.v0.0.2.yaml       # YAML needs PyYAML
"""

import argparse
import csv
import json
import shutil
import subprocess
import sys

# ----------------------------------------------------------------------------
# Cluster / file access
# ----------------------------------------------------------------------------

CLI = None


def oc_json(args, allow_fail=False):
    cmd = [CLI] + args + ["-o", "json"]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit(f"ERROR: '{CLI}' not found in PATH")
    except subprocess.CalledProcessError as e:
        if allow_fail:
            return None
        sys.exit(f"ERROR running {' '.join(cmd)}:\n{e.stderr.strip()}")
    return json.loads(out.stdout)


def load_file(path):
    with open(path) as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except ValueError:
        try:
            import yaml
        except ImportError:
            sys.exit("ERROR: file is not JSON and PyYAML is not installed "
                     "(dnf install python3-pyyaml, or save with -o json)")
        docs = [d for d in yaml.safe_load_all(text) if d]
        data = docs[0] if len(docs) == 1 else {"items": docs}
    if isinstance(data, dict) and data.get("kind") == "ClusterServiceVersion":
        return [data]
    return (data or {}).get("items", [])


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def g(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p)
        if d is None:
            return default
    return d


def parse_properties(ann):
    """Return list of {type, value} from operatorframework.io/properties or olm.properties."""
    props = []
    raw = ann.get("operatorframework.io/properties")
    if raw:
        try:
            props += json.loads(raw).get("properties", [])
        except (ValueError, AttributeError):
            pass
    raw = ann.get("olm.properties")
    if raw:
        try:
            v = json.loads(raw)
            props += v if isinstance(v, list) else []
        except ValueError:
            pass
    return props


def parse_alm_examples(raw):
    if not raw:
        return []
    try:
        items = json.loads(raw)
    except ValueError:
        return []
    items = items if isinstance(items, list) else [items]
    return [{"apiVersion": i.get("apiVersion", ""), "kind": i.get("kind", ""),
             "name": g(i, "metadata", "name", default="")}
            for i in items if isinstance(i, dict)]


HIGH_RISK_RESOURCES = {"secrets", "clusterroles", "clusterrolebindings", "roles",
                       "rolebindings", "securitycontextconstraints", "nodes",
                       "customresourcedefinitions", "mutatingwebhookconfigurations",
                       "validatingwebhookconfigurations", "pods/exec"}


def rule_flags(rule):
    flags = []
    verbs = rule.get("verbs") or []
    res = rule.get("resources") or []
    groups = rule.get("apiGroups") or []
    if "*" in verbs:
        flags.append("ALL-VERBS")
    if "*" in res:
        flags.append("ALL-RESOURCES")
    if "*" in groups:
        flags.append("ALL-GROUPS")
    risky = sorted(set(res) & HIGH_RISK_RESOURCES)
    if risky and any(v in verbs for v in ("*", "create", "update", "patch", "delete", "get", "list")):
        flags.append("SENSITIVE:" + ",".join(risky))
    if any(v in verbs for v in ("escalate", "bind", "impersonate")):
        flags.append("PRIV-VERB")
    return flags


def fmt_rule(rule):
    if rule.get("nonResourceURLs"):
        return f"nonResourceURLs={','.join(rule['nonResourceURLs'])} verbs={','.join(rule.get('verbs') or [])}"
    groups = ",".join(x if x else "core" for x in (rule.get("apiGroups") or [""]))
    names = f" names={','.join(rule['resourceNames'])}" if rule.get("resourceNames") else ""
    return f"[{groups}] {','.join(rule.get('resources') or [])} : {','.join(rule.get('verbs') or [])}{names}"


def summarize_affinity(aff):
    out = []
    terms = g(aff, "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution",
              "nodeSelectorTerms", default=[]) or []
    for t in terms:
        for e in t.get("matchExpressions") or []:
            out.append(f"{e.get('key')} {e.get('operator')} {','.join(e.get('values') or [])}")
    if g(aff, "podAntiAffinity"):
        out.append("podAntiAffinity set")
    return out


# ----------------------------------------------------------------------------
# Parse a CSV into a flat-ish dict
# ----------------------------------------------------------------------------

def parse_csv(obj):
    md = obj.get("metadata") or {}
    spec = obj.get("spec") or {}
    st = obj.get("status") or {}
    ann = md.get("annotations") or {}
    labels = md.get("labels") or {}
    props = parse_properties(ann)

    max_ocp = ann.get("olm.maxOpenShiftVersion", "")
    for p in props:
        if p.get("type") == "olm.maxOpenShiftVersion":
            max_ocp = str(p.get("value"))
    required_pkgs = [json.dumps(p.get("value"), separators=(",", ":"))
                     for p in props if p.get("type") in ("olm.package.required", "olm.gvk.required", "olm.constraint")]

    # Deployments
    deployments = []
    images = []
    for d in g(spec, "install", "spec", "deployments", default=[]) or []:
        ps = g(d, "spec", "template", "spec", default={}) or {}
        containers = []
        for kind, clist in (("init", ps.get("initContainers") or []), ("main", ps.get("containers") or [])):
            for c in clist:
                images.append(c.get("image", ""))
                containers.append({
                    "type": kind,
                    "name": c.get("name", ""),
                    "image": c.get("image", ""),
                    "requests": g(c, "resources", "requests", default={}) or {},
                    "limits": g(c, "resources", "limits", default={}) or {},
                    "liveness": bool(c.get("livenessProbe")),
                    "readiness": bool(c.get("readinessProbe")),
                    "ports": [f"{p.get('containerPort')}/{p.get('protocol','TCP')}" for p in c.get("ports") or []],
                    "args": c.get("args") or [],
                    "env": [e.get("name") for e in c.get("env") or []],
                    "privileged": bool(g(c, "securityContext", "privileged")),
                })
        deployments.append({
            "name": d.get("name", ""),
            "replicas": g(d, "spec", "replicas", default=1),
            "strategy": g(d, "spec", "strategy", "type", default="") or "RollingUpdate(default)",
            "serviceAccount": ps.get("serviceAccountName", ""),
            "nodeSelector": ps.get("nodeSelector") or {},
            "tolerations": [f"{t.get('key','*')}:{t.get('effect','')}" for t in ps.get("tolerations") or []],
            "affinity": summarize_affinity(ps.get("affinity") or {}),
            "priorityClass": ps.get("priorityClassName", ""),
            "hostNetwork": bool(ps.get("hostNetwork")),
            "runAsNonRoot": g(ps, "securityContext", "runAsNonRoot"),
            "containers": containers,
        })

    related = [r.get("image") if isinstance(r, dict) else r for r in spec.get("relatedImages") or []]
    container_image = ann.get("containerImage", "")
    all_images = sorted(set(i for i in images + related + [container_image] if i))

    def perms(key):
        out = []
        for p in g(spec, "install", "spec", key, default=[]) or []:
            rules = p.get("rules") or []
            out.append({
                "serviceAccount": p.get("serviceAccountName", ""),
                "rules": [{"rule": fmt_rule(r), "flags": rule_flags(r)} for r in rules],
            })
        return out

    # Requirements that are not satisfied
    unmet = []
    for r in st.get("requirementStatus") or []:
        if r.get("status") not in ("Present", "Satisfied"):
            unmet.append(f"{r.get('kind')} {r.get('name')}: {r.get('status')} {r.get('message','')}".strip())
        for dep in r.get("dependents") or []:
            if dep.get("status") not in ("Present", "Satisfied"):
                unmet.append(f"{dep.get('kind')}: {dep.get('status')} {dep.get('message','')}".strip())

    crds = g(spec, "customresourcedefinitions", default={}) or {}
    apis = g(spec, "apiservicedefinitions", default={}) or {}

    return {
        "name": md.get("name", ""),
        "namespace": md.get("namespace", ""),
        "displayName": spec.get("displayName", ""),
        "version": spec.get("version", ""),
        "provider": g(spec, "provider", "name", default=""),
        "maturity": spec.get("maturity", ""),
        "capabilities": ann.get("capabilities", ""),
        "created": md.get("creationTimestamp", ""),
        "copied": labels.get("olm.copiedFrom", "") or ("yes" if st.get("reason") == "Copied" else ""),
        # status
        "phase": st.get("phase", ""),
        "reason": st.get("reason", ""),
        "message": st.get("message", ""),
        "lastTransition": st.get("lastTransitionTime", ""),
        "unmetRequirements": unmet,
        "conditions": [f"{c.get('lastTransitionTime','')}  {c.get('phase',''):<13} {c.get('reason',''):<22} {c.get('message','')}"
                       for c in st.get("conditions") or []],
        # upgrade
        "replaces": spec.get("replaces", ""),
        "skips": spec.get("skips") or [],
        "skipRange": ann.get("olm.skipRange", ""),
        "maxOpenShiftVersion": max_ocp,
        "minKubeVersion": spec.get("minKubeVersion", ""),
        "requires": required_pkgs,
        # OLM
        "operatorGroup": ann.get("olm.operatorGroup", ""),
        "operatorNamespace": ann.get("olm.operatorNamespace", ""),
        "targetNamespaces": ann.get("olm.targetNamespaces", "") or "(all namespaces)",
        "installModes": [m.get("type") for m in spec.get("installModes") or [] if m.get("supported")],
        "cleanupEnabled": bool(g(spec, "cleanup", "enabled")),
        "finalizers": md.get("finalizers") or [],
        "suggestedNamespace": ann.get("operatorframework.io/suggested-namespace", ""),
        "infraFeatures": ann.get("operators.openshift.io/infrastructure-features", ""),
        "validSubscription": ann.get("operators.openshift.io/valid-subscription", ""),
        "builder": ann.get("operators.operatorframework.io/builder", ""),
        # APIs
        "ownedCRDs": [{"name": c.get("name", ""), "version": c.get("version", ""), "kind": c.get("kind", "")}
                      for c in crds.get("owned") or []],
        "requiredCRDs": [{"name": c.get("name", ""), "version": c.get("version", ""), "kind": c.get("kind", "")}
                         for c in crds.get("required") or []],
        "ownedAPIServices": [f"{a.get('group')}/{a.get('version')} {a.get('kind')}" for a in apis.get("owned") or []],
        "webhooks": [f"{w.get('type')} {w.get('generateName')} -> {w.get('deploymentName')}:{w.get('containerPort')} "
                     f"failurePolicy={w.get('failurePolicy','')}"
                     for w in spec.get("webhookdefinitions") or []],
        "almExamples": parse_alm_examples(ann.get("alm-examples")),
        # workload
        "deployments": deployments,
        "images": all_images,
        "relatedImages": [r for r in related if r],
        # rbac
        "permissions": perms("permissions"),
        "clusterPermissions": perms("clusterPermissions"),
        # live (filled later)
        "subscription": None,
        "drift": None,
    }


# ----------------------------------------------------------------------------
# Live enrichment: Subscription + Deployment drift
# ----------------------------------------------------------------------------

def enrich_live(items):
    subs = oc_json(["get", "subscriptions.operators.coreos.com", "-A"], allow_fail=True) or {}
    by_installed = {}
    for s in subs.get("items") or []:
        inst = g(s, "status", "installedCSV")
        ns = g(s, "metadata", "namespace")
        if inst:
            by_installed[(ns, inst)] = s

    deploy_cache = {}
    for it in items:
        s = by_installed.get((it["namespace"], it["name"]))
        if s:
            it["subscription"] = {
                "name": g(s, "metadata", "name"),
                "package": g(s, "spec", "name"),
                "channel": g(s, "spec", "channel", default=""),
                "source": f"{g(s, 'spec', 'source')}/{g(s, 'spec', 'sourceNamespace')}",
                "approval": g(s, "spec", "installPlanApproval", default="Automatic"),
                "startingCSV": g(s, "spec", "startingCSV", default=""),
                "state": g(s, "status", "state", default=""),
                "installedCSV": g(s, "status", "installedCSV", default=""),
                "currentCSV": g(s, "status", "currentCSV", default=""),
                "installPlan": g(s, "status", "installPlanRef", "name", default=""),
                # Subscription conditions are problem/notice flags when status is True
                # (CatalogSourcesUnhealthy, ResolutionFailed, BundleUnpackFailed, InstallPlanPending, ...)
                "badConditions": [f"{c.get('type')}: {c.get('reason','')} {c.get('message','')}".strip()
                                  for c in g(s, "status", "conditions", default=[]) or []
                                  if c.get("status") == "True"],
            }
        ns = it["namespace"]
        if ns not in deploy_cache:
            d = oc_json(["get", "deployments", "-n", ns], allow_fail=True) or {}
            deploy_cache[ns] = {g(x, "metadata", "name"): x for x in d.get("items") or []}
        drift = []
        for dep in it["deployments"]:
            live = deploy_cache[ns].get(dep["name"])
            if not live:
                drift.append(f"{dep['name']}: Deployment MISSING")
                continue
            ready = g(live, "status", "readyReplicas", default=0)
            want = g(live, "spec", "replicas", default=1)
            if ready != want:
                drift.append(f"{dep['name']}: {ready}/{want} replicas ready")
            live_imgs = {c.get("name"): c.get("image") for c in g(live, "spec", "template", "spec", "containers", default=[]) or []}
            for c in dep["containers"]:
                if c["type"] != "main":
                    continue
                li = live_imgs.get(c["name"])
                if li is None:
                    drift.append(f"{dep['name']}/{c['name']}: container not in live Deployment")
                elif li != c["image"]:
                    drift.append(f"{dep['name']}/{c['name']}: live={li}  csv={c['image']}")
        it["drift"] = drift


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------

def kv(label, value, indent=0):
    if value in ("", None, [], {}):
        return
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    elif isinstance(value, dict):
        value = ", ".join(f"{k}={v}" for k, v in value.items())
    print(f"{' ' * indent}{label + ':':<24}{value}")


def print_text(items, show_rbac, show_history):
    bar = "=" * 100
    for it in items:
        print(bar)
        flag = "" if it["phase"] == "Succeeded" else "   <-- ATTENTION"
        print(f"CSV: {it['name']}   (namespace: {it['namespace']}){flag}")
        print(bar)
        kv("Display Name", it["displayName"])
        kv("Version", it["version"])
        kv("Provider", it["provider"])
        kv("Maturity", it["maturity"])
        kv("Capabilities", it["capabilities"])
        kv("Created", it["created"])
        kv("Built with", it["builder"])
        if it["copied"]:
            kv("Copied from", it["copied"])

        print("\n-- Status")
        kv("Phase", it["phase"], 2)
        kv("Reason", it["reason"], 2)
        kv("Message", it["message"], 2)
        kv("Last transition", it["lastTransition"], 2)
        for u in it["unmetRequirements"]:
            print(f"  UNMET: {u}")
        if show_history and it["conditions"]:
            print("  History:")
            for c in it["conditions"]:
                print(f"    {c}")

        print("\n-- Upgrade graph")
        kv("Replaces", it["replaces"] or "-", 2)
        kv("Skips", it["skips"] or "-", 2)
        kv("Skip range", it["skipRange"] or "-", 2)
        kv("Max OpenShift version", it["maxOpenShiftVersion"] or "-", 2)
        kv("Min kube version", it["minKubeVersion"], 2)
        for r in it["requires"]:
            kv("Requires", r, 2)

        print("\n-- OLM")
        kv("OperatorGroup", it["operatorGroup"], 2)
        kv("Operator namespace", it["operatorNamespace"], 2)
        kv("Target namespaces", it["targetNamespaces"], 2)
        kv("Install modes", it["installModes"], 2)
        kv("Cleanup on delete", "enabled (CRs removed with CSV!)" if it["cleanupEnabled"] else "disabled", 2)
        kv("Finalizers", it["finalizers"], 2)
        kv("Suggested namespace", it["suggestedNamespace"], 2)
        kv("Infra features", it["infraFeatures"], 2)
        kv("Valid subscription", it["validSubscription"], 2)

        if it["subscription"] is not None or it["drift"] is not None:
            print("\n-- Live")
            s = it["subscription"]
            if s:
                kv("Subscription", s["name"], 2)
                kv("Package / channel", f"{s['package']} / {s['channel']}", 2)
                kv("Source", s["source"], 2)
                kv("Approval", s["approval"], 2)
                kv("Starting CSV", s["startingCSV"], 2)
                kv("State", s["state"], 2)
                if s["currentCSV"] and s["currentCSV"] != s["installedCSV"]:
                    kv("UPGRADE PENDING", f"{s['installedCSV']} -> {s['currentCSV']} (InstallPlan {s['installPlan']})", 2)
                for c in s["badConditions"]:
                    print(f"  SUB CONDITION: {c}")
            elif it["drift"] is not None:
                print("  Subscription:          (none found - CSV not managed by a Subscription, or it is a copy)")
            if it["drift"]:
                for d in it["drift"]:
                    print(f"  DRIFT: {d}")
            elif it["drift"] is not None:
                print("  Deployments:           match CSV, all replicas ready")

        print("\n-- APIs")
        print(f"  Owned CRDs ({len(it['ownedCRDs'])}):")
        for c in it["ownedCRDs"]:
            print(f"    - {c['name']:<55} {c['version']:<10} {c['kind']}")
        if it["requiredCRDs"]:
            print(f"  Required CRDs ({len(it['requiredCRDs'])}):")
            for c in it["requiredCRDs"]:
                print(f"    - {c['name']:<55} {c['version']:<10} {c['kind']}")
        for a in it["ownedAPIServices"]:
            kv("API service", a, 2)
        for w in it["webhooks"]:
            kv("Webhook", w, 2)
        if it["almExamples"]:
            print("  Sample CRs (alm-examples):")
            for e in it["almExamples"]:
                print(f"    - {e['apiVersion']}  kind={e['kind']}  name={e['name']}")

        print("\n-- Deployments")
        for d in it["deployments"]:
            print(f"  {d['name']}  replicas={d['replicas']}  strategy={d['strategy']}  sa={d['serviceAccount']}")
            kv("Node selector", d["nodeSelector"], 4)
            kv("Affinity", d["affinity"], 4)
            kv("Tolerations", d["tolerations"], 4)
            kv("Priority class", d["priorityClass"], 4)
            if d["hostNetwork"]:
                kv("Host network", "true", 4)
            for c in d["containers"]:
                tag = " (init)" if c["type"] == "init" else ""
                print(f"    container {c['name']}{tag}")
                kv("Image", c["image"], 6)
                kv("Requests", c["requests"], 6)
                kv("Limits", c["limits"], 6)
                kv("Probes", f"liveness={'yes' if c['liveness'] else 'NO'} readiness={'yes' if c['readiness'] else 'NO'}", 6)
                kv("Ports", c["ports"], 6)
                if c["privileged"]:
                    kv("Privileged", "true", 6)

        print(f"\n-- Images ({len(it['images'])})")
        for i in it["images"]:
            print(f"  {i}")

        print("\n-- RBAC")
        for label, key in (("Namespaced", "permissions"), ("Cluster", "clusterPermissions")):
            for p in it[key]:
                flagged = [r for r in p["rules"] if r["flags"]]
                print(f"  {label} permissions for SA {p['serviceAccount']}: {len(p['rules'])} rules"
                      + (f", {len(flagged)} flagged" if flagged else ""))
                for r in (p["rules"] if show_rbac else flagged):
                    f = f"   <-- {' '.join(r['flags'])}" if r["flags"] else ""
                    print(f"    {r['rule']}{f}")
        if not show_rbac:
            print("  (use --rbac to list every rule)")
        print()
    print(f"Total CSVs: {len(items)}")


def print_summary(items):
    rows = [("NAMESPACE", "NAME", "VERSION", "PHASE", "REPLACES", "SKIPS", "MAX-OCP", "APPROVAL", "UPGRADE")]
    for it in items:
        s = it["subscription"] or {}
        up = ""
        if s.get("currentCSV") and s.get("currentCSV") != s.get("installedCSV"):
            up = f"-> {s['currentCSV']}"
        if it["drift"]:
            up = (up + " DRIFT").strip()
        rows.append((it["namespace"], it["name"], it["version"], it["phase"],
                     it["replaces"] or "-", str(len(it["skips"])) if it["skips"] else "-",
                     it["maxOpenShiftVersion"] or "-", s.get("approval", "-") if it["subscription"] is not None else "-",
                     up or "-"))
    w = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        print("  ".join(v.ljust(w[i]) for i, v in enumerate(r)).rstrip())


CSV_FIELDS = ["namespace", "name", "displayName", "version", "provider", "phase", "reason", "message",
              "replaces", "skips", "skipRange", "maxOpenShiftVersion", "operatorGroup", "targetNamespaces",
              "installModes", "cleanupEnabled", "ownedCRDs", "deployments", "images", "flaggedRBAC",
              "subscription", "channel", "source", "approval", "subState", "currentCSV", "drift"]


def write_csv(items):
    w = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDS)
    w.writeheader()
    for it in items:
        s = it["subscription"] or {}
        flagged = [r["rule"] + " " + " ".join(r["flags"])
                   for p in it["permissions"] + it["clusterPermissions"] for r in p["rules"] if r["flags"]]
        w.writerow({
            "namespace": it["namespace"], "name": it["name"], "displayName": it["displayName"],
            "version": it["version"], "provider": it["provider"], "phase": it["phase"],
            "reason": it["reason"], "message": it["message"], "replaces": it["replaces"],
            "skips": ";".join(it["skips"]), "skipRange": it["skipRange"],
            "maxOpenShiftVersion": it["maxOpenShiftVersion"], "operatorGroup": it["operatorGroup"],
            "targetNamespaces": it["targetNamespaces"], "installModes": ";".join(it["installModes"]),
            "cleanupEnabled": it["cleanupEnabled"],
            "ownedCRDs": ";".join(f"{c['name']}/{c['version']}" for c in it["ownedCRDs"]),
            "deployments": ";".join(d["name"] for d in it["deployments"]),
            "images": ";".join(it["images"]), "flaggedRBAC": " | ".join(flagged),
            "subscription": s.get("name", ""), "channel": s.get("channel", ""), "source": s.get("source", ""),
            "approval": s.get("approval", ""), "subState": s.get("state", ""), "currentCSV": s.get("currentCSV", ""),
            "drift": " | ".join(it["drift"] or []),
        })


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    global CLI
    ap = argparse.ArgumentParser(description="Report details from OLM ClusterServiceVersions",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("Examples:")[1])
    ap.add_argument("names", nargs="*", help="filter: CSV name contains any of these strings")
    ap.add_argument("-n", "--namespace", help="only this namespace (default: all namespaces)")
    ap.add_argument("-i", "--input", help="read a saved CSV / CSV list (JSON, or YAML with PyYAML)")
    ap.add_argument("-o", "--output", default="text", choices=["text", "summary", "csv", "json", "images"])
    ap.add_argument("--live", action="store_true", help="add Subscription info and Deployment drift checks")
    ap.add_argument("--rbac", action="store_true", help="list every RBAC rule (default: flagged rules only)")
    ap.add_argument("--history", action="store_true", help="show the CSV phase/condition history")
    ap.add_argument("--not-succeeded", action="store_true", help="only CSVs whose phase is not Succeeded")
    ap.add_argument("--include-copied", action="store_true", help="include OLM-copied CSVs")
    ap.add_argument("--cli", help="CLI to use (default: oc, falls back to kubectl)")
    args = ap.parse_args()

    CLI = args.cli or ("oc" if shutil.which("oc") else "kubectl")

    if args.input:
        raw = load_file(args.input)
        if args.live:
            print("NOTE: --live queries the current cluster for Subscriptions/Deployments", file=sys.stderr)
    else:
        scope = ["-n", args.namespace] if args.namespace else ["-A"]
        raw = oc_json(["get", "clusterserviceversions.operators.coreos.com"] + scope).get("items", [])

    items = [parse_csv(o) for o in raw]
    if args.namespace:
        items = [i for i in items if i["namespace"] == args.namespace]
    if not args.include_copied:
        items = [i for i in items if not i["copied"]]
    if args.names:
        items = [i for i in items if any(n in i["name"] for n in args.names)]
    if args.not_succeeded:
        items = [i for i in items if i["phase"] != "Succeeded"]
    items.sort(key=lambda i: (i["namespace"], i["name"]))

    if not items:
        sys.exit("No matching CSVs found.")

    if args.live:
        enrich_live(items)

    if args.output == "text":
        print_text(items, args.rbac, args.history)
    elif args.output == "summary":
        print_summary(items)
    elif args.output == "csv":
        write_csv(items)
    elif args.output == "json":
        json.dump(items, sys.stdout, indent=2)
        print()
    elif args.output == "images":
        for i in sorted({img for it in items for img in it["images"]}):
            print(i)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
