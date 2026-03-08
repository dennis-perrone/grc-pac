#!/usr/bin/env python3
import sys
import os
import yaml
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load YAML file (returns list of documents)
def load_yaml(path):
    with open(path, "r") as f:
        return list(yaml.safe_load_all(f))

# Detect platform (Kubernetes, Docker, Terraform)
def detect_platform(file_path):
    docs = load_yaml(file_path)
    for doc in docs:
        if doc is None:
            continue
        if isinstance(doc, dict):
            if "apiVersion" in doc and "kind" in doc:
                return "kubernetes"
            elif "resource" in doc:
                return "terraform"
        elif isinstance(doc, str) and doc.strip().upper().startswith("FROM"):
            return "docker"
    return "unknown"

# Query OPA server
def query_opa(data, platform):
    url = f"http://host.containers.internal:8181/v1/data/grc/{platform}/findings"
    payload = {"input": data}
    try:
        r = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=5
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"Error contacting OPA: {e}")
        return {"result": []}

# Print results nicely and return max severity
def print_results(results, file_path):
    result = results.get("result", [])

    if isinstance(result, dict):
        findings = result.get("findings", [])
    else:
        findings = result

    if not findings:
        print(f"\n✅ No policy violations in {file_path}\n")
        return 0

    severity_map = {"low": 1, "medium": 2, "high": 3}
    max_severity = 0

    print(f"\n❌ Policy Violations in {file_path}\n")

    for f in findings:

        if not isinstance(f, dict):
            print(f"- {f}")
            continue

        sev = f.get("severity", "low").lower()
        max_severity = max(max_severity, severity_map.get(sev, 0))

        print(f"[{sev.upper()}] {f.get('policy_id','unknown')}")
        print(f"Resource: {f.get('resource','unknown')}")
        print(f"Message: {f.get('message','')}")

        # Framework mapping
        frameworks = f.get("frameworks", {})
        if frameworks:
            print("Frameworks:")
            for fw, controls in frameworks.items():
                print(f"  {fw}: {', '.join(controls)}")

        print()

    return max_severity

# Print summary of framework violations across multiple files
def print_framework_summary(results_list):
    framework_summary = {}

    for results in results_list:
        result = results.get("result", [])

        if isinstance(result, dict):
            findings = result.get("findings", [])
        else:
            findings = result

        for f in findings:
            if not isinstance(f, dict):
                continue
            frameworks = f.get("frameworks", {})
            for fw, controls in frameworks.items():
                if fw not in framework_summary:
                    framework_summary[fw] = {}
                for control in controls:
                    framework_summary[fw][control] = framework_summary[fw].get(control, 0) + 1

    if not framework_summary:
        print("\nNo framework-specific violations found")
        return

    print("\n==============================")
    print("Compliance Framework Summary")
    print("==============================")
    for fw, controls in framework_summary.items():
        print(f"\n{fw.upper()}:")
        for control, count in controls.items():
            print(f"  {control}: {count} violation(s)")

# Print summary of violations across multiple files
def print_summary(results_list):
    summary = {"high": 0, "medium": 0, "low": 0}

    for results in results_list:
        result = results.get("result", [])

        if isinstance(result, dict):
            findings = result.get("findings", [])
        else:
            findings = result

        for f in findings:
            if isinstance(f, dict):
                sev = f.get("severity", "low").lower()
                if sev in summary:
                    summary[sev] += 1

    print("\n==============================")
    print("Compliance Summary")
    print("==============================\n")
    print(f"High:   {summary['high']}")
    print(f"Medium: {summary['medium']}")
    print(f"Low:    {summary['low']}")

# Scan a single file (used for parallel execution)
def scan_file(file_path):
    platform = detect_platform(file_path)
    if platform == "unknown":
        print(f"Skipping {file_path}, unknown platform")
        return file_path, {"result": []}

    docs = load_yaml(file_path)

    # Remove empty YAML docs
    docs = [d for d in docs if d is not None]

    payload = {"input": docs}

    results = query_opa(payload["input"], platform)

    return file_path, results

# Main CLI
def main():
    if len(sys.argv) != 2:
        print("Usage: grc-check <yaml-file-or-directory>")
        sys.exit(1)

    path = sys.argv[1]

    if os.path.isdir(path):
        files = []
        for root, _, filenames in os.walk(path):
            for name in filenames:
                if name.endswith((".yml", ".yaml")):
                    files.append(os.path.join(root, name))
        files.sort()
    else:
        files = [path]

    overall_max_severity = 0
    all_results = []

    # Parallel scanning
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_file = {executor.submit(scan_file, f): f for f in files}
        for future in as_completed(future_to_file):
            file_path, results = future.result()
            print(f"\nResults for {file_path}:")
            file_max_sev = print_results(results, file_path)
            overall_max_severity = max(overall_max_severity, file_max_sev)
            all_results.append(results)

    # Print summary
    print_summary(all_results)

    # Print compliance framework summary
    print_framework_summary(all_results)

    # Exit codes
    if overall_max_severity == 3:
        sys.exit(1)  # High severity found
    else:
        sys.exit(0)  # Medium/low/no issues

if __name__ == "__main__":
    main()