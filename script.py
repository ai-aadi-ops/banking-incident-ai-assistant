#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import csv
import shutil
from datetime import datetime

INPUT_DIR = "input_logs"
ARCHIVE_DIR = "archive"
MASKED_DIR = "masked"

OWNER_MAP = {
    "1": "Testing / QA",
    "2": "Development",
    "3": "Deployment / Release",
    "4": "Server Management / Infra",
    "5": "Database",
    "6": "Network"
}


def ensure_dirs():
    for d in [INPUT_DIR, ARCHIVE_DIR, MASKED_DIR]:
        os.makedirs(d, exist_ok=True)


def read_logs():
    content = []
    files = []

    for name in os.listdir(INPUT_DIR):
        path = os.path.join(INPUT_DIR, name)

        if os.path.isfile(path):
            files.append(path)

            try:
                with open(path, "r", errors="ignore") as f:
                    content.append("\n" + ("=" * 80))
                    content.append("FILE: " + name)
                    content.append("=" * 80)
                    content.append(f.read())

            except Exception as e:
                content.append(
                    "ERROR READING FILE {} : {}".format(name, e)
                )

    return "\n".join(content), files


def detect_owner(log):
    text = log.upper()

    scores = {
        "Testing / QA": 0,
        "Development": 0,
        "Deployment / Release": 0,
        "Server Management / Infra": 0,
        "Database": 0,
        "Network": 0
    }

    keyword_map = {
        "Development": [
            "NULLPOINTEREXCEPTION",
            "CLASSNOTFOUND",
            "UNSUPPORTEDCLASSVERSIONERROR",
            "STACKTRACE",
            "COMPILATION",
            "JAVA.LANG"
        ],
        "Testing / QA": [
            "TEST CASE",
            "EXPECTED",
            "ACTUAL",
            "ASSERTION",
            "REGRESSION",
            "QA",
            "UAT",
            "SIT"
        ],
        "Deployment / Release": [
            "DEPLOY",
            "ROLLBACK",
            "ARTIFACT",
            "PIPELINE",
            "RELEASE",
            "JENKINS",
            "BUILD FAILED",
            ".EAR",
            ".WAR"
        ],
        "Server Management / Infra": [
            "CPU",
            "MEMORY",
            "DISK",
            "SERVICE DOWN",
            "SYSTEMD",
            "PERMISSION DENIED",
            "OUTOFMEMORY",
            "HEAP",
            "JVM"
        ],
        "Database": [
            "ORA-",
            "SQLSTATE",
            "JDBC",
            "DATABASE",
            "TABLESPACE",
            "DEADLOCK"
        ],
        "Network": [
            "TIMEOUT",
            "CONNECTION REFUSED",
            "HOST UNREACHABLE",
            "DNS",
            "SOCKET",
            "PORT"
        ]
    }

    for owner, keywords in keyword_map.items():
        for kw in keywords:
            if kw in text:
                scores[owner] += 2

    best = max(scores, key=scores.get)
    score = scores[best]

    if score == 0:
        return "Unknown", 0

    confidence = min(95, 50 + (score * 5))
    return best, confidence


def detect_severity(log):
    text = log.upper()

    if "FATAL" in text or "CRITICAL" in text or "SEV1" in text:
        return "Sev1 Critical"

    if "ERROR" in text or "EXCEPTION" in text or "FAILED" in text:
        return "Sev2 High"

    if "WARN" in text:
        return "Sev3 Medium"

    return "Sev4 Low"


def extract_findings(log):
    text = log.upper()
    findings = []

    if "UNSUPPORTEDCLASSVERSIONERROR" in text:
        findings.append("Java bytecode version mismatch detected")

    if "CLASS FILE VERSION 61.0" in text:
        findings.append("Application compiled with Java 17")

    if "UP TO 52.0" in text or "VERSIONS UP TO 52.0" in text:
        findings.append("Runtime supports Java 8 only")

    if "DEPLOYMENT" in text and "FAILED" in text:
        findings.append("Deployment failure detected")

    if ".EAR" in text:
        findings.append("EAR packaging / deployment involved")

    if "ORA-" in text:
        findings.append("Oracle database error detected")

    if "TIMEOUT" in text:
        findings.append("Connection timeout observed")

    if "OUTOFMEMORYERROR" in text:
        findings.append("JVM memory pressure observed")

    if "PERMISSION DENIED" in text:
        findings.append("Filesystem permission issue detected")

    if not findings:
        findings.append("General application failure detected")

    return findings


def sanitize_logs(log):
    mapping = []
    counters = {
        "EMAIL": 1,
        "IP": 1,
        "PHONE": 1,
        "ACCOUNT": 1,
        "SERVER": 1,
        "PATH": 1
    }

    def replace(pattern, prefix, text):
        counter = counters[prefix]
        found = list(set(re.findall(pattern, text)))

        for item in found:
            token = "{}_{:03d}".format(prefix, counter)
            text = text.replace(item, token)
            mapping.append((token, item))
            counter += 1

        counters[prefix] = counter
        return text

    log = replace(
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        "EMAIL",
        log
    )
    log = replace(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "IP",
        log
    )
    log = replace(
        r'\b[6-9]\d{9}\b',
        "PHONE",
        log
    )
    log = replace(
        r'\b\d{8,18}\b',
        "ACCOUNT",
        log
    )
    log = replace(
        r'/[A-Za-z0-9_\-./]+',
        "PATH",
        log
    )
    log = replace(
        r'\b[a-zA-Z0-9\-]+(?:srv|server|host)[a-zA-Z0-9\-]*\b',
        "SERVER",
        log
    )

    return log, mapping


def generate_prompt(owner, description, severity, sanitized_log):
    findings = extract_findings(sanitized_log)

    header = (
        "Analyze attached sanitized banking logs.\n\n"
        "Context:\n"
        "Issue Owner: {}\n"
        "Severity: {}\n"
        "Description: {}\n\n"
        .format(owner, severity, description)
    )

    observed = "Observed Signals:\n"
    for item in findings:
        observed += "- {}\n".format(item)

    observed += "\n"

    owner_specific = {
        "Testing / QA":
            (
                "Need:\n"
                "1. Identify impacted validation scope\n"
                "2. Expected vs actual behavior\n"
                "3. Reproducible test path\n"
                "4. Regression impact analysis\n"
                "5. Recommended retest checklist\n"
            ),
        "Development":
            (
                "Need:\n"
                "1. Exact code/module root cause\n"
                "2. Exception breakdown\n"
                "3. Dependency/config issue mapping\n"
                "4. Code fix recommendation\n"
                "5. Post-fix validation approach\n"
            ),
        "Deployment / Release":
            (
                "Need:\n"
                "1. Explain exact deployment failure sequence\n"
                "2. Confirm artifact/config/runtime mismatch\n"
                "3. Release-side remediation plan\n"
                "4. Rollback / forward-fix strategy\n"
                "5. Validation checklist before redeployment\n"
            ),
        "Server Management / Infra":
            (
                "Need:\n"
                "1. Infra-level root cause\n"
                "2. Resource/service dependency impact\n"
                "3. Immediate remediation steps\n"
                "4. Preventive hardening recommendation\n"
                "5. Monitoring / alert recommendation\n"
            ),
        "Database":
            (
                "Need:\n"
                "1. DB root cause\n"
                "2. Query/connection breakdown\n"
                "3. Immediate fix steps\n"
                "4. Data impact assessment\n"
                "5. Preventive DB recommendation\n"
            ),
        "Network":
            (
                "Need:\n"
                "1. Connectivity root cause\n"
                "2. DNS/Firewall/Port validation\n"
                "3. Immediate remediation\n"
                "4. Dependency impact\n"
                "5. Monitoring recommendation\n"
            )
    }

    body = owner_specific.get(
        owner,
        "Need:\n1. Root cause\n2. Fix\n3. Validation\n"
    )

    prompt = header + observed + body
    prompt += "\nSanitized Logs:\n"
    prompt += sanitized_log

    return prompt


def archive_logs(files):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(ARCHIVE_DIR, stamp)
    os.makedirs(dest, exist_ok=True)

    for file_path in files:
        try:
            shutil.copy2(file_path, dest)
        except Exception:
            pass

    return dest


def write_outputs(sanitized, mapping, prompt):
    sanitized_file = os.path.join(MASKED_DIR, "sanitized_logs.txt")
    mapping_file = os.path.join(MASKED_DIR, "masked_mapping.csv")
    prompt_file = os.path.join(MASKED_DIR, "ai_prompt.txt")

    with open(sanitized_file, "w", encoding="utf-8") as f:
        f.write(sanitized)

    with open(mapping_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["MASKED_VALUE", "ORIGINAL_VALUE"])
        for row in mapping:
            writer.writerow(row)

    with open(prompt_file, "w", encoding="utf-8") as f:
        f.write(prompt)

    return sanitized_file, mapping_file, prompt_file


def manual_owner_select():
    print("\nSelect issue owner:")
    print("1) Testing / QA")
    print("2) Development")
    print("3) Deployment / Release")
    print("4) Server Management / Infra")
    print("5) Database")
    print("6) Network")

    while True:
        choice = input("Choose: ").strip()
        if choice in OWNER_MAP:
            return OWNER_MAP[choice]
        print("Invalid choice. Try again.")


def ask_owner(auto_owner):
    print("\nDo you want to proceed with detected category? (y/n)")
    ans = input("> ").strip().lower()

    if ans == "y":
        return auto_owner

    return manual_owner_select()


def main():
    print("=" * 60)
    print("BANKING INCIDENT AI ASSISTANT")
    print("=" * 60)

    ensure_dirs()

    logs, files = read_logs()

    if not files:
        print("\nNo files found in input_logs/")
        return

    print("\nScanning logs...")
    auto_owner, confidence = detect_owner(logs)
    severity = detect_severity(logs)

    if auto_owner == "Unknown":
        print("Could not auto-detect category confidently.")
        owner = manual_owner_select()
    else:
        print(
            "Suggested owner: {} (Confidence: {}%)"
            .format(auto_owner, confidence)
        )
        owner = ask_owner(auto_owner)

    print("\nDetected Severity: {}".format(severity))

    print("\nEnter short issue description:")
    description = input("> ").strip()

    print("\nSanitizing logs...")
    sanitized, mapping = sanitize_logs(logs)

    print("Generating tailored prompt...")
    prompt = generate_prompt(owner, description, severity, sanitized)

    print("Archiving logs...")
    archive_path = archive_logs(files)

    sanitized_file, mapping_file, prompt_file = write_outputs(
        sanitized,
        mapping,
        prompt
    )

    print("\n" + "=" * 60)
    print("COMPLETED")
    print("=" * 60)
    print("Owner      :", owner)
    print("Severity   :", severity)
    print("Archive    :", archive_path)
    print("Sanitized  :", sanitized_file)
    print("Mapping    :", mapping_file)
    print("AI Prompt  :", prompt_file)
    print("=" * 60)


if __name__ == "__main__":
    main()