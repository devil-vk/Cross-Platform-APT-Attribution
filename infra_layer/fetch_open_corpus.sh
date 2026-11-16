#!/usr/bin/env bash
# Reproduce the open IOC corpus (no API keys needed). Run on any machine with git.
set -e
mkdir -p ioc_sources && cd ioc_sources
git clone --depth 1 https://github.com/eset/malware-ioc.git        || true
git clone --depth 1 https://github.com/fireeye/iocs.git fireeye_iocs || true
echo "Done. Next (from the repo root): python3 infra_extract.py ioc_sources/malware-ioc"
