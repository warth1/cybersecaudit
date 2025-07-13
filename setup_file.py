#!/usr/bin/env python3
"""
CyberSecAudit Setup Script
Kurulum ve dağıtım için setup.py dosyası
"""

from setuptools import setup, find_packages
import os

# README dosyasını oku
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Gereksinimler dosyasını oku
with open("requirements_file.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cybersecaudit",
    version="1.0.0",
    author="Warth",
    author_email="",
    description="Kapsamlı Siber Güvenlik Denetim Aracı",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/warth1/cybersecaudit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    extras_require={
        "dev": ["pytest", "black", "flake8", "mypy"],
        "advanced": ["python-nmap", "scapy", "requests", "beautifulsoup4"],
    },
    entry_points={
        "console_scripts": [
            "cybersecaudit=cybersec_audit:main",
        ],
    },
    keywords="cybersecurity, security audit, port scanner, vulnerability assessment, penetration testing",
    project_urls={
        "Bug Reports": "https://github.com/warth1/cybersecaudit/issues",
        "Source": "https://github.com/warth1/cybersecaudit",
        "Documentation": "https://github.com/warth1/cybersecaudit#readme",
    },
)
