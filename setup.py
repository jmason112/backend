"""
Setup script for Python Logging Agent

This script handles the installation and packaging of the Python Logging Agent.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = requirements_path.read_text(encoding="utf-8").strip().split("\n")

setup(
    name="python-logging-agent",
    version="1.0.0",
    description="Python Cybersecurity Agent for collecting and standardizing Windows logs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Python Logging Agent Team",
    author_email="support@example.com",
    url="https://github.com/example/python-logging-agent",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "config": ["*.yaml"],
    },
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "service": [
            "pywin32>=306",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "Topic :: Security",
    ],
    keywords="logging, security, windows, cybersecurity, monitoring, siem",
    entry_points={
        "console_scripts": [
            "python-logging-agent=main:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/example/python-logging-agent/issues",
        "Source": "https://github.com/example/python-logging-agent",
        "Documentation": "https://github.com/example/python-logging-agent/wiki",
    },
)
