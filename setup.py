"""
Setup configuration for secureVault password manager.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="securevault",
    version="1.0.0",
    author="Ahpatsum15",
    description="Secure offline password manager with modern cryptography",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Ahpatsum15/secureVault",
    packages=find_packages(),
    package_dir={"": "."},
    python_requires=">=3.8",
    install_requires=[
        "argon2-cffi>=25.1.0",
        "cryptography>=46.0.2",
        "click>=8.3.0",
        "rich>=13.7.0",
        "pyperclip>=1.8.2",
    ],
    entry_points={
        "console_scripts": [
            "securevault=src.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="password manager security cryptography argon2 aes encryption offline",
)
