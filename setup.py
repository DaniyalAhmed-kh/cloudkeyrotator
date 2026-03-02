from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cloudkeyrotator",
    version="1.0.0",
    author="CloudKeyRotator Contributors",
    description="Multi-Cloud Credential Exposure Validator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
        "requests>=2.28",
        # Optional but recommended:
        # "boto3>=1.28",
        # "google-auth>=2.0",
        # "azure-identity>=1.14",
        # "azure-storage-blob>=12.0",
        # "cryptography>=41.0",
    ],
    extras_require={
        "aws":    ["boto3>=1.28"],
        "gcp":    ["google-auth>=2.0", "google-api-python-client>=2.0", "cryptography>=41.0"],
        "azure":  ["azure-identity>=1.14", "azure-storage-blob>=12.0", "azure-mgmt-authorization>=3.0"],
        "all":    [
            "boto3>=1.28",
            "google-auth>=2.0",
            "google-api-python-client>=2.0",
            "cryptography>=41.0",
            "azure-identity>=1.14",
            "azure-storage-blob>=12.0",
            "azure-mgmt-authorization>=3.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cloudkeyrotator=cloudkeyrotator.cli:main",
            "ckr=cloudkeyrotator.cli:main",  # Short alias
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="security pentesting cloud aws azure gcp github credentials secrets",
)
