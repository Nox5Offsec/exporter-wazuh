from setuptools import setup, find_packages

setup(
    name="soc-exporter",
    version="1.0.0",
    description="SOC Exporter — Wazuh event forwarder to central API",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "soc-exporter=soc_exporter.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
)
