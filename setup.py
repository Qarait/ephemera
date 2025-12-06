from setuptools import setup, find_packages

setup(
    name="ephemera-cli",
    version="2.0.0",
    description="Zero-Trust SSH Certificate Authority CLI",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Ephemera Team",
    url="https://github.com/SSH-Pearl/ephemera",
    packages=find_packages(),
    py_modules=["ephemera_cli"],
    install_requires=[
        "requests",
        "colorama",
    ],
    entry_points={
        "console_scripts": [
            "ephemera=ephemera_cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
)
