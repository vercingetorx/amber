from setuptools import setup, find_packages


setup(
    name="amber",
    version="0.1",
    packages=find_packages(),
    description="A minimal, future‑proof archive format focused on long‑term safety against bit rot.",
    author="vercingetorx",
    install_requires=[
        "pycryptodomex>=3.23.0",
        "argon2-cffi>=23.1.0",
    ],
    entry_points={
        "console_scripts": [
            "amber=amber.cli:main",
        ]
    },
)
