from setuptools import setup, find_packages

setup(
    name="argus",
    version="0.2.0",
    description="Argus - Intelligence-Driven Security Scanner (The All-Seeing Eye)",
    author="Fevra",
    author_email="fev.dev@proton.me",
    url="https://github.com/fevra-dev/Argus",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[
        "paramiko>=3.3.0",
        "click>=8.1.0",
        "colorama>=0.4.6",
        "rich>=13.0.0",
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "pydantic>=2.0.0",
        "jinja2>=3.1.0",
        "apscheduler>=3.10.0",
    ],
    entry_points={
        "console_scripts": [
            "argus=argus.cli:main",
        ],
    },
)
