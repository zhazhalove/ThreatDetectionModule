from setuptools import setup, find_packages

setup(
    name="input_sanitizer",
    version="1.0.0",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=["typer"],
    description="Reusable input sanitization package",
    author="zhazhalove",
    author_email="test@example.com",
    license="MIT",
)
