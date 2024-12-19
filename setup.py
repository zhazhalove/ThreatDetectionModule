from setuptools import setup, find_packages

setup(
    name="threat_detection_score",
    version="1.0.0",
    description="A package for cybersecurity threat analysis and detection",
    author="zhazhalove",
    author_email="zhazhalove@example.com",
    packages=find_packages(include=["threat_detection_score*"]),
    install_requires=[
        "typer",
        "langchain",
        "langchain-openai",
        "python-dotenv",
    ],
    entry_points={
        "console_scripts": [
            "detection_coverage=threat_detection_score.langchain_detection_coverage_openai:app",
            "org_alignment=threat_detection_score.langchain_organizational_alignment_openai:app",
            "threat_severity=threat_detection_score.threat_severity_openai_chain:app",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)