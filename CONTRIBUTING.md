# Contributing to Prismor

First off, thank you for taking the time to contribute! 🎉

Prismor acts as an "autoimmune system" for LLM-powered applications. While our automated systems constantly poll the National Vulnerability Database (NVD) for AI frameworks, the threat landscape evolves faster than CVEs are issued. 

Community intelligence regarding novel prompt injections, jailbreaks, data exfiltration vectors, and unsafe tool payloads is absolutely vital to the project's success.

## How Can I Contribute?

### 1. Submitting Threat Intelligence

If you are a security researcher or an engineer who has discovered a vulnerability in the AI agent supply chain (from framework flaws to novel jailbreak patterns), please submit it using our **Threat Intelligence Issue Template**.

1. Go to the **Issues** tab.
2. Click **New Issue**.
3. Select the **Submit Threat Intelligence** template.
4. Fill out the required YAML fields completely. This ensures the automated pipeline can easily classify and ingest your finding into the `immunity-feed.json`.

**What happens next?**
A maintainer will review the submission. If validated, the findings will be mapped to the Prismor Threat Object schema and merged into the active feed, distributed globally to update active scanners.

### 2. Improving the Pipeline Scripts

We welcome pull requests that improve the extraction, merging, and cryptographic signing pipeline located in `scripts/`.

#### Setting Up Locally
1. Clone the repository.
2. Create a virtual environment: `python3 -m venv venv && source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`

#### Creating a Pull Request
1. Fork the repo and create your branch from `main`.
2. Write clear, documented code.
3. If you've modified `fetch_nvd_intel.py` or `merge_intel.py`, ensure you test the changes locally using the mocked pipeline command in the `README.md`.
4. Ensure your changes do not break the JSON schema validation (`schemas/threat-object.schema.json`).
5. Open a PR with a clear description of the problem you are solving relative to an existing issue.

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms. Ensure your interactions are respectful, welcoming, and professional.

## License

By contributing to Prismor, you agree that your contributions will be licensed under its Apache 2.0 License. If you are submitting original threat intelligence, you explicitly grant us permission to distribute it via our feeds.
