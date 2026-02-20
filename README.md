# Prismorsec Agent Immunity Intelligence Pipeline

This repository hosts the continuous security intelligence feed for the Prismorsec Agent Immunity platform. It automatically polls the National Vulnerability Database (NVD) for CVEs impacting the AI agent ecosystem, merges them, and cryptographically signs the output.

## Directory Structure

- `.github/workflows/`: CI/CD pipelines defining the automated polling, processing, and signing logic.
- `advisories/`: The final, published intelligence feed (`immunity-feed.json`) and its Ed25519 signature (`immunity-feed.json.sig`).
- `schemas/`: The JSON schema defining the shape of a Prismorsec Threat Object.
- `scripts/`: The core Python and Bash logic to fetch, translate, validate, and sign the intelligence data.

## The Intelligence Pipeline Architecture

1. **Extraction**: `scripts/fetch_nvd_intel.py` queries the NVD using specific AI ecosystem keywords (`LangChain`, `OpenAI`, `Prompt Injection`, etc.). It handles rate limits and transforms the raw data (mapping CVSS to Prismorsec severity tiers and inferring threat types from CWEs).
2. **Merging**: The python script pipes the JSON array to `scripts/merge_intel.py`, which deduplicates the existing `immunity-feed.json` by ID, updates the `updated` timestamp, and rigorously enforces the JSON Schema (`schemas/threat-object.schema.json`).
3. **Cryptographic Sealing**: Finally, `scripts/sign_feed.sh` uses OpenSSL and a protected environment variable containing a private Ed25519 key to generate a detached base64-encoded signature.

## Development & Testing

### Python Setup
Ensure you are using Python 3.10+:

```bash
pip install -r requirements.txt
```

### Manual Run
You can run the pipeline locally to test it. Note that `fetch_nvd_intel.py` will be much faster if you provide an `NVD_API_KEY` (you can request one from NIST).

```bash
export NVD_API_KEY="your-nist-api-key"

# Pipe the fetching script into the merger
python3 scripts/fetch_nvd_intel.py | python3 scripts/merge_intel.py
```

## Cryptographic Setup (Generating Keypairs)

For clients to trust the feed, it is signed with a private Ed25519 key managed in GitHub secrets (`PRISMORSEC_SIGNING_PRIVATE_KEY`).

To generate a new keypair exactly compatible with this pipeline:

1. **Generate the private key:**
   ```bash
   openssl genpkey -algorithm ed25519 -out private.pem
   ```
   **Important:** Store the contents of `private.pem` securely as the `PRISMORSEC_SIGNING_PRIVATE_KEY` repository secret in GitHub. Never commit this file.

2. **Generate the public key (for distribution):**
   ```bash
   openssl pkey -in private.pem -pubout -out public.pub
   ```
   The contents of `public.pub` should be hardcoded or distributed to the Prismorsec scanners running in production so they can verify the `immunity-feed.json.sig` file.

## Client Verification Protocol

Clients downloading `immunity-feed.json` and `immunity-feed.json.sig` must verify authenticity before applying any security policies:

```bash
# Example verification using the standard openssl command line
# Decode the base64 signature back to raw binary bytes first
openssl base64 -d -A -in advisories/immunity-feed.json.sig -out signature.bin

openssl pkeyutl -verify -pubin -inkey public.pub -rawin -in advisories/immunity-feed.json -sigfile signature.bin
```
If the output says `Signature Verified Successfully`, the feed is genuine and unmanipulated.