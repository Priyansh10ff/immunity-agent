# Prismor Agent Immunity Specification

## 1. Executive Summary
The **Prismor Agent Immunity** feed is a continuously updated, cryptographically verifiable stream of security intelligence designed specifically for the AI agent ecosystem. Acting as an "autoimmune system" for LLM-powered applications, it provides the real-time threat data required by the Prismor platform to detect, isolate, and remediate vulnerabilities—such as prompt injections, data exfiltration vectors, and unsafe tool payloads—before they can compromise production environments.

## 2. Core Operational Objectives
The Agent Immunity architecture operates on three foundational pillars:
- **Proactive Threat Inoculation:** Alert teams to newly discovered "pathogens" (vulnerabilities in frameworks, unsafe default prompts, or vulnerable dependency chains) so agents can be updated before exploitation.
- **Continuous Lifecycle Monitoring:** Provide a live intelligence feed that powers continuous auditing algorithms, ensuring that as an agent's capabilities evolve, its security posture scales proportionally.
- **Cryptographic Trust:** Guarantee the integrity of the threat feed through Ed25519 digital signatures, preventing supply-chain poisoning by malicious actors attempting to suppress vulnerability reports.

## 3. Intelligence Sources (The "Antigen" Providers)
Prismor synthesizes threat intelligence from two primary streams:

1. **NVD (National Vulnerability Database) Polling:** Automated systems continuously monitor the NVD for CVEs impacting the AI supply chain. 
   - *Target Sentinels:* `LangChain`, `LlamaIndex`, `OpenAI API`, `Anthropic SDK`, `Vanna`, `CrewAI`, `AutoGPT`.
2. **Prismor Threat Labs:** Proprietary and community-verified intelligence focusing on architectural flaws that do not yet have CVEs.
   - *Examples:* Novel jailbreak techniques, cross-agent prompt injection patterns, unauthorized system prompt extraction, and overly permissive tool configurations (e.g., unsanitized bash/python execution environments).

## 4. The "Pathogen" Data Schema
The intelligence is published as a unified JSON artifact (`immunity-feed.json`), consisting of global metadata and an array of recognized threats (advisories).

### Feed Metadata
- `version`: Schema version (e.g., "1.1.0").
- `updated`: ISO 8601 timestamp of the last intelligence update.
- `description`: A brief description of the intelligence package.
- `advisories`: Array of Threat Objects.

### Threat Object (Advisory)
| Field | Type | Description |
|-------|------|-------------|
| `id` | String | Unique identifier (e.g., `CVE-2026-12345` or `PRISMOR-2026-0001`). |
| `severity` | String | Evaluated risk level: `critical`, `high`, `medium`, `low`. |
| `type` | String | The specific AI threat vector. Examples: `prompt_injection`, `data_exfiltration`, `unsafe_tool_execution`, `jailbreak`, `policy_bypass`, `dependency_vulnerability`, `model_denial_of_service`. |
| `title` | String | Brief summary of the threat. |
| `description`| String | Detailed explanation of the attack vector, prerequisites, and potential blast radius. |
| `affected` | Array | CPE-style strings defining vulnerable frameworks, models, or tool configurations (e.g., `["crewai<=0.28.8", "langchain-experimental<0.0.50"]`). |
| `action` | String | The prescribed "immune response" (e.g., "Upgrade to version X", "Wrap tool execution in isolated Docker container", "Implement prompt guardrails"). |
| `published` | String | ISO 8601 timestamp of publication. |
| `references` | Array | URLs to original CVEs, Proofs of Concept (PoCs), or Prismor Threat Lab write-ups. |

#### Example: Unsafe Tool Execution Threat
```json
{
  "id": "PRISMOR-2026-0042",
  "severity": "critical",
  "type": "unsafe_tool_execution",
  "title": "Arbitrary Code Execution via Unsanitized BashREPL Tool in Agent Framework",
  "description": "An issue in the default BashREPL execution tool allows an LLM to escape the intended restricted environment by chaining specific shell operators (e.g., `;` or `&&`). If an attacker successfully executes a prompt injection attack against the agent, they can leverage this tool to achieve arbitrary code execution on the host machine running the agent.",
  "affected": ["example-agent-framework<=2.1.0"],
  "action": "Disable the default BashREPL tool, or upgrade to version 2.1.1 which forces execution within an ephemeral, unprivileged Docker sandbox.",
  "published": "2026-02-20T12:00:00Z",
  "references": ["https://prismorsec.com/immunity/PRISMOR-2026-0042"]
}
```

## 5. The Immune Response Pipeline (CI/CD Generation)
The feed is not manually curated; it is the output of an automated, resilient intelligence pipeline optimized for speed and accuracy.

1. **Delta Detection:** The pipeline identifies the timestamp of the last successful run to fetch only new or updated records from upstream sources.
2. **NVD Extraction:** The system queries the NVD API using the defined AI ecosystem keywords, implementing robust rate-limit handling and exponential backoff.
3. **Prismor Translation Engine:** Raw NVD data is transformed into the Prismor schema. 
   - CVSS scores are mapped to Prismor `severity` tiers.
   - Traditional CWEs (Common Weakness Enumerations) are semantically mapped to AI-specific `type` categories (e.g., mapping CWE-78 [OS Command Injection] to `unsafe_tool_execution`).
4. **State Merging & Deduplication:** The newly fetched findings are merged with the existing `immunity-feed.json`, ensuring no duplicated intel and updating existing records if severity or mitigation steps change.
5. **Cryptographic Sealing:** The pipeline generates a detached Ed25519 signature (`immunity-feed.json.sig`) using a highly restricted private key stored securely in the CI/CD environment's secrets manager.
6. **Global Distribution:** The sealed feed is published to a high-availability CDN, ensuring that Prismor scanners worldwide receive the latest intelligence with minimal latency.

## 7. Reference Implementation Architecture (Directives for Code Generation)
To implement this architecture, the repository should be structured to support the automated CI/CD intelligence pipeline, state management, and cryptographic signing.

### 7.1 Required Repository Structure
```text
prismor/
├── .github/
│   └── workflows/
│       ├── poll-nvd-intel.yml      # Cron job to fetch NVD updates (runs daily)
│       └── process-community-intel.yml # Converts GH Issues into threat objects
├── advisories/
│   ├── immunity-feed.json          # The main, merged intelligence JSON file
│   └── immunity-feed.json.sig      # Detached Ed25519 signature of the feed
├── pipeline/
│   ├── fetch_nvd_intel.py          # Python script to poll NVD API, map CVSS to Prismor severity
│   ├── merge_intel.py              # Script to identify deltas and merge new threats into feed.json
│   └── sign_feed.sh                # Bash script utilizing openssl to sign the feed.json
├── scripts/
│   └── query.sh                    # Script to query the feed locally
├── schemas/
│   └── threat-object.schema.json   # JSON Schema definition for validation
└── README.md                       # Documentation on consumption and contribution
```

### 7.2 Core Implementation Requirements
When building this repository, the implementation must adhere to the following constraints:

1. **GitHub Actions (`poll-nvd-intel.yml`):**
   - Must be triggered on a `schedule` (e.g., cron `0 6 * * *`) and via `workflow_dispatch`.
   - Must check out the repository, run the `pipeline/fetch_nvd_intel.py` script, and pipe the output to `merge_intel.py`.
   - Must use a stored GitHub Secret (e.g., `PRISMOR_SIGNING_PRIVATE_KEY`) to execute `sign_feed.sh` and generate the `.sig` file.
   - Must commit the changes back to the repository automatically (e.g., standard `git config` and `git push` workflow) or create a PR.

2. **Fetching Logic (`fetch_nvd_intel.py`):**
   - Use the `requests` library to poll the NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0`).
   - Query using AI-specific keywords (`LangChain`, `LlamaIndex`, `OpenAI`, `Anthropic`, `Prompt Injection`, etc.).
   - Handle API rate limit HTTP 403/429 errors with `time.sleep()` backoffs.
   - Map NVD CWSS/CVSS scores to the Prismor `severity` tiers (e.g., `Score >= 9.0` -> `critical`).
   - Extract CWE metadata and map it to Prismor `type` enumerations (e.g., mapping Command Injection CWEs to `unsafe_tool_execution`).

3. **Merging Logic (`merge_intel.py`):**
   - Load the existing `advisories/immunity-feed.json`.
   - Compare new NVD results by `id` (e.g., `CVE-2026-XXXX`).
   - If new, append to the `.advisories[]` array. Create a new `updated` timestamp.
   - Ensure the final output complies with the `threat-object.schema.json` structure.

4. **Cryptographic Signing (`sign_feed.sh`):**
   - Use `openssl` with Ed25519 keys (e.g., `openssl pkeyutl -sign -inkey private.pem -rawin -in feed.json -out feed.json.sig.bin`).
   - Output an ASCII base64 encoded detached signature to `immunity-feed.json.sig` so clients can easily fetch and verify it.

### 7.3 Guidelines for LLM Generation
If you are an LLM reading this spec to generate the `prismor` repository:
- **Language Stack:** Use modern, typed Python 3.10+ for scripts. Use vanilla Bash for signing orchestration.
- **Dependencies:** Keep dependencies minimal (e.g., `requests`, `jsonschema`). Generate a `requirements.txt`.
- **Error Handling:** Ensure the NVD polling script fails gracefully so CI isn't perpetually red during NIST API downtimes.
- **Documentation:** Generate a `README.md` that explains exactly how a user should generate the Ed25519 keypair and where to put the public key for client consumption.

