# Assessment Desk + Obsidian vault

## Open
- Double-click **Start Assessment.cmd** in the parent folder. The local application listens on **http://127.0.0.1:8765**. Keep its terminal open.
- In Obsidian, choose **Open folder as vault** and select **Assessment Vault**. Start with **Home.md**.
- Copy the entire parent folder to another Windows x64 bench to retain the embedded Python runtime, app data, vault and PDF links. For Linux/macOS, install Python 3.10+ and run `python assessment/serve.py`; rebuilds additionally need PyMuPDF.

## What is included
- All 1,739 unique CVEs in the supplied CSV, with descriptions, vendor/product, ransomware and triage flags, catalog dates, actions and reference URLs.
- NVD applicability data for every entry: affected-version boundaries, nested AND/OR environment conditions, descriptions, access metrics and dated provenance. These are analyst evidence, not automatic version verdicts.
- Eleven self-contained book-derived assessment methods with find/verify/fix/retest steps and decision branches. Applicable methods are embedded in each CVE note and the app; opening books is optional.
- Three individually vendor-reviewed catalog guides (BIND CVE-2015-5477, Struts CVE-2016-3081 and Strapi CVE-2023-22894), including configuration checks and exact remediation distinctions. Research for two related non-catalog Strapi issues (CVE-2023-22621 and CVE-2023-22893) is retained in cve_overrides.json. Additional NVD-indexed upstream GitHub patch candidates are labeled as unreviewed.
- One vault note per CVE; vendor/CWE grouping; branching assessment logic; platform inventory commands; attacker-vantage discovery and evidence templates.
- Full-text extraction of all 11 PDFs / 5,391 pages, source hashes, embedded contents and page-linked search. 92 low-text pages are flagged; no OCR was performed. Extraction is not comprehensive manual review.
- Offline CLI product correlation for every catalog entry. Product/vendor identity matching is exact and case-insensitive; aliases must be normalized to the catalog identity by the assessor. No version ranges are guessed.
- Asset/CVE evidence records with branch-derived status, editing, JSON backup/import and Obsidian Markdown export.
- A detection-validation guide covering low-signal activity, authorization/identity correlation, telemetry gaps, alert latency, false positives and verified containment. It is linked in each CVE workflow and in the vault; it is not a stealth/evasion implementation.

## Analyst training: actions and defensive interpretation
Open **03 Analyst training** in the app or **Analyst Training.md** in the vault. All 14 requested groups and 198 topic entries have behavior explanations, evidence checks, prevention, exercises, shared group procedures and outcome branches. Repeated topic names are retained under their distinct groups with unique vault filenames.

Six hands-on labs pair operator actions with defender checks: bounded Nmap port discovery, print-only PowerShell execution, inert file-integrity fixtures, synthetic-account authorization/logout/containment, read-only AWS/Kubernetes inspection, and an executable offline telemetry-gap classifier. Commands include prerequisites, expected results and limits. The eight fictional records in `training_fixtures.json` distinguish source, ingestion, alert and containment gaps, normal no-alert behavior and unintended alerts. Run that PowerShell exercise from this assessment folder.

These are not operational instructions for credential theft, covert persistence/C2, detection bypass or destructive attacks. Those topics use defensive inspection and clearly labeled fixture/tabletop exercises. A replay tests query logic, not live capture; an inert marker tests visibility, not resistance to every malicious variant. Environment-specific Nmap, AWS, Kubernetes and identity procedures require the stated tools and owner-provided lab targets/accounts. No new snapshot/reset workflow is introduced. This preserves the user's category labels, not exact current ATT&CK technique mappings; the source/taxonomy note explains the current 15-tactic matrix.

## CLI (PowerShell, from this assessment folder)
Copy `inventory.example.json` to `inventory.json`, replace the example objects with collected evidence, then:

```powershell
..\.tools\python\python.exe check.py --inventory inventory.json
..\.tools\python\python.exe check.py --cve CVE-2015-5477 --inventory inventory.json
```

Omitting `--cve` correlates all catalog rows. Results are **Candidate** or **Not matched**, never proof of vulnerability or absence. No system is scanned or changed by this command. Terminal inventory commands are supplied as reference text; the app does not run them.

## Lab workflow
Find reachable interfaces from the attacker vantage point → correlate product → verify the vendor's version/configuration prerequisites → record the documented lab test and expected/observed result → fix → repeat the same test and check normal functionality. Your existing lifecycle scripts remain outside this application; testing does not depend on snapshots/resets here.

## Important incomplete coverage
All entries now have NVD enrichment and embedded assessment methods, but only three catalog CVEs have individually vendor-reviewed CVE-specific defensive instructions. Most verification procedures are weakness-family or applicability checks, not validated reproductions of the named CVE. This is not 1,739 validated detectors or bespoke exploit walkthroughs. No bulk exploit kit, destructive exploit programs, or stealth/detection-bypass recipes are included. GitHub links are defensive source/fixes, not exploit downloads; automatically selected patch links have not been individually reviewed or executed. Platform categorization and weakness mapping are heuristic. Books contributed selected, substantively reviewed material, not exhaustive coverage of every page or technique. No vulnerable target builds were exercised here.

## Evidence storage and portability
Records live in browser local storage on this origin, **not in the server folder**. They are not encrypted, multiuser-synchronized or tamper-evident. Export JSON before moving machines, changing browsers or clearing browser data. Import merges by asset + CVE and updates matching pairs. Markdown export can be saved under the vault's Assessments folder; there is no automatic vault/app sync. Do not use this reference server as a shared production service.

## Rebuild and test
Prebuilt data is included. Rebuild generated CVE/vendor/weakness/source/method/training notes after changing the source CSV/PDFs, guide_content.json, training_content.json, cve_overrides.json or research/nvd-kev.json:

```powershell
..\.tools\python\python.exe build.py
..\.tools\python\python.exe tests.py
..\.tools\python\python.exe ui_tests.py
```

`build.py` needs PyMuPDF (included in the local runtime). The fixture command test requires Windows PowerShell. UI tests need Playwright (included) and installed Edge, plus the app running on port 8765. Generated notes are overwritten on rebuild; keep custom work in separate notes/Assessments. The application runtime itself uses only Python's standard library and local browser assets. The app makes no cloud API calls; cloud lab commands are manually executed only against owner-approved accounts.
