# Cybersecurity Assessment Vault

An Obsidian knowledge vault with an offline assessment application, CVE reference data, and analyst training. Source PDF books are kept locally and are not included in the repository.

## Open the vault

In Obsidian, choose **Open folder as vault**, select **Assessment Vault**, and open **Home.md**. Open that subfolder, not this repository root.

On Windows x64, double-click **Start Assessment.cmd** to start the companion application at http://127.0.0.1:8765. Keep its terminal open. The bundled Python runtime is included so the existing launcher works after cloning.

## Repository layout

| Path | Purpose |
| --- | --- |
| `Assessment Vault/` | Obsidian notes and shared vault settings |
| `Assessment Vault/CVEs/` | CVE reference notes |
| `Assessment Vault/Guides/`, `Playbooks/`, `Training/` | Assessment methods, workflows, and analyst training |
| `Assessment Vault/Vendors/`, `Weaknesses/`, `Sources/` | Vendor, weakness, and source indexes |
| `Assessment Vault/Assessments/` | Location for manually saved assessment notes |
| `assessment/` | Offline app, build tools, tests, and usage documentation |
| `assessment/data/`, `assessment/research/` | Prebuilt catalog, extracted page index, and research data |
| `known_exploited_vulnerabilities.csv` | Source vulnerability catalog |
| `.tools/python/` | Portable Windows x64 Python runtime and dependencies |
| `Start Assessment.cmd` | Windows app launcher |

The existing folder names are intentional: generated notes, source links, and build tools depend on them. The prebuilt vault and app data are included. PDF links, PDF viewing, and rebuilding from books require your own local source PDFs at their original paths; cloning does not download them. See [the application guide](assessment/README.md) for rebuilding, testing, coverage limits, and evidence workflows.

## What Git backs up

Notes, source data, application files, the portable runtime, and shared Obsidian configuration are included. PDF books, temporary caches, local agent artifacts, secrets, local inventory files, and Obsidian window/workspace state are excluded by `.gitignore`. The extracted page index still contains book text; excluding PDFs does not remove that text.

**Application evidence lives in browser local storage, not in this repository.** Export it from the app before moving machines or clearing browser data. Keep sensitive evidence backups outside the repository unless you deliberately review and add them. Markdown exports saved in `Assessment Vault/Assessments/` will be tracked; review them for sensitive information before committing.

## Publish with GitHub Desktop

1. Add this existing repository using **File > Add local repository** and select this parent folder.
2. Choose **Publish repository**. Suggested name: `cybersecurity-assessment-vault`.
3. Leave **Keep this code private** checked, then publish.
4. For later updates, review changes, commit to `main`, and choose **Push origin**.

This repository contains extracted third-party book text, but not the source PDFs. Keep the repository private unless you have verified redistribution rights for all included material; private visibility does not itself grant those rights. No blanket license is applied to third-party content. Only perform assessment exercises against systems you own or are authorized to test.
