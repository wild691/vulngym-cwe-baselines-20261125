# Frozen VulnGym parallel baseline proposal

Prepared 2026-11-25. Public publication and standard-runner execution have been authorized by the account owner. Actual run status is recorded in GitHub Actions; publishing the definition does not establish successful execution or detection performance.

This package contains public repository/commit indices and static experiment scripts for the frozen Tencent/VulnGym v0.1.5 corpus, commit `abfcb1aa0cb4e8719f6550b0a7b41169d7a3843f`.

The same 91 snapshots represent 97 selected advisories across all 65 observed advisory CWE IDs, with up to three advisory samples per CWE. Selection and CWE mapping remain in the local research workspace; no labels or annotated locations are supplied to the scanners.

The workflow uses **standard `ubuntu-24.04` public GitHub runners**, up to 16 concurrent snapshot jobs. Dispatch `smoke` first to verify one existing Python snapshot (`s_c9313122c553`); dispatch `full` only after verifying its evidence. The full run includes all 91 snapshots, without choosing cases based on the smoke result. CodeQL CLI2.27.5 / Python queries1.9.2 / JS queries2.5.2, official default code-scanning suite and forced reevaluation; Semgrep CE1.186.0 with locked official rule hashes; Bandit1.9.4 for Python. The source projects are parsed, never executed or built. Only Python/JavaScript CodeQL is configured; unsupported languages/queries must not be scored as false negatives.

No model API is called. No Actions artifact or cache is uploaded: compressed reports are emitted into job logs for retrieval. GitHub's billing page was checked locally on 2026-11-25 and states that standard hosted runners in public repositories are free independently of included compute usage. This does not authorize larger runners, private-repository compute, Copilot, or paid services.

**Publishing requires approval because it creates a public GitHub repository containing these experiment files and public logs.** A browser login alone is not API/CLI authorization; first-use GitHub CLI/device authorization may require the account owner to confirm. No API key, browser cookie, or local credential file belongs in this package.

Linux cloud outputs are a separate platform/configuration baseline, not silently combined with the historical Windows runs or incompletely rerun threat-model variants. Raw execution success is not a vulnerability verdict. Source/setup failures, timeouts, parser and rule support must be reviewed; no type ranking or precision/F1 is automatically produced.

Source attribution: [Tencent/VulnGym](https://github.com/Tencent/VulnGym), dataset CC-BY-4.0. This package includes only a transformed public snapshot index; each upstream source and tool retains its own license. Rule files are downloaded for the owner's internal analysis from official URLs and are not redistributed here. Fingerprints lock all matching fields, IDs, messages, severities and options, while ignoring metadata and ordering for the comparison only; original downloaded files and notices remain unmodified during scanning. Actual raw hashes and matching fingerprints are exported in the receipts. A matching-configuration change fails setup instead of silently mixing baselines. See `rule_fingerprint.py` for the explicit algorithm.
