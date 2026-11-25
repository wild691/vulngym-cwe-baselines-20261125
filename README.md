# Frozen VulnGym parallel baseline proposal

Prepared 2026-11-25. **Not published or run.**

This package contains public repository/commit indices and static experiment scripts for the frozen Tencent/VulnGym v0.1.5 corpus, commit `abfcb1aa0cb4e8719f6550b0a7b41169d7a3843f`.

The same 91 snapshots represent 97 selected advisories across all 65 observed advisory CWE IDs, with up to three advisory samples per CWE. Selection and CWE mapping remain in the local research workspace; no labels or annotated locations are supplied to the scanners.

The workflow uses **standard `ubuntu-24.04` public GitHub runners**, up to 16 concurrent snapshot jobs. CodeQL CLI2.27.5 / Python queries1.9.2 / JS queries2.5.2, official default code-scanning suite and forced reevaluation; Semgrep CE1.186.0 with locked official rule hashes; Bandit1.9.4 for Python. The source projects are parsed, never executed or built. Only Python/JavaScript CodeQL is configured; unsupported languages/queries must not be scored as false negatives.

No model API is called. No Actions artifact or cache is uploaded: compressed reports are emitted into job logs for retrieval. GitHub's billing page was checked locally on 2026-11-25 and states that standard hosted runners in public repositories are free independently of included compute usage. This does not authorize larger runners, private-repository compute, Copilot, or paid services.

**Publishing requires approval because it creates a public GitHub repository containing these experiment files and public logs.** A browser login alone is not API/CLI authorization; first-use GitHub CLI/device authorization may require the account owner to confirm. No API key, browser cookie, or local credential file belongs in this package.

Linux cloud outputs are a separate platform/configuration baseline, not silently combined with the historical Windows runs or incompletely rerun threat-model variants. Raw execution success is not a vulnerability verdict. Source/setup failures, timeouts, parser and rule support must be reviewed; no type ranking or precision/F1 is automatically produced.

Source attribution: [Tencent/VulnGym](https://github.com/Tencent/VulnGym), dataset CC-BY-4.0. This package includes only a transformed public snapshot index; each upstream source and tool retains its own license. Rule files are downloaded from official URLs and checked against local frozen hashes rather than redistributed here.
