# Final technical and research review

Review date: 2026-11-24 (Asia/Bangkok)
Scope: tracked source, both training notebooks, exported model/results, local PCAP pipeline, CLI, Streamlit application, tests, dependencies and Git hygiene.

## Executive verdict

No Critical defect was found in the reviewed inference path. The application restores and executes the reviewed PCAP QAE-QNN artifacts on CPU, and its outputs agree with the exported Colab rows within floating-point tolerance. The implementation is suitable for a controlled offline demonstration with the documented bundle and synthetic captures.

The project must not be described as a production IDS, a live-capture system, evidence of generalization to real networks, or evidence of quantum advantage. Two High research/distribution risks remain: exact feature vectors occur across the file-disjoint train/test split, and the upstream code/data redistribution license is not clearly published. These cannot be responsibly removed by an application-code change.

## Severity summary

### Critical

None found.

### High

1. **Limited independence of the PCAP evaluation.** Files and SHA-256 values do not cross splits, but `leakage_check.csv` reports 18 exact feature vectors shared by train/test, 17 by train/validation and 11 by validation/test. Labels are capture-level and the traffic is synthetic. The 1.0 metrics are correct for this exported split, but are at high risk of optimistic interpretation. Remaining action: evaluate on independently generated or real, separately sourced captures and report confidence intervals.
2. **Unresolved upstream redistribution terms.** The associated upstream README says “Research use only” and refers to a LICENSE file, but no LICENSE file was visible during this review. The Zenodo record did not display a license value. `NOTICE.md` now records provenance and the restriction. Remaining action: obtain written permission or a concrete license from the upstream owner before public redistribution or non-evaluation use.

### Medium

1. **Artifact authenticity is not independently signed.** The current artifacts match Colab predictions and their reviewed bytes are now pinned in `models/checksums.sha256`, but this proves integrity after review, not who trained them or from which immutable training run. A signed release manifest produced in Colab would close the provenance gap.
2. **Evaluation scope is small.** PCAP test contains 83 windows from 16 captures. Benchmark summaries use two folds and one seed, and raw per-sample benchmark scores are absent. Results are descriptive, not robust estimates of deployment performance.
3. **Probabilities are not calibrated on real traffic.** `attack_probability = 1 - P(Normal)` and the 0.5 binary threshold match the notebook, but should not be interpreted as real-world risk probability without calibration.
4. **Large capture cost.** Extraction intentionally reads the capture twice. CLI processing is streaming, but Streamlit uploads retain the uploaded file in memory and default to 200 MB. A reviewed 119.9 MB capture took about 20.5 seconds locally; larger files should use the CLI. This is acceptable for offline analysis, not line-rate monitoring.
5. **Clean-clone end-to-end PCAP tests require external data.** Unit/model tests run from tracked files, while two Streamlit tests skip if demo PCAPs have not been prepared. README now states this explicitly and provides the preparation workflow.

### Low

1. Streamlit AppTest emits `missing ScriptRunContext` warnings in bare test mode; tests still pass and the warning does not occur as an application exception.
2. Git on this workstation reports that the global ignore file under the Windows user profile is unreadable. Repository-local ignore rules work and protected data remained untracked.
3. Exact dependency pins improve reproduction of this bundle but will eventually require a reviewed upgrade cycle for security and wheel availability.

## Review of the 18 requested questions

| # | Finding | Verdict and evidence |
|---:|---|---|
| 1 | Correct trained model | **Pass with provenance limitation.** `hybrid.pt` loads strictly on CPU with tensors `theta (2,3)`, `head.weight (4,13)`, `head.bias (4)`. The tensors equal the checkpoint byte-for-byte in tests. Predictions match 71 exported Colab rows across five CSVs; 55 unique windows are covered. Current artifact hashes are pinned. A signed original export is still absent. |
| 2 | Quantum circuits match notebook | **Pass.** QAE uses 3 qubits, RX/RY/RZ per qubit and CX ring `0→1→2→0`. VQNN applies two six-feature Ry encoding blocks, the same CX ring, then two learned Ry layers. Independent Qiskit statevector tests reproduce QAE features and VQNN probabilities. |
| 3 | f1–f6 formulas | **Pass for the notebook contract.** f1 total packets; f2 SYN/max(SYN-ACK,1); f3 distinct IPv4 sources; f4 maximum GET/POST TCP packet count per source; f5 source IPv4 entropy with total packets as denominator; f6 UDP count. Windowing starts at the minimum timestamp, keeps non-empty complete 5-second windows and drops the incomplete tail. All 83 exported test windows matched, with maximum observed f5 difference `9.77e-14` and zero for the other five features. |
| 4 | Correct fitted scaler | **Pass.** The tracked `MinMaxScaler` is fitted on 259 training rows, has `clip=True`, range `[0,1]`, six ordered features and float64 coefficients. Runtime performs notebook-equivalent `log1p` before transform. Checksum is pinned. |
| 5 | Data leakage | **High limitation, no file/hash leakage.** Splitting is by capture file and no filename/SHA-256 crosses splits. However exact feature vectors cross splits (18 train/test), so evaluation independence is weakened. Scaler and QAE use training data only; QAE threshold uses validation Normal rows. |
| 6 | Label used as model input | **Pass.** Runtime selects exactly ordered f1–f6. A new test proves changing `label`, `target` and a fake `prediction` metadata column leaves inference identical. |
| 7 | Hardcoded prediction | **Pass.** Predictions come from restored weights, QAE features, linear head and softmax. Tests compare independent circuits, multiple batch sizes and Colab exports. No class-return lookup or filename-based prediction exists. |
| 8 | Fake UI data | **Pass.** Operational values originate from the active analysis/replay session. Research pages read tracked exported artifacts. Empty sessions render an explicit empty state; no random or mock event generation exists. “Demo library” means real local PCAP files, not fabricated predictions. |
| 9 | Metrics match research | **Pass within exported scope.** PCAP accuracy, macro-F1, binary-F1 and binary ROC-AUC reproduce as 1.0. The CIC-DDoS2019 QAE+QNN V4 macro-F1 summary is `0.8651685`. The UI labels sources and scope. These figures must retain the limitations above. |
| 10 | Benchmark/PCAP model confusion | **Pass.** Runtime inference exclusively loads `models/`, the PCAP export. Benchmark pages only read `results/benchmark`; their metrics are not fed to inference. PCAP metrics are displayed in a separately labelled expander. |
| 11 | Replay described as live capture | **Pass.** UI and README explicitly say offline replay and not live capture. Replay advances already extracted complete windows and performs no network sniffing. |
| 12 | Quantum advantage overclaim | **Pass after documentation hardening.** The application states CPU statevector simulation. README now explicitly says the results do not demonstrate quantum advantage. Classical RF/MLP/QNN equality on the PCAP split is visible rather than hidden. |
| 13 | Dependency/Windows errors | **Pass in reviewed environment.** CPython 3.11.9 on Windows, all versions match `models/environment.json`, `pip check` reports no broken requirements, and the app/tests run. Console logs were made CP1252-safe. Future dependency upgrades still require review. |
| 14 | Performance/memory | **Acceptable for offline demo, not live IDS.** Batched 83-window inference p50 was documented at about 1.56 ms with batch 512 after loading. Packet extraction dominates runtime and uses two sequential passes. Streamlit uploads add memory pressure; CLI is recommended for large PCAPs. |
| 15 | Absolute paths | **Pass for runtime source.** Runtime paths derive from `Path(__file__)`. Colab-only `/content/...` and Drive paths remain inside notebooks as expected and are now called out in README. |
| 16 | Secrets/private/large files | **Pass with normal GitHub caution.** Pattern scan found no token, private key or password. `.env`, Streamlit secrets, AWS data, keys, ZIP/PCAP and `data/` are ignored. Largest tracked file is the 384,318-byte benchmark notebook; no GitHub-size-risk file is tracked. Notebook metadata contains the researcher's display name/user identifier, which is not a credential but should be reviewed if anonymity is required. |
| 17 | License | **High unresolved risk.** See `NOTICE.md`. No upstream/UI code or asset was intentionally copied for the SOC redesign, but the research algorithm/dataset provenance needs explicit permission before redistribution. This project itself also has no grant-of-rights LICENSE; do not assume open-source permission. |
| 18 | README clone/run completeness | **Pass after fixes.** README now includes clone, venv, exact install/verification/start commands, data preparation, test-skip behavior, path behavior, resource expectations, offline semantics, research limits and the license notice. |

## Fixes made during review

- Added `models/checksums.sha256` and made `scripts.verify_model` reject changed reviewed artifacts.
- Added automated checksum and label/metadata isolation tests in `tests/test_review_contracts.py`.
- Added `NOTICE.md` for dataset/code provenance and unresolved license terms.
- Expanded README with clean-clone commands, resource requirements, external PCAP preparation, expected test skips, portable path behavior, offline replay semantics and the explicit absence of a quantum-advantage claim.
- Did not alter model weights, scaler, quantum circuits, feature formulas, thresholds or prediction logic.

## Verification results

Reviewed environment: Windows, CPython 3.11.9, CPU-only.

- `python -m scripts.verify_model`: passed; checksum, scaler, QAE and checkpoint contracts passed.
- `python -m scripts.check_environment`: passed; eight recorded package versions matched the Colab export and CPU circuit smoke test passed.
- `python -m pip check`: no broken requirements.
- `python -m unittest discover -s tests -q`: **21/21 passed**, including real local PCAP Analysis/Replay tests (no skips in this workspace).
- Colab parity maximum absolute differences: confidence `2.79e-08`, attack probability `2.83e-08`, anomaly score `2.22e-16`.
- `ruff check app.py core pages scripts tests`: passed.
- `python -m compileall -q app.py core pages scripts tests`: passed.
- `git diff --check`: passed.

## Demo risk statement

The safest demonstration is an offline, deterministic reproduction: verify checksums, analyze a manifest-verified synthetic PCAP, show extracted f1–f6, and compare its prediction with the exported Colab row. State clearly that the quantum circuits are simulated on a classical CPU, replay is not live capture, probabilities are not real-network calibrated, exact feature duplicates exist across splits, and license permission remains unresolved. Do not claim deployment readiness, zero-day detection, real-time throughput, generalization to operational networks or quantum advantage.
