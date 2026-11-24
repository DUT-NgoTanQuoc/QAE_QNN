# Provenance and use notice

This repository is a research implementation and offline evaluation interface. It is not a production IDS and does not perform live packet capture.

The synthetic PCAP dataset and the research context originate from:

- Rakshit Raj, *DDoS Detection Dataset: Synthetic PCAPs, Standard Benchmarks, and Quantum-Classical Hybrid Results*, Zenodo, DOI `10.5281/zenodo.21705919`.
- The associated upstream repository: <https://github.com/hgdttf/ddos-quantum-framework>.

The upstream README currently describes its code as "Research use only" and refers to a LICENSE file, but no LICENSE file was visible during the review on 2026-11-24. The Zenodo record also did not display a license value. Consequently, this repository does not claim that upstream code or data has an open-source redistribution grant. Confirm permission with the upstream author before public redistribution or reuse beyond evaluation.

The application source in this repository was implemented for the exported QAE-QNN artifacts and notebook contract. No source or assets from the UI reference repositories were copied. Third-party Python packages remain subject to their own licenses.

`models/checksums.sha256` records the artifact bytes reviewed in this repository. It is an integrity record, not a digital signature and not independent proof of training provenance.
