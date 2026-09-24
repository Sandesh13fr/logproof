# LogProof: SIH Jury Q&A

Short answers for likely industry-jury questions. Keep the distinction clear: LogProof is a working local prototype and an assurance-layer concept, not a ministry-ready universal log platform.

## Core explanation

**What is LogProof?**  
LogProof is a local-first prototype that accepts selected security-log formats, keeps the received event available, maps parsed fields to their source, and lets a reviewer test a firewall-parser change against golden samples before approval.

**What problem does it address?**  
Security teams receive events with different layouts and field names. A bad or changed parser can lose or misstate useful context before events reach a SIEM or analytics system. LogProof makes selected transformations inspectable and gives one parser family a replay-and-review path.

**What is the purpose in one sentence?**  
Make it easier to see what a parser did to an event and to check a parser change before using it.

## Likely jury questions

### 1. Is the approach novel, or is this just another parser?

Log parsing and preprocessing are established areas. Qin et al. (SANER 2025) directly study general preprocessing to improve log-template parsers, so we do not claim to have invented preprocessing. Our prototype brings raw-event inspection, field-to-source mappings, drift visibility, and a reviewed replay path together in one workflow. The replay and approval implementation is currently for the firewall example; broader assurance coverage is future work. ([Qin et al.](https://doi.org/10.1109/SANER64311.2025.00036), [preprint](https://arxiv.org/abs/2412.05254); [prototype scope](../../README.md#prototype-boundaries))

### 2. What does LogProof currently support?

The demo has ten sample source families across JSON, CSV, LEEF, Syslog, CEF, NGINX combined access logs, and Windows Event XML. These are representative prototype parsers, not complete implementations of every standard or vendor extension. Windows Security JSON is explicitly simplified sample data; Windows Event XML is a separate input. ([formats and limitations](../../README.md#formats-in-the-demo))

### 3. Are the datasets authentic and representative of ministry traffic?

Most built-in samples are synthetic and demonstrate format conversion; they do not establish real-world source diversity or representativeness. An optional bounded import uses sanitized events attributed to the [WitFoo Precinct6 dataset](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity-100m), but that alone is not a representative ministry corpus. For a pilot, we would need approved, appropriately sanitized samples from the target environment and documented source coverage.

### 4. Does the hash prove who sent a log or that it was never changed?

No. SHA-256 lets us check whether the bytes stored by LogProof still match the digest recorded at receipt. It does not authenticate the source device, prove who created the event, protect the database and digest from a privileged attacker, or establish trusted time. Those require additional identity, key, transport, and audit controls. ([README](../../README.md#prototype-boundaries))

### 5. Is normalization lossless? What happens to unknown fields?

The normalized schema is not lossless by itself. The prototype preserves the received raw event alongside its parsed record and provides field mappings, so an analyst can inspect the original input. That is a raw-evidence retention claim for this prototype, not a guarantee that every source extension is understood or every downstream export preserves all semantics. ([ingestion and formats](../../README.md#formats-in-the-demo))

### 6. Is this OCSF-compliant or a universal schema?

No. The current canonical record is a limited LogProof schema, not full OCSF conformance and not a universal schema. A production design should map supported source fields to a chosen, versioned target taxonomy, preserve unmapped data, and publish conformance tests. ([prototype boundaries](../../README.md#prototype-boundaries); [OCSF project](https://ocsf.io/))

### 7. How are parser quality and accuracy measured?

The evaluation uses 20 curated synthetic cases across the ten demo source families. It compares normalized field key/value pairs against expected values and reports precision, recall, and F1; labeled malformed/valid cases also measure quarantine precision, recall, and F1. It reports exact fixture pass rate and local evaluation runtime. These are repeatable checks on this small fixture set—not production accuracy, broad format coverage, or proof that the cases represent ministry traffic.

### 8. How do you prevent a parser update from silently breaking records?

For the firewall parser, the prototype replays the same golden samples against current and candidate versions, shows changes, and supports named approval and rollback. Other parsers do not yet share that promotion gate. Before production, each supported parser would need versioned representative fixtures, explicit acceptance thresholds, and a controlled release process. ([README](../../README.md#what-is-implemented))

### 9. Does LogProof detect attacks?

No. It parses and organizes selected event data; it is not an IDS, SIEM, threat detector, or incident-response system. Any future filtering must be measured carefully because removing events that look redundant can erase useful sequence, count, or location context. Zheng et al. show this risk in failure-prediction logs; their results are specific to their datasets and task. ([Zheng et al.](https://doi.org/10.1109/DSN.2009.5270289))

### 10. Can it scale to billions of events per day or run at ministry scale now?

That has not been demonstrated. The documented benchmark is a sequential, single-process local microbenchmark; it is not a distributed or concurrent capacity test. The prototype uses SQLite and local files and lacks production backpressure, high availability, multi-user access control, native collectors, and a production throughput assessment. A ministry deployment would need representative load tests, resilient storage, security review, operational monitoring, and a staged pilot. ([bounded workload and limits](../../README.md#bounded-local-workload))

### 11. Does the offline bundle prove air-gapped deployment is ready?

It proves a narrower path: application images were exported, loaded from an archive without registry pulls, and started with Docker Compose on the tested machine. A separate ministry air-gapped host has not been tested. The optional WitFoo fetch needs a network connection, and persistent data needs its own backup plan. ([offline transfer verification](../../README.md#offline-container-transfer))

### 12. Which research supports the problem, and how does LogProof relate?

The papers address related but different tasks: Qin et al. improve preprocessing for log parsing; Zheng et al. study preprocessing for failure prediction; web-log studies address usage mining or intrusion detection; and Marin-Castro and Tello-Leal review event-log preparation for process mining. Together they support the importance of careful, task-aware preprocessing—not the claim that one schema or parser fits every source. LogProof applies that motivation to an evidence-oriented parser-review workflow. ([Qin et al.](https://doi.org/10.1109/SANER64311.2025.00036); [Zheng et al.](https://doi.org/10.1109/DSN.2009.5270289); [Hussain et al.](https://doi.org/10.1109/ICIET.2010.5625730); [Dhanalakshmi et al.](https://doi.org/10.1109/IACC.2016.35); [Marin-Castro & Tello-Leal](https://www.mdpi.com/2076-3417/11/22/10556); [related-paper review](logproof-paper-literature-review.md))

### 13. What is the next responsible step?

Run a time-boxed pilot with approved logs from a small set of perimeter devices. Agree on source coverage and field semantics, compare outputs with analyst-reviewed expected results, test malformed and changed formats, review security and retention controls, then benchmark representative volume and concurrency. Expand only when the pilot meets explicit acceptance criteria.

## Claims to avoid

- “The hash proves log authenticity.” It only checks bytes against the digest recorded at receipt.
- “We support every vendor and format.” The prototype has selected representative parsers.
- “We are OCSF-compliant” or “we provide a universal schema.” Neither is implemented.
- “We are proven for ministry scale or billions of events.” No such capacity test has been run.
- “Our fixture score is production accuracy.” It measures only a small, curated synthetic evaluation set.
- “LogProof detects attacks.” Attack detection is outside the current product behavior.

## References

- [LogProof README: formats, implementation, limits, workload, and offline transfer](../../README.md)
- [LogProof paper review and detailed prior-art comparison](logproof-paper-literature-review.md)
- [Qin et al., *Preprocessing is All You Need* (SANER 2025)](https://doi.org/10.1109/SANER64311.2025.00036)
- [Zheng et al., *System Log Pre-processing to Improve Failure Prediction* (DSN 2009)](https://doi.org/10.1109/DSN.2009.5270289)
- [Marin-Castro & Tello-Leal, *Event Log Preprocessing for Process Mining: A Review* (2021)](https://www.mdpi.com/2076-3417/11/22/10556)
- [Hussain et al., *Web Usage Mining: A Survey on Preprocessing of Web Log File* (2010)](https://doi.org/10.1109/ICIET.2010.5625730)
- [Dhanalakshmi et al., *The Research of Preprocessing and Pattern Discovery Techniques on Web Log Files* (2016)](https://doi.org/10.1109/IACC.2016.35)
- [Patil & Patil, *Preprocessing Web Logs for Web Intrusion Detection* (2013 publisher record)](https://www.ijais.org/proceedings/icwac/number3/492-1332/)
- [OCSF project](https://ocsf.io/)
- [WitFoo Precinct6 Cybersecurity dataset card](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity-100m)
