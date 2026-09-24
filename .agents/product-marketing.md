# Product Marketing Context

**Document version:** v1
**Last updated:** 2026-09-24
**Status:** Working draft based on the local prototype and supplied positioning references. Customer demand and pricing have not been validated.

## Product Overview

**One-liner:** LogProof is a local-first prototype for reviewing how raw security logs become structured events and for checking parser changes before promotion.
**What it does:** It retains ingested raw bytes, records field mappings and parser versions, signals shape drift, quarantines failed or incomplete parses, and replays old and candidate parsers on the same corpus before a named approval.
**Product category:** Pre-SIEM log preprocessing assurance.
**Product type:** Working hackathon prototype; production product is proposed.
**Business model:** Illustrative India-market proposal for a free community tier, annual self-hosted licenses, and a paid pilot. No live offer or validated price points.

## Target Audience

**Target companies:** Teams with heterogeneous security logs and a need to inspect parser behavior. Restricted-network and government use cases are a proposed direction, not validated deployments.
**Decision-makers:** Security engineering, detection engineering, SOC leadership, and platform engineering.
**Primary use case:** Review the integrity and interpretation of a log event when a source format or parser changes.
**Jobs to be done:**

- Explain where a normalized field came from.
- Keep malformed or incomplete parses available for investigation.
- Compare a candidate parser against a fixed sample corpus before promotion.

## Positioning

**Core problem:** Collection and transformation alone do not give a team a single review trail for raw evidence, field interpretation, drift, replay results, and parser approval.
**Value promise:** Make parser changes explainable and reviewable before downstream analytics relies on the changed output.
**Current proof:** A local demo shows raw-byte retention and SHA-256 integrity checking, field maps, drift/quarantine, equal-corpus replay, human-approved promotion, and rollback. The hash does not prove source-device authenticity.
**Scope boundary:** The demo does not implement SIEM export, production throughput, source authentication, signed packs, full OCSF mapping, or air-gapped distribution.

## Competitive Landscape

| Product or foundation                                                                                                                                                                                                                                                                                | Documented role                                      | LogProof positioning                                                 |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------- |
| [Cribl Stream](https://docs.cribl.io/stream/basic-concepts/)                                                                                                                                                                                                                                         | Collect, process, preview, replay, route telemetry   | Center the receipt-to-field explanation and parser promotion gate    |
| [Datadog Observability Pipelines](https://docs.datadoghq.com/observability_pipelines/configuration/set_up_pipelines/)                                                                                                                                                                                | Process and route data with pipeline simulation      | Center local raw evidence and parser-change review                   |
| [Splunk Edge Processor](https://help.splunk.com/en/splunk-enterprise/process-data-at-the-edge)                                                                                                                                                                                                       | Filter, mask, transform, route data near source      | Verify parsed meaning upstream of analytics                          |
| [Elastic / Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)                                                                                                                                                                                                      | Configurable input, filter, and output pipelines     | Guided evidence and parser acceptance workflow                       |
| [Vector](https://vector.dev/docs/reference/configuration/unit-tests/), [Fluent Bit](https://docs.fluentbit.io/manual/data-pipeline/parsers), [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/), [OCSF](https://github.com/ocsf/ocsf-docs/blob/main/overview/understanding-ocsf.md) | Transform tests, collection, transport, event schema | Potential building blocks or standards; integrations are not shipped |

These are product-emphasis comparisons, not claims that any competitor lacks a specific feature. Cribl preview/replay, Datadog pipeline simulation, and Vector transform tests overlap parts of the proposed story.

Feature-specific references: [Cribl Data Preview](https://docs.cribl.io/stream/pipelines/), [Cribl Collector replay](https://docs.cribl.io/stream/collectors/), [Datadog Pipeline Simulation](https://docs.datadoghq.com/observability_pipelines/configuration/set_up_pipelines/), and [Vector unit tests](https://vector.dev/docs/reference/configuration/unit-tests/).

## Objections and Answers

| Objection                                | Answer                                                                                                                                                                                                    |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| “Our pipeline already tests transforms.” | LogProof's demo links raw evidence, field mapping, drift, equal-corpus replay, and human approval in one parser-change review loop. Evaluate whether that workflow adds value in the buyer's environment. |
| “Is it production-ready?”                | No. It is a local prototype with representative generated samples. Production connectors, security controls, and performance need validation.                                                             |
| “Can it replace our SIEM or pipeline?”   | Replacement is not the product claim. A future version is intended to verify parsed events upstream of downstream tools.                                                                                  |

## Brand Voice

**Tone:** Precise, confident, evidence-led.
**Words to use:** raw evidence, field mapping, parser drift, quarantine, replay, approval gate.
**Words to avoid:** proven source authenticity, production scale, guaranteed compliance, unique replay, competitor feature absence.

## Proof and Goals

**Metrics:** No production throughput or customer results measured.
**Customers and testimonials:** None supplied.
**Current conversion action:** Run the local demo, inspect evidence, and compare a parser candidate.
**Future validation:** Test real customer source formats, operational fit, willingness to pay, and proposed deployment/security features in a scoped pilot.

## Changelog

- v1 (2026-09-24) — Initial positioning context for the Why LogProof section, with prototype and competitor claim boundaries.
