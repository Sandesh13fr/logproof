"use client";

import {
  ArrowRight,
  ArrowUpRight,
  Database,
  Fingerprint,
  GitCompareArrows,
  RotateCcw,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";

const assuranceSteps = [
  {
    number: "01",
    icon: Database,
    title: "Keep the original",
    detail:
      "A receipt points back to saved raw bytes. The demo verifies those bytes against a stored SHA-256 hash.",
    action: "Inspect evidence",
    target: "evidence",
  },
  {
    number: "02",
    icon: Fingerprint,
    title: "Explain each field",
    detail:
      "The normalized record carries source-field mapping and the parser version that produced it.",
    action: "Trace a field",
    target: "evidence",
  },
  {
    number: "03",
    icon: GitCompareArrows,
    title: "Surface format drift",
    detail:
      "Shape changes raise a signal. Failed or incomplete parses are held in quarantine for review.",
    action: "See drift watch",
    target: "drift",
  },
  {
    number: "04",
    icon: RotateCcw,
    title: "Prove the parser change",
    detail:
      "Old and candidate parsers replay the same corpus. Promotion waits for passing checks and a named approval.",
    action: "Open replay lab",
    target: "replay",
  },
];

const platforms = [
  {
    name: "Cribl Stream",
    role: "Collects, processes, and routes telemetry across sources and destinations.",
    fit: "LogProof centers the receipt-to-field explanation and an explicit parser promotion decision.",
    href: "https://docs.cribl.io/stream/basic-concepts/",
  },
  {
    name: "Datadog Observability Pipelines",
    role: "Processes and routes data in the customer environment, with pipeline simulation.",
    fit: "LogProof focuses on preserved raw evidence, field lineage, and the review trail for a changed parser.",
    href: "https://docs.datadoghq.com/observability_pipelines/configuration/set_up_pipelines/",
  },
  {
    name: "Splunk Edge Processor",
    role: "Filters, masks, transforms, and routes data near its source.",
    fit: "LogProof is designed around checking the meaning of the parsed event before downstream analysis.",
    href: "https://help.splunk.com/en/splunk-enterprise/process-data-at-the-edge",
  },
  {
    name: "Elastic / Logstash",
    role: "Provides configurable input, filter, and output processing pipelines.",
    fit: "LogProof makes evidence and parser-change acceptance a guided workflow in this demo.",
    href: "https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline",
  },
];

const foundations = [
  {
    name: "Vector",
    role: "Transform tests",
    href: "https://vector.dev/docs/reference/configuration/unit-tests/",
  },
  {
    name: "Fluent Bit",
    role: "Collection and parsing",
    href: "https://docs.fluentbit.io/manual/data-pipeline/parsers",
  },
  {
    name: "OpenTelemetry Collector",
    role: "Telemetry transport",
    href: "https://opentelemetry.io/docs/collector/",
  },
  {
    name: "OCSF",
    role: "Security event schema",
    href: "https://github.com/ocsf/ocsf-docs/blob/main/overview/understanding-ocsf.md",
  },
];

export function WhyLogProofSection({
  onNavigate,
}: {
  onNavigate: (section: string) => void;
}) {
  return (
    <section className="why-page" aria-labelledby="why-title">
      <div className="why-hero">
        <div className="why-hero-copy">
          <h1 id="why-title">Make every parsed field answerable.</h1>
          <p>
            LogProof exists to make the step between raw security logs and
            downstream decisions inspectable. The demo preserves the original,
            explains what the parser produced, holds uncertain records, and
            checks changes before promotion.
          </p>
          <div className="why-hero-actions">
            <Button onClick={() => onNavigate("evidence")}>
              Follow an evidence trail <ArrowRight data-icon="inline-end" />
            </Button>
            <button type="button" onClick={() => onNavigate("replay")}>
              See the parser gate <ArrowUpRight aria-hidden="true" />
            </button>
          </div>
        </div>
        <div
          className="why-flow"
          aria-label="Conceptual placement of LogProof before analysis"
        >
          <div className="why-flow-source">
            <span>RAW SOURCE</span>
            <code>rule=allow&nbsp; action=login</code>
            <code>src=203.0.113.42</code>
            <small>Original bytes retained</small>
          </div>
          <div className="why-flow-link" aria-hidden="true">
            <span />
          </div>
          <div className="why-flow-core">
            <span>LOGPROOF / ASSURANCE</span>
            <div>
              <Fingerprint aria-hidden="true" />
              <strong>source field → event field</strong>
            </div>
            <div>
              <GitCompareArrows aria-hidden="true" />
              <strong>drift → replay → approval</strong>
            </div>
          </div>
          <div className="why-flow-link" aria-hidden="true">
            <span />
          </div>
          <div className="why-flow-destination">
            <ShieldCheck aria-hidden="true" />
            <span>DOWNSTREAM ANALYSIS</span>
            <small>Intended integration point</small>
          </div>
          <p>Conceptual placement. The prototype does not export to a SIEM.</p>
        </div>
      </div>

      <div className="why-intro">
        <h2>When the source changes, the parser deserves a review.</h2>
        <p>
          Collectors, pipelines, and analytics tools already move and shape data
          well. LogProof concentrates the evidence needed to decide whether a
          parser change is safe: the original record, its field mapping, the
          changed shape, and replay results on the same samples.
        </p>
      </div>

      <div className="why-assurance" aria-label="LogProof assurance workflow">
        {assuranceSteps.map(
          ({ number, icon: Icon, title, detail, action, target }) => (
            <div className="why-assurance-step" key={number}>
              <span className="why-step-number">{number}</span>
              <Icon className="why-step-icon" aria-hidden="true" />
              <div className="why-step-body">
                <h3>{title}</h3>
                <p>{detail}</p>
              </div>
              <button type="button" onClick={() => onNavigate(target)}>
                {action}
                <ArrowUpRight aria-hidden="true" />
              </button>
            </div>
          ),
        )}
      </div>

      <div className="why-compare-head">
        <div>
          <h2>How LogProof fits with established tools</h2>
          <p>
            These platforms have substantial capabilities. The comparison
            describes product emphasis and a possible place for LogProof in the
            stack.
          </p>
        </div>
        <span>OFFICIAL PRODUCT DOCS</span>
      </div>
      <div
        className="why-compare"
        role="table"
        aria-label="LogProof and established log platforms"
      >
        <div className="why-compare-labels" role="row">
          <span role="columnheader">Platform</span>
          <span role="columnheader">Established role</span>
          <span role="columnheader">LogProof emphasis</span>
        </div>
        {platforms.map((platform) => (
          <div className="why-compare-row" role="row" key={platform.name}>
            <div role="cell">
              <a href={platform.href} target="_blank" rel="noopener noreferrer">
                {platform.name}
                <ArrowUpRight aria-hidden="true" />
              </a>
            </div>
            <p role="cell">
              <span className="why-mobile-label">Established role</span>
              {platform.role}
            </p>
            <p role="cell">
              <span className="why-mobile-label">LogProof emphasis</span>
              {platform.fit}
            </p>
          </div>
        ))}
      </div>
      <p className="why-compare-note">
        Overlap is real: Cribl offers{" "}
        <a
          href="https://docs.cribl.io/stream/pipelines/"
          target="_blank"
          rel="noopener noreferrer"
        >
          data preview
        </a>{" "}
        and{" "}
        <a
          href="https://docs.cribl.io/stream/collectors/"
          target="_blank"
          rel="noopener noreferrer"
        >
          collector replay
        </a>
        , Datadog offers pipeline simulation, and Vector supports transform
        tests. Editions and configurations vary.
      </p>

      <div className="why-foundation">
        <div>
          <h2>Reuse the plumbing. Focus the product on assurance.</h2>
          <p>
            Open collectors, transform tests, and event schemas are useful
            foundations for future interoperability. They are references for
            product direction, not integrations shipped in this demo.
          </p>
        </div>
        <div className="why-foundation-links">
          {foundations.map((item) => (
            <a
              key={item.name}
              href={item.href}
              target="_blank"
              rel="noopener noreferrer"
            >
              <strong>{item.name}</strong>
              <span>{item.role}</span>
              <ArrowUpRight aria-hidden="true" />
            </a>
          ))}
        </div>
      </div>
      <p className="why-scope-note">
        Demonstrated here: raw-byte retention and integrity check, field
        mapping, shape-drift signal, quarantine, equal-corpus replay,
        human-approved promotion, and rollback. Production connectors, full OCSF
        mapping, signed packs, air-gap distribution, and throughput claims
        remain future work.
      </p>
    </section>
  );
}
