"use client";

import Image from "next/image";
import { useState } from "react";
import * as Tabs from "@radix-ui/react-tabs";
import {
  ArrowRight,
  Check,
  Database,
  FileCheck2,
  LockKeyhole,
  Server,
  ShieldCheck,
  Workflow,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const plans = [
  {
    name: "Community",
    audience: "For local evaluation",
    price: "₹0",
    cadence: "free proposal",
    capacity: "Up to 10 GB/day",
    deployment: "Single node",
    features: ["Core engine", "5 starter source packs", "Community support"],
  },
  {
    name: "Team",
    audience: "For one operating team",
    price: "₹24,000",
    cadence: "/ month · billed annually",
    capacity: "Up to 100 GB/day",
    deployment: "10 source packs",
    features: [
      "Console and field provenance",
      "Parser replay workflow",
      "Email support",
    ],
  },
  {
    name: "Secure",
    audience: "For restricted environments",
    price: "₹1.25 lakh",
    cadence: "/ month · billed annually",
    capacity: "Up to 1 TB/day",
    deployment: "3-node deployment",
    features: ["Air-gap bundle flow", "RBAC and signed packs", "8×5 support"],
    featured: true,
  },
  {
    name: "Enterprise / Government",
    audience: "For multi-site operations",
    price: "From ₹30 lakh",
    cadence: "/ year · scoped quote",
    capacity: "Custom throughput",
    deployment: "Multi-site and HA scope",
    features: [
      "Custom connectors and training",
      "Deployment assurance",
      "24×7 support option",
    ],
  },
];

const valuePoints = [
  {
    icon: Database,
    title: "Preserve",
    copy: "Keep raw evidence available alongside normalized records.",
  },
  {
    icon: FileCheck2,
    title: "Explain",
    copy: "Trace fields back to source text and parser versions.",
  },
  {
    icon: Workflow,
    title: "Change safely",
    copy: "Compare parser candidates before promotion.",
  },
  {
    icon: LockKeyhole,
    title: "Run locally",
    copy: "Plan for private and restricted deployments.",
  },
];

export function PricingSection() {
  const [pricingMode, setPricingMode] = useState("licenses");
  return (
    <section className="pricing-page" aria-labelledby="pricing-title">
      <div className="pricing-hero">
        <div className="pricing-hero-copy">
          <Badge variant="outline" className="pricing-proposal-badge">
            INDIA MARKET · ILLUSTRATIVE PROPOSAL
          </Badge>
          <h1 id="pricing-title">Confidence before the SIEM.</h1>
          <p>
            A proposed way to package LogProof for teams that need dependable
            log preprocessing, parser change assurance, and control over
            deployment.
          </p>
          <div className="pricing-hero-facts">
            <span>
              <Server aria-hidden="true" /> Self-hosted by design
            </span>
            <span>
              <ShieldCheck aria-hidden="true" /> Evidence-led workflow
            </span>
          </div>
          <a className="pricing-hero-link" href="#pricing-plans">
            Explore proposed plans <ArrowRight aria-hidden="true" />
          </a>
        </div>
        <div className="pricing-art">
          <Image
            src="/pricing-architecture.webp"
            width={1672}
            height={941}
            alt="Illustration of local servers connected to a central evidence layer"
            sizes="(max-width: 820px) 100vw, 46vw"
          />
          <span>PRIVATE PIPELINE · TRACEABLE OUTPUT</span>
        </div>
      </div>

      <div className="pricing-value-grid" aria-label="Product value">
        {valuePoints.map(({ icon: Icon, title, copy }) => (
          <div className="pricing-value" key={title}>
            <span className="pricing-value-icon">
              <Icon aria-hidden="true" />
            </span>
            <div>
              <strong>{title}</strong>
              <p>{copy}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="pricing-section-heading" id="pricing-plans">
        <div>
          <span className="eyebrow">PACKAGING / 01</span>
          <h2>Choose a starting scope.</h2>
          <p>
            Capacity bands use daily raw ingest. Paid license figures assume
            annual billing.
          </p>
        </div>
        <span className="pricing-currency">ALL FIGURES IN INR</span>
      </div>

      <Tabs.Root
        className="pricing-tabs"
        value={pricingMode}
        onValueChange={setPricingMode}
      >
        <Tabs.List className="pricing-tab-list" aria-label="Pricing options">
          <Tabs.Trigger value="licenses">Annual licenses</Tabs.Trigger>
          <Tabs.Trigger value="pilot">12-week pilot</Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="licenses" className="pricing-tab-content">
          <div className="pricing-plans-grid">
            {plans.map((plan) => (
              <article
                className={`pricing-plan${plan.featured ? " is-featured" : ""}`}
                key={plan.name}
              >
                {plan.featured && (
                  <div className="pricing-plan-flag">FOR RESTRICTED TEAMS</div>
                )}
                <div className="pricing-plan-top">
                  <p className="pricing-plan-audience">{plan.audience}</p>
                  <h3>{plan.name}</h3>
                  <div className="pricing-price">{plan.price}</div>
                  <p className="pricing-cadence">{plan.cadence}</p>
                </div>
                <div className="pricing-plan-scope">
                  <span>
                    <Database aria-hidden="true" /> {plan.capacity}
                  </span>
                  <span>
                    <Server aria-hidden="true" /> {plan.deployment}
                  </span>
                </div>
                <div className="pricing-includes">
                  <span>PROPOSED SCOPE</span>
                  <ul>
                    {plan.features.map((feature) => (
                      <li key={feature}>
                        <Check aria-hidden="true" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                </div>
              </article>
            ))}
          </div>
          <div className="pricing-next-step">
            <div>
              <strong>Need real-source validation first?</strong>
              <p>
                A defined pilot can measure coverage and throughput before a
                license is scoped.
              </p>
            </div>
            <Button variant="outline" onClick={() => setPricingMode("pilot")}>
              View pilot scope <ArrowRight data-icon="inline-end" />
            </Button>
          </div>
        </Tabs.Content>

        <Tabs.Content value="pilot" className="pricing-tab-content">
          <div className="pricing-pilot">
            <div className="pricing-pilot-main">
              <span className="eyebrow">DISCOVER → VALIDATE → HAND OVER</span>
              <h3>12-week paid pilot</h3>
              <p className="pricing-pilot-price">
                ₹4.5–7.5 lakh <span>one-time proposal</span>
              </p>
              <p>
                Five real source types at one site, with a jointly agreed
                benchmark and adoption report.
              </p>
              <div className="pricing-pilot-tags">
                <span>One site</span>
                <span>Five source types</span>
                <span>12 weeks</span>
              </div>
            </div>
            <div className="pricing-pilot-deliverables">
              <span className="eyebrow">PROPOSED DELIVERABLES</span>
              <ol>
                <li>
                  <b>01</b>
                  <span>
                    <strong>Discover</strong> Confirm formats, fields,
                    deployment needs, and acceptance criteria.
                  </span>
                </li>
                <li>
                  <b>02</b>
                  <span>
                    <strong>Prove</strong> Deploy and benchmark representative
                    customer logs.
                  </span>
                </li>
                <li>
                  <b>03</b>
                  <span>
                    <strong>Transfer</strong> Hand over parser findings,
                    results, and an adoption plan.
                  </span>
                </li>
              </ol>
            </div>
          </div>
        </Tabs.Content>
      </Tabs.Root>

      <div className="pricing-model-grid">
        <div>
          <span>01 / PILOT FIRST</span>
          <strong>Prove the source fit</strong>
          <p>Start with discovery and parser validation on customer data.</p>
        </div>
        <div>
          <span>02 / ANNUAL LICENSE</span>
          <strong>Scale by throughput</strong>
          <p>Scope the self-hosted license around daily ingest and support.</p>
        </div>
        <div>
          <span>03 / OPEN CORE</span>
          <strong>Govern the changes</strong>
          <p>
            Keep a path for parser contributions; package governance and support
            commercially.
          </p>
        </div>
      </div>
      <p className="pricing-disclosure">
        Proposal figures from the supplied reference, not a live offer or
        validated market price. Capacity, HA, RBAC, signed packs, air-gap
        workflows, and support tiers are proposed capabilities, not performance
        or feature claims for this prototype. Hardware, storage, taxes, travel,
        and custom integrations would be scoped separately.
      </p>
    </section>
  );
}
