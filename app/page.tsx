"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Image from "next/image";
import * as Tabs from "@radix-ui/react-tabs";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Clock3,
  Database,
  FileCode2,
  Fingerprint,
  GitCompareArrows,
  IndianRupee,
  Layers3,
  LockKeyhole,
  Pause,
  Play,
  RotateCcw,
  Search,
  ShieldCheck,
  ShieldX,
  TerminalSquare,
  Workflow,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { PricingSection } from "@/components/pricing-section";
import { WhyLogProofSection } from "@/components/why-logproof-section";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

type FieldMap = Record<
  string,
  {
    source_key: string;
    byte_start: number | null;
    byte_end: number | null;
    transform: string;
    confidence: number;
  }
>;
type Event = {
  event_id: string;
  receipt_id: string;
  source_id: string;
  received_at: string;
  raw_path: string;
  sha256: string;
  parser_version: string;
  raw_format: string;
  normalized: Record<string, unknown>;
  quality: {
    status: string;
    confidence: number;
    missing_required_fields: string[];
    validation_errors: string[];
    drift_detected: boolean;
  };
  field_map: FieldMap;
  shape: Record<string, string>;
  drift: string[];
};
type Overview = {
  accepted: number;
  quarantined: number;
  drift_alerts: number;
  sources: {
    id: string;
    name: string;
    format: string;
    enabled: boolean;
    rate: number;
  }[];
  registry: Record<string, string>;
  simulator_running: boolean;
};
type Evidence = {
  receipt_id: string;
  raw_path: string;
  raw_text: string;
  sha256: string;
  hash_verified: boolean;
  parser_version: string;
  field_map: FieldMap;
  retrieval_time_ms: number;
};
type Replay = {
  old_parser: string;
  candidate_parser: string;
  corpus_size: number;
  old_pass: number;
  candidate_pass: number;
  golden_passed: number;
  golden_total: number;
  regressions: number;
  old_coverage: number;
  candidate_coverage: number;
  duration_ms: number;
  diffs: {
    sample: number;
    field: string;
    old: string | null;
    candidate: string | null;
    result: string;
  }[];
  promotion_ready: boolean;
};
type Registry = {
  packs: {
    parser_id: string;
    version: string;
    description: string;
    checksum: string;
    checksum_valid: boolean;
    status: string;
  }[];
  state: Record<string, string>;
};
const API = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
const HOSTED = API.startsWith("https://");
const names: Record<string, string> = {
  paloalto_firewall: "Palo Alto-style Firewall",
  cisco_router: "Cisco-style Router",
  nginx_access: "NGINX Access",
  windows_security: "Windows Security",
  json_application: "Application JSON",
};
const tabs = [
  { id: "overview", label: "Overview", icon: Layers3 },
  { id: "why", label: "Why LogProof", icon: ShieldCheck },
  { id: "live", label: "Live ingestion", icon: Activity },
  { id: "evidence", label: "Evidence explorer", icon: Fingerprint },
  { id: "drift", label: "Drift watch", icon: GitCompareArrows },
  { id: "quarantine", label: "Quarantine", icon: ShieldX },
  { id: "replay", label: "Replay lab", icon: Workflow },
  { id: "registry", label: "Parser registry", icon: Database },
  { id: "pricing", label: "Pricing", icon: IndianRupee },
];
async function call<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (!response.ok)
    throw new Error(
      (await response.text()).slice(0, 180) ||
        `Request failed: ${response.status}`,
    );
  return response.json();
}
function Status({ value }: { value: string }) {
  return (
    <span
      className={`status status-${value === "accepted" || value === "active" ? "good" : value === "quarantined" || value === "candidate" ? "warn" : "neutral"}`}
    >
      <span className="status-dot" />
      {value}
    </span>
  );
}
function Heading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="section-heading">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        {description && <p className="section-description">{description}</p>}
      </div>
      {action}
    </div>
  );
}
function Kpi({
  icon: Icon,
  label,
  value,
  sub,
  tone,
}: {
  icon: typeof Activity;
  label: string;
  value: string | number;
  sub: string;
  tone?: string;
}) {
  return (
    <Card className={`kpi-card ${tone || ""}`}>
      <CardHeader className="kpi-head">
        <CardDescription>{label}</CardDescription>
        <Icon aria-hidden="true" />
      </CardHeader>
      <CardContent>
        <div className="kpi-value">{value}</div>
        <div className="kpi-sub">{sub}</div>
      </CardContent>
    </Card>
  );
}
function SourceControls({
  sources,
  busy,
  act,
}: {
  sources: Overview["sources"];
  busy: boolean;
  act: (name: string, path: string, body?: unknown) => Promise<void>;
}) {
  return (
    <Card className="panel source-controls">
      <CardHeader>
        <CardTitle>Source controls</CardTitle>
        <CardDescription>
          Generate, pause, and set the event rate for each demo source.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {sources.map((source) => (
          <div className="control-row" key={source.id}>
            <div>
              <strong>{source.name}</strong>
              <small>{source.format}</small>
            </div>
            <label>
              Rate{" "}
              <select
                aria-label={`${source.name} rate`}
                value={source.rate}
                disabled={busy}
                onChange={(event) =>
                  void act("Rate updated", "/api/simulator/source", {
                    source_id: source.id,
                    rate: Number(event.target.value),
                  })
                }
              >
                {[1, 2, 3, 4, 5].map((rate) => (
                  <option key={rate} value={rate}>
                    {rate}/s
                  </option>
                ))}
              </select>
            </label>
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() =>
                void act(
                  "Event emitted",
                  `/api/simulator/source/${source.id}/emit`,
                )
              }
            >
              Emit one
            </Button>
            <Button
              size="sm"
              variant="ghost"
              disabled={busy}
              onClick={() =>
                void act(
                  source.enabled ? "Source paused" : "Source resumed",
                  source.enabled
                    ? `/api/simulator/source/${source.id}/pause`
                    : "/api/simulator/source",
                  source.enabled
                    ? undefined
                    : { source_id: source.id, rate: source.rate },
                )
              }
            >
              {source.enabled ? "Pause" : "Resume"}
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

export default function Home() {
  const [tab, setTab] = useState("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [registry, setRegistry] = useState<Registry | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [field, setField] = useState<string | null>(null);
  const [replay, setReplay] = useState<Replay | null>(null);
  const [approval, setApproval] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const refresh = useCallback(async () => {
    try {
      const [nextOverview, nextEvents, nextRegistry] = await Promise.all([
        call<Overview>("/api/overview"),
        call<Event[]>("/api/events"),
        call<Registry>("/api/parser/registry"),
      ]);
      setOverview(nextOverview);
      setEvents(nextEvents);
      setRegistry(nextRegistry);
      setError("");
      setSelected((current) =>
        current && nextEvents.some((item) => item.event_id === current)
          ? current
          : nextEvents[0]?.event_id || null,
      );
    } catch {
      setError(
        HOSTED
          ? "The demo API is waking up or temporarily unavailable. This page retries automatically; the free service may take about a minute after idle."
          : "The LogProof API is unavailable. Check the backend connection, then retry.",
      );
    }
  }, []);
  useEffect(() => {
    const initial = window.setTimeout(() => void refresh(), 0);
    const id = window.setInterval(() => void refresh(), 2500);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(id);
    };
  }, [refresh]);
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [tab]);
  const selectedEvent = useMemo(
    () => events.find((item) => item.event_id === selected) || null,
    [events, selected],
  );
  useEffect(() => {
    if (!selectedEvent) return;
    void call<Evidence>(`/api/evidence/${selectedEvent.receipt_id}`)
      .then(setEvidence)
      .catch(() => setEvidence(null));
  }, [selectedEvent]);
  async function act(name: string, path: string, body?: unknown) {
    setBusy(name);
    setError("");
    setNotice("");
    try {
      await call(path, "POST", body);
      await refresh();
      setNotice(`${name} complete.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Action failed.");
    } finally {
      setBusy("");
    }
  }
  async function runReplay() {
    setBusy("Replay");
    setError("");
    try {
      setReplay(await call<Replay>("/api/replay", "POST"));
      setTab("replay");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Replay failed.");
    } finally {
      setBusy("");
    }
  }
  function showEvidence(eventId: string) {
    setSelected(eventId);
    setTab("evidence");
  }
  const driftEvents = events.filter((item) => item.drift.length > 0),
    quarantined = events.filter(
      (item) => item.quality.status === "quarantined",
    );
  const selectedField = field ? evidence?.field_map[field] : undefined,
    rawText = evidence?.raw_text || "",
    start = selectedField?.byte_start,
    end = selectedField?.byte_end;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <Image
            src="/logproof-mark.png"
            width={44}
            height={44}
            alt=""
            priority
          />
          <span>
            Log<span>Proof</span>
          </span>
        </div>
        <div className="sidebar-divider" />
        <p className="nav-caption">WORKSPACE</p>
        <nav aria-label="Primary navigation">
          <Tabs.Root value={tab} onValueChange={setTab} orientation="vertical">
            <Tabs.List className="nav-list" aria-label="LogProof sections">
              {tabs.map(({ id, label, icon: Icon }) => (
                <Tabs.Trigger key={id} value={id} className="nav-item">
                  <Icon aria-hidden="true" />
                  <span>{label}</span>
                  {id === "quarantine" &&
                    overview &&
                    overview.quarantined > 0 && (
                      <span className="nav-count">{overview.quarantined}</span>
                    )}
                </Tabs.Trigger>
              ))}
            </Tabs.List>
          </Tabs.Root>
        </nav>
        <div className="sidebar-bottom">
          <div className="local-badge">
            <span className="pulse-dot" />{" "}
            {HOSTED ? "HOSTED DEMO" : "LOCAL DEMO"} <span>•</span>{" "}
            {HOSTED ? "SYNTHETIC DATA" : "OFFLINE READY"}
          </div>
          <div className="sidebar-small">
            SIH 2026 <span>·</span> Log preprocessing
          </div>
          <div className="sidebar-small">
            Lossless in. Explainable out. Safe to change.
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            WORKSPACE <ChevronRight aria-hidden="true" />{" "}
            <strong>{tabs.find((item) => item.id === tab)?.label}</strong>
          </div>
          <div className="topbar-right">
            <span className="demo-chip">
              <span className="pulse-dot" /> SYSTEM{" "}
              {error ? "DISCONNECTED" : HOSTED ? "HOSTED" : "LOCAL"}
            </span>
            <span className="topbar-separator" />
            <span className="avatar" aria-label="Presenter mode">
              LP
            </span>
          </div>
        </header>
        <main id="main-content" className="content">
          <div className="mobile-brand">
            <Image src="/logproof-mark.png" width={32} height={32} alt="" /> Log
            <span>Proof</span>
          </div>
          <div className="mobile-nav">
            <label htmlFor="mobile-section">Section</label>
            <select
              id="mobile-section"
              value={tab}
              onChange={(event) => setTab(event.target.value)}
            >
              {tabs.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </div>
          {error && (
            <div className="message error" role="alert">
              <CircleAlert aria-hidden="true" />
              {error}
              <Button
                variant="outline"
                size="sm"
                onClick={() => void refresh()}
              >
                Retry
              </Button>
            </div>
          )}
          {notice && !error && (
            <div className="message success" role="status">
              <CheckCircle2 aria-hidden="true" />
              {notice}
            </div>
          )}
          {tab === "overview" && (
            <>
              <div className="hero">
                <div className="hero-copy">
                  <div className="hero-kicker">
                    <span className="hero-line" /> TRUST ASSURANCE CONSOLE
                  </div>
                  <h1>
                    Every log has
                    <br />
                    <em>a story to prove.</em>
                  </h1>
                  <p>
                    Watch raw evidence become structured data. Catch format
                    drift before it becomes a false assumption. Prove a parser
                    fix before it goes live.
                  </p>
                  <div className="hero-actions">
                    <Button
                      onClick={() => {
                        setTab("live");
                        void act(
                          "Baseline",
                          "/api/simulator/scenario/baseline",
                        );
                      }}
                      disabled={!!busy}
                    >
                      <Play data-icon="inline-start" /> Start guided demo
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => setTab("evidence")}
                    >
                      Explore evidence <ArrowRight data-icon="inline-end" />
                    </Button>
                  </div>
                </div>
                <div className="hero-proof">
                  <div className="proof-header">
                    <span className="proof-window-dot" />
                    <span className="proof-window-dot" />
                    <span className="proof-window-dot" />
                    <span>TRUST CHAIN / LIVE</span>
                  </div>
                  <div className="proof-flow">
                    <div>
                      <span>01</span>
                      <Fingerprint /> <strong>Preserve</strong>
                      <small>Raw bytes + SHA-256</small>
                    </div>
                    <ChevronRight />
                    <div>
                      <span>02</span>
                      <FileCode2 /> <strong>Explain</strong>
                      <small>Field-level lineage</small>
                    </div>
                    <ChevronRight />
                    <div>
                      <span>03</span>
                      <ShieldCheck /> <strong>Verify</strong>
                      <small>Replay before promotion</small>
                    </div>
                  </div>
                  <div className="proof-foot">
                    <span className="pulse-dot" /> Evidence remains linked at
                    every step
                  </div>
                </div>
              </div>
              <div className="metric-grid">
                <Kpi
                  icon={CheckCircle2}
                  label="Accepted events"
                  value={overview?.accepted ?? "—"}
                  sub="Measured in this workspace"
                />
                <Kpi
                  icon={ShieldX}
                  label="Quarantined"
                  value={overview?.quarantined ?? "—"}
                  sub="Preserved for review"
                  tone="kpi-warn"
                />
                <Kpi
                  icon={GitCompareArrows}
                  label="Drift signals"
                  value={overview?.drift_alerts ?? "—"}
                  sub="Detected shape changes"
                  tone="kpi-alert"
                />
                <Kpi
                  icon={FileCode2}
                  label="Active parser"
                  value={`v${overview?.registry.active || "—"}`}
                  sub="Palo Alto traffic parser"
                />
              </div>
              <div className="two-column">
                <Card className="panel">
                  <CardHeader>
                    <div className="panel-title-row">
                      <div>
                        <p className="eyebrow">DEMO PATH</p>
                        <CardTitle>Three proofs, one story</CardTitle>
                      </div>
                      <Badge variant="outline">2–4 MINUTES</Badge>
                    </div>
                    <CardDescription>
                      Run each step in order for a jury-ready walkthrough.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="steps">
                    <div className="step">
                      <span className="step-no">01</span>
                      <div>
                        <strong>Break the mapping</strong>
                        <p>
                          Emit a firewall event with a nested rule object. The
                          old parser quarantines it and raises drift.
                        </p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={!!busy}
                        onClick={() => {
                          void act(
                            "Format change",
                            "/api/simulator/scenario/mapping-failure",
                          );
                          setTab("drift");
                        }}
                      >
                        Trigger change <ArrowRight data-icon="inline-end" />
                      </Button>
                    </div>
                    <div className="step">
                      <span className="step-no">02</span>
                      <div>
                        <strong>Trace to raw evidence</strong>
                        <p>
                          Open the receipt, verify the bytes, and inspect how
                          each field was mapped.
                        </p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setTab("evidence")}
                      >
                        View evidence <ArrowRight data-icon="inline-end" />
                      </Button>
                    </div>
                    <div className="step">
                      <span className="step-no">03</span>
                      <div>
                        <strong>Prove the correction</strong>
                        <p>
                          Replay both versions on identical samples, then
                          approve the candidate.
                        </p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => void runReplay()}
                      >
                        Run replay <ArrowRight data-icon="inline-end" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
                <Card className="panel source-panel">
                  <CardHeader>
                    <div className="panel-title-row">
                      <div>
                        <p className="eyebrow">DEMO INPUTS</p>
                        <CardTitle>Simulated sources</CardTitle>
                      </div>
                      <span className="tiny-muted">
                        {overview?.sources.length || 5} CONNECTED
                      </span>
                    </div>
                    <CardDescription>
                      Deterministic samples generated by the demo backend.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="sources-list">
                    {overview?.sources.map((source) => (
                      <div className="source-row" key={source.id}>
                        <span className="source-icon">
                          <TerminalSquare aria-hidden="true" />
                        </span>
                        <div>
                          <strong>{source.name}</strong>
                          <small>
                            {source.format} · {source.rate}/s when running
                          </small>
                        </div>
                        <span className="source-online">
                          <span className="status-dot" />
                          {source.enabled ? "Ready" : "Paused"}
                        </span>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              </div>
            </>
          )}
          {tab === "live" && (
            <>
              <Heading
                eyebrow="01 / INGEST"
                title="Live ingestion"
                description="Every generated event gets a receipt before parsing. Select a row to inspect its evidence."
                action={
                  <div className="heading-actions">
                    <Button
                      variant="outline"
                      disabled={!!busy}
                      onClick={() =>
                        void act(
                          overview?.simulator_running
                            ? "Simulator stopped"
                            : "Simulator started",
                          `/api/simulator/${overview?.simulator_running ? "stop" : "start"}`,
                        )
                      }
                    >
                      {overview?.simulator_running ? (
                        <Pause data-icon="inline-start" />
                      ) : (
                        <Play data-icon="inline-start" />
                      )}
                      {overview?.simulator_running
                        ? "Pause stream"
                        : "Start stream"}
                    </Button>
                    <Button
                      disabled={!!busy}
                      onClick={() =>
                        void act(
                          "One event emitted",
                          "/api/simulator/source/paloalto_firewall/emit",
                        )
                      }
                    >
                      Emit firewall event
                    </Button>
                    <Button
                      variant="outline"
                      disabled={!!busy}
                      onClick={() =>
                        void act(
                          "Malformed event",
                          "/api/simulator/scenario/malformed",
                        )
                      }
                    >
                      Emit malformed event
                    </Button>
                  </div>
                }
              />
              <Card className="panel">
                <CardHeader>
                  <div className="panel-title-row">
                    <CardTitle>Recent receipts</CardTitle>
                    <span className="tiny-muted">AUTO REFRESH · 2.5S</span>
                  </div>
                  <CardDescription>
                    Actual events stored by the demo backend.
                  </CardDescription>
                </CardHeader>
                <CardContent className="table-scroll">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Time</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead>Format</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Receipt</TableHead>
                        <TableHead></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {events.map((item) => (
                        <TableRow key={item.event_id}>
                          <TableCell className="mono">
                            {item.received_at.slice(11, 19)}
                          </TableCell>
                          <TableCell className="cell-strong">
                            {names[item.source_id]}
                          </TableCell>
                          <TableCell>{item.raw_format}</TableCell>
                          <TableCell>
                            <Status value={item.quality.status} />
                          </TableCell>
                          <TableCell className="mono">
                            {item.receipt_id}
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => showEvidence(item.event_id)}
                            >
                              Inspect <ArrowRight data-icon="inline-end" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
              {overview && (
                <SourceControls
                  sources={overview.sources}
                  busy={!!busy}
                  act={act}
                />
              )}
            </>
          )}
          {tab === "evidence" && (
            <>
              <Heading
                eyebrow="02 / TRACE"
                title="Evidence explorer"
                description="Go backward from a normalized field to the exact stored raw record."
                action={
                  <Badge variant="outline">
                    <LockKeyhole /> RAW EVIDENCE VAULT
                  </Badge>
                }
              />
              <div className="evidence-layout">
                <Card className="panel event-rail">
                  <CardHeader>
                    <CardTitle>Receipts</CardTitle>
                    <CardDescription>Select a processed event.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <label className="search-box">
                      <Search aria-hidden="true" />
                      <input
                        aria-label="Search receipts"
                        placeholder="Search receipt or source"
                        value={query}
                        onChange={(event) => setQuery(event.target.value)}
                      />
                    </label>
                    <div className="receipt-list">
                      {events
                        .filter((item) =>
                          `${item.receipt_id} ${names[item.source_id]}`
                            .toLowerCase()
                            .includes(query.toLowerCase()),
                        )
                        .map((item) => (
                          <button
                            key={item.event_id}
                            className={`receipt-item ${selected === item.event_id ? "is-selected" : ""}`}
                            onClick={() => {
                              setSelected(item.event_id);
                              setField(null);
                            }}
                          >
                            <div>
                              <strong>{names[item.source_id]}</strong>
                              <Status value={item.quality.status} />
                            </div>
                            <span className="mono">{item.receipt_id}</span>
                          </button>
                        ))}
                    </div>
                  </CardContent>
                </Card>
                <div className="evidence-main">
                  {selectedEvent && evidence ? (
                    <>
                      <Card className="panel evidence-summary">
                        <CardContent>
                          <div>
                            <span className="eyebrow">RECEIPT ID</span>
                            <strong className="mono">
                              {evidence.receipt_id}
                            </strong>
                          </div>
                          <div>
                            <span className="eyebrow">PARSER VERSION</span>
                            <strong>v{evidence.parser_version}</strong>
                          </div>
                          <div>
                            <span className="eyebrow">RETRIEVAL</span>
                            <strong>
                              {evidence.retrieval_time_ms} ms{" "}
                              <span className="measured">MEASURED</span>
                            </strong>
                          </div>
                          <div>
                            <span className="eyebrow">INTEGRITY</span>
                            <strong className="integrity">
                              <CheckCircle2 />
                              {evidence.hash_verified ? "Verified" : "Mismatch"}
                            </strong>
                          </div>
                        </CardContent>
                      </Card>
                      <div className="evidence-pair">
                        <Card className="panel code-card">
                          <CardHeader>
                            <div className="panel-title-row">
                              <CardTitle>Original raw event</CardTitle>
                              <Badge variant="outline">INGESTED BYTES</Badge>
                            </div>
                            <CardDescription>
                              Stored at {evidence.raw_path}
                            </CardDescription>
                          </CardHeader>
                          <CardContent>
                            <pre className="code-block">
                              {start != null && end != null && start >= 0 ? (
                                <>
                                  {rawText.slice(0, start)}
                                  <mark>{rawText.slice(start, end)}</mark>
                                  {rawText.slice(end)}
                                </>
                              ) : (
                                rawText
                              )}
                            </pre>
                          </CardContent>
                        </Card>
                        <Card className="panel code-card">
                          <CardHeader>
                            <CardTitle>Normalized record</CardTitle>
                            <CardDescription>
                              Click a mapped field to locate its source.
                            </CardDescription>
                          </CardHeader>
                          <CardContent>
                            <div className="field-list">
                              {Object.entries(selectedEvent.field_map).map(
                                ([key]) => (
                                  <button
                                    key={key}
                                    className={`field-row ${field === key ? "is-selected" : ""}`}
                                    onClick={() => setField(key)}
                                  >
                                    <span>{key}</span>
                                    <code>
                                      {String(
                                        key
                                          .split(".")
                                          .reduce<unknown>(
                                            (value, part) =>
                                              value && typeof value === "object"
                                                ? (
                                                    value as Record<
                                                      string,
                                                      unknown
                                                    >
                                                  )[part]
                                                : null,
                                            selectedEvent.normalized,
                                          ) ?? "—",
                                      )}
                                    </code>
                                    <ChevronRight aria-hidden="true" />
                                  </button>
                                ),
                              )}
                            </div>
                            {selectedEvent.quality.missing_required_fields.map(
                              (missing) => (
                                <div className="failed-field" key={missing}>
                                  <strong>{missing}: unmapped</strong>
                                  <span>
                                    {selectedEvent.quality.validation_errors.join(
                                      " · ",
                                    ) || "Required field missing"}
                                  </span>
                                </div>
                              ),
                            )}
                            {selectedField && (
                              <div className="field-detail">
                                <strong>
                                  {field} ← {selectedField.source_key}
                                </strong>
                                <span>
                                  {selectedField.transform} · confidence{" "}
                                  {Math.round(selectedField.confidence * 100)}%
                                </span>
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      </div>
                      <Card className="panel hash-card">
                        <CardContent>
                          <Fingerprint />
                          <div>
                            <span>SHA-256 FINGERPRINT</span>
                            <code>{evidence.sha256}</code>
                          </div>
                          <span className="hash-note">
                            Verified against stored bytes
                          </span>
                        </CardContent>
                      </Card>
                    </>
                  ) : (
                    <Card className="panel empty-panel">
                      <CardContent>
                        Select or generate an event to view evidence.
                      </CardContent>
                    </Card>
                  )}
                </div>
              </div>
            </>
          )}
          {tab === "drift" && (
            <>
              <Heading
                eyebrow="03 / DETECT"
                title="Drift watch"
                description="Structural changes are compared with the approved parser baseline."
                action={
                  <Button
                    disabled={!!busy}
                    onClick={() =>
                      void act(
                        "Format change",
                        "/api/simulator/scenario/mapping-failure",
                      )
                    }
                  >
                    Trigger format change <ArrowRight data-icon="inline-end" />
                  </Button>
                }
              />
              <div className="alert-banner">
                <CircleAlert />
                <div>
                  <strong>
                    {driftEvents.length
                      ? "Format drift detected"
                      : "Baseline shape is stable"}
                  </strong>
                  <p>
                    {driftEvents.length
                      ? `${driftEvents.length} event(s) differ from the approved firewall shape. Invalid fields: ${driftEvents[0]?.quality.validation_errors.length || 0}. Unknown paths: ${driftEvents[0]?.drift.filter((change) => change.startsWith("new:")).length || 0}. Required coverage: 100% → ${Math.round((driftEvents[0]?.quality.confidence || 0) * 100)}%.`
                      : "Trigger the vendor-format change to show the detection path."}
                  </p>
                </div>
                <Badge variant="outline">
                  {driftEvents.length ? "HIGH SEVERITY" : "MONITORING"}
                </Badge>
              </div>
              <div className="two-column">
                <Card className="panel">
                  <CardHeader>
                    <CardTitle>Baseline shape</CardTitle>
                    <CardDescription>
                      Approved with parser v1.4.2
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="shape-list">
                      {[
                        "timestamp · str",
                        "action · str",
                        "src_ip · str",
                        "dst_ip · str",
                        "rule · str",
                        "severity · int",
                      ].map((item) => (
                        <div key={item}>
                          <CheckCircle2 />
                          {item}
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
                <Card className="panel">
                  <CardHeader>
                    <CardTitle>Current shape</CardTitle>
                    <CardDescription>
                      {driftEvents[0]
                        ? `Receipt ${driftEvents[0].receipt_id}`
                        : "Awaiting changed event"}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {driftEvents[0] ? (
                      <>
                        <div className="shape-list">
                          {Object.entries(driftEvents[0].shape).map(
                            ([key, value]) => (
                              <div
                                key={key}
                                className={
                                  key.startsWith("rule") ? "changed" : ""
                                }
                              >
                                {key.startsWith("rule") ? (
                                  <CircleAlert />
                                ) : (
                                  <CheckCircle2 />
                                )}
                                {key} · {value}
                              </div>
                            ),
                          )}
                        </div>
                        <div className="drift-changes">
                          {driftEvents[0].drift.map((change) => (
                            <span key={change}>{change}</span>
                          ))}
                        </div>
                      </>
                    ) : (
                      <p className="empty-copy">No drift event yet.</p>
                    )}
                  </CardContent>
                </Card>
              </div>
              <Card className="panel">
                <CardHeader>
                  <CardTitle>Detection history</CardTitle>
                </CardHeader>
                <CardContent className="table-scroll">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Receipt</TableHead>
                        <TableHead>Changed paths</TableHead>
                        <TableHead>Parser</TableHead>
                        <TableHead>Quality</TableHead>
                        <TableHead></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {driftEvents.map((item) => (
                        <TableRow key={item.event_id}>
                          <TableCell className="mono">
                            {item.receipt_id}
                          </TableCell>
                          <TableCell>{item.drift.join(", ")}</TableCell>
                          <TableCell>v{item.parser_version}</TableCell>
                          <TableCell>
                            <Status value={item.quality.status} />
                          </TableCell>
                          <TableCell>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => showEvidence(item.event_id)}
                            >
                              Inspect <ArrowRight data-icon="inline-end" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </>
          )}
          {tab === "quarantine" && (
            <>
              <Heading
                eyebrow="04 / REVIEW"
                title="Quarantine"
                description="Uncertain events remain available with a reason and a link to their original bytes."
              />
              <Card className="panel">
                <CardHeader>
                  <CardTitle>Held for review</CardTitle>
                  <CardDescription>
                    {quarantined.length} stored event(s)
                  </CardDescription>
                </CardHeader>
                <CardContent className="table-scroll">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Receipt</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead>Reason</TableHead>
                        <TableHead>Parser</TableHead>
                        <TableHead></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {quarantined.map((item) => (
                        <TableRow key={item.event_id}>
                          <TableCell className="mono">
                            {item.receipt_id}
                          </TableCell>
                          <TableCell>{names[item.source_id]}</TableCell>
                          <TableCell>
                            {[
                              ...item.quality.validation_errors,
                              ...item.quality.missing_required_fields.map(
                                (value) => `missing ${value}`,
                              ),
                            ].join(" · ")}
                          </TableCell>
                          <TableCell>v{item.parser_version}</TableCell>
                          <TableCell>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => showEvidence(item.event_id)}
                            >
                              Review raw <ArrowRight data-icon="inline-end" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  {quarantined.length === 0 && (
                    <div className="empty-copy">
                      No quarantined events. Trigger a format change to populate
                      this queue.
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          )}
          {tab === "replay" && (
            <>
              <Heading
                eyebrow="05 / PROVE"
                title="Replay lab"
                description="Run the same stored corpus through the approved and candidate parsers."
                action={
                  <Button disabled={!!busy} onClick={() => void runReplay()}>
                    <Play data-icon="inline-start" />
                    {busy === "Replay" ? "Running…" : "Run replay"}
                  </Button>
                }
              />
              <div className="replay-flow">
                <div>
                  <span>BASELINE PARSER</span>
                  <strong>v1.4.2</strong>
                  <small>Expects rule as text</small>
                </div>
                <GitCompareArrows />
                <div>
                  <span>IDENTICAL CORPUS</span>
                  <strong>{replay?.corpus_size ?? "—"} samples</strong>
                  <small>Golden + stored raw events</small>
                </div>
                <ArrowRight />
                <div>
                  <span>CANDIDATE</span>
                  <strong>v1.4.3</strong>
                  <small>Accepts rule.name object</small>
                </div>
              </div>
              {replay ? (
                <>
                  <div className="metric-grid replay-metrics">
                    <Kpi
                      icon={CheckCircle2}
                      label="Golden tests"
                      value={`${replay.golden_passed}/${replay.golden_total}`}
                      sub="Computed in this replay"
                    />
                    <Kpi
                      icon={Search}
                      label="Required coverage"
                      value={`${replay.old_coverage}% → ${replay.candidate_coverage}%`}
                      sub="Old to candidate"
                    />
                    <Kpi
                      icon={CircleAlert}
                      label="Regressions"
                      value={replay.regressions}
                      sub="Stable cases lost"
                    />
                    <Kpi
                      icon={Clock3}
                      label="Replay time"
                      value={`${replay.duration_ms} ms`}
                      sub="Measured in this workspace"
                    />
                  </div>
                  <Card className="panel">
                    <CardHeader>
                      <CardTitle>Field-level changes</CardTitle>
                      <CardDescription>
                        Only changed normalized values appear here.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="table-scroll">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Sample</TableHead>
                            <TableHead>Field</TableHead>
                            <TableHead>Old parser</TableHead>
                            <TableHead>Candidate</TableHead>
                            <TableHead>Result</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {replay.diffs.map((diff, index) => (
                            <TableRow key={index}>
                              <TableCell>#{diff.sample}</TableCell>
                              <TableCell className="mono">
                                {diff.field}
                              </TableCell>
                              <TableCell>
                                {diff.old ?? (
                                  <span className="bad-text">Missing</span>
                                )}
                              </TableCell>
                              <TableCell className="good-text">
                                {diff.candidate ?? "Missing"}
                              </TableCell>
                              <TableCell>{diff.result}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                  <Card className="panel promotion-panel">
                    <CardContent>
                      <div>
                        <span className="eyebrow">HUMAN APPROVAL GATE</span>
                        <h3>
                          {replay.promotion_ready
                            ? "Candidate passed replay gates"
                            : "Candidate is not ready"}
                        </h3>
                        <p>
                          Promotion records the approver and retains the
                          previous version as a rollback target.
                        </p>
                      </div>
                      <div className="approval-actions">
                        <label htmlFor="approver">Approver name</label>
                        <input
                          id="approver"
                          value={approval}
                          maxLength={80}
                          onChange={(event) => setApproval(event.target.value)}
                          placeholder="Your name"
                        />
                        <Button
                          disabled={!replay.promotion_ready || !!busy}
                          onClick={() =>
                            approval.trim()
                              ? void act(
                                  "Parser promotion",
                                  "/api/parser/approve",
                                  { approved_by: approval.trim() },
                                )
                              : setError(
                                  "Enter the approver name before promotion.",
                                )
                          }
                        >
                          Approve & promote{" "}
                          <ArrowRight data-icon="inline-end" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </>
              ) : (
                <Card className="panel empty-panel">
                  <CardContent>
                    <GitCompareArrows />
                    <h3>Ready to compare</h3>
                    <p>
                      Run replay to measure coverage, golden tests, field diffs,
                      and regressions in this workspace.
                    </p>
                  </CardContent>
                </Card>
              )}
            </>
          )}
          {tab === "registry" && (
            <>
              <Heading
                eyebrow="06 / GOVERN"
                title="Parser registry"
                description="Versioned parser packs with local checksums and a recorded rollback pointer."
                action={
                  <Button
                    variant="outline"
                    disabled={!registry?.state.rollback || !!busy}
                    onClick={() => void act("Rollback", "/api/parser/rollback")}
                  >
                    <RotateCcw data-icon="inline-start" /> Roll back parser
                  </Button>
                }
              />
              <div className="two-column">
                {registry?.packs.map((pack) => (
                  <Card key={pack.version} className="panel parser-card">
                    <CardHeader>
                      <div className="panel-title-row">
                        <div>
                          <p className="eyebrow">PALO ALTO TRAFFIC</p>
                          <CardTitle>Parser v{pack.version}</CardTitle>
                        </div>
                        <Status value={pack.status} />
                      </div>
                      <CardDescription>{pack.description}</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="registry-property">
                        <span>Pack checksum</span>
                        <code>{pack.checksum.slice(0, 24)}…</code>
                      </div>
                      <div className="registry-property">
                        <span>Integrity</span>
                        <strong
                          className={
                            pack.checksum_valid ? "good-text" : "bad-text"
                          }
                        >
                          {pack.checksum_valid
                            ? "Checksum verified"
                            : "Checksum mismatch"}
                        </strong>
                      </div>
                      <div className="registry-property">
                        <span>Status</span>
                        <strong>{pack.status}</strong>
                      </div>
                      <div className="registry-property">
                        <span>Approved by</span>
                        <strong>
                          {pack.status === "active"
                            ? registry.state.approved_by || "Demo baseline"
                            : "—"}
                        </strong>
                      </div>
                      <div className="registry-property">
                        <span>Rollback target</span>
                        <strong>{registry.state.rollback || "—"}</strong>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
              <div className="registry-note">
                <ShieldCheck />
                <div>
                  <strong>Promotion requires proof</strong>
                  <p>
                    Golden tests, required-field coverage, and regression checks
                    must pass before a named person approves the candidate.
                    Checksums identify local pack bytes; they are not a
                    source-authenticity claim.
                  </p>
                </div>
              </div>
            </>
          )}
          {tab === "pricing" && <PricingSection />}
          {tab === "why" && <WhyLogProofSection onNavigate={setTab} />}
        </main>
        <footer className="footer">
          <span>
            <span className="pulse-dot" />{" "}
            {HOSTED
              ? "Hosted demo · shared synthetic data resets on service restart"
              : "Local-first prototype · data stays on this laptop"}
          </span>
          <Button
            variant="ghost"
            size="sm"
            disabled={!!busy}
            onClick={() => {
              setReplay(null);
              void act("Demo reset", "/api/simulator/scenario/reset");
              setTab("overview");
            }}
          >
            Reset demo <RotateCcw data-icon="inline-end" />
          </Button>
        </footer>
      </div>
    </div>
  );
}
