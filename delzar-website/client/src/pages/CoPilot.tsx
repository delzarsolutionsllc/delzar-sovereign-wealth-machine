/**
 * Delzar Solutions — AI Co-Pilot Dashboard
 * Manus ↔ Claude Anthropic bidirectional intelligence system
 */

import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2, Brain, Zap, CheckCircle, AlertCircle, ArrowLeftRight, FileText, TrendingUp, Shield } from "lucide-react";
import { Streamdown } from "streamdown";
import { Link } from "wouter";

// ─── Agent Status Badge ───────────────────────────────────────────────────────
function AgentBadge({ name, active }: { name: string; active: boolean }) {
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-sm"
      style={{ background: active ? "oklch(0.72 0.12 75 / 0.15)" : "oklch(1 0 0 / 0.05)", border: `1px solid ${active ? "oklch(0.72 0.12 75 / 0.4)" : "oklch(1 0 0 / 0.1)"}` }}>
      <div className={`w-2 h-2 rounded-full ${active ? "animate-pulse" : ""}`}
        style={{ background: active ? "oklch(0.72 0.12 75)" : "oklch(0.4 0 0)" }} />
      <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: active ? "oklch(0.72 0.12 75)" : "oklch(0.5 0 0)" }}>
        {name}
      </span>
    </div>
  );
}

// ─── Output Panel ─────────────────────────────────────────────────────────────
function AgentOutput({ label, content, color }: { label: string; content: string; color: string }) {
  if (!content) return null;
  return (
    <div className="rounded-sm p-4" style={{ background: "oklch(0.10 0.04 250 / 0.8)", border: `1px solid ${color}30` }}>
      <div className="flex items-center gap-2 mb-3">
        <div className="w-2 h-2 rounded-full" style={{ background: color }} />
        <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 700, letterSpacing: "0.15em", textTransform: "uppercase", color }}>
          {label}
        </span>
      </div>
      <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.80 0.005 65)", lineHeight: 1.7 }}>
        <Streamdown>{content}</Streamdown>
      </div>
    </div>
  );
}

// ─── Capability Statement Tab ─────────────────────────────────────────────────
function CapabilityTab() {
  const [form, setForm] = useState({
    companyName: "Delzar Solutions LLC",
    ownerName: "Dominique Delzar",
    naicsCodes: "541511,541512,541519",
    coreCapabilities: "Federal IT services, cloud migration, systems integration, AI-powered procurement intelligence, Buy Indian Act compliance consulting, GovCon strategy",
    targetAgency: "",
    pastPerformance: "",
  });
  const [result, setResult] = useState<{ statement: string; qaReview: string; finalStatement: string } | null>(null);

  const generate = trpc.copilot.generateCapabilityStatement.useMutation({
    onSuccess: (data) => setResult(data),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setResult(null);
    generate.mutate({
      companyName: form.companyName,
      ownerName: form.ownerName || undefined,
      naicsCodes: form.naicsCodes.split(",").map(s => s.trim()).filter(Boolean),
      coreCapabilities: form.coreCapabilities,
      targetAgency: form.targetAgency || undefined,
      pastPerformance: form.pastPerformance || undefined,
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 p-4 rounded-sm" style={{ background: "oklch(0.72 0.12 75 / 0.08)", border: "1px solid oklch(0.72 0.12 75 / 0.2)" }}>
        <ArrowLeftRight size={16} style={{ color: "oklch(0.72 0.12 75)" }} />
        <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.70 0.005 65)" }}>
          <strong style={{ color: "oklch(0.72 0.12 75)" }}>Claude writes</strong> the initial statement →{" "}
          <strong style={{ color: "oklch(0.65 0.15 200)" }}>Manus QA-reviews</strong> for accuracy →{" "}
          <strong style={{ color: "oklch(0.72 0.12 75)" }}>Claude finalizes</strong> with improvements incorporated.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid md:grid-cols-2 gap-4">
          <div>
            <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Company Name</label>
            <Input value={form.companyName} onChange={e => setForm({ ...form, companyName: e.target.value })} className="bg-transparent border-white/10 text-white" required />
          </div>
          <div>
            <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Owner Name</label>
            <Input value={form.ownerName} onChange={e => setForm({ ...form, ownerName: e.target.value })} className="bg-transparent border-white/10 text-white" />
          </div>
        </div>
        <div className="grid md:grid-cols-2 gap-4">
          <div>
            <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>NAICS Codes (comma-separated)</label>
            <Input value={form.naicsCodes} onChange={e => setForm({ ...form, naicsCodes: e.target.value })} className="bg-transparent border-white/10 text-white" required />
          </div>
          <div>
            <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Target Agency (optional)</label>
            <Input value={form.targetAgency} onChange={e => setForm({ ...form, targetAgency: e.target.value })} placeholder="e.g., IHS, BIA, HHS" className="bg-transparent border-white/10 text-white" />
          </div>
        </div>
        <div>
          <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Core Capabilities</label>
          <Textarea value={form.coreCapabilities} onChange={e => setForm({ ...form, coreCapabilities: e.target.value })} rows={3} className="bg-transparent border-white/10 text-white resize-none" required />
        </div>
        <div>
          <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Past Performance (optional)</label>
          <Textarea value={form.pastPerformance} onChange={e => setForm({ ...form, pastPerformance: e.target.value })} rows={2} className="bg-transparent border-white/10 text-white resize-none" />
        </div>
        <Button type="submit" disabled={generate.isPending} className="w-full" style={{ background: "linear-gradient(135deg, oklch(0.72 0.12 75), oklch(0.62 0.10 75))", color: "oklch(0.12 0.04 250)", fontWeight: 700, borderRadius: "2px" }}>
          {generate.isPending ? <><Loader2 size={14} className="animate-spin mr-2" />Running Dual-Agent Pipeline...</> : <><Zap size={14} className="mr-2" />Generate with Claude + Manus QA</>}
        </Button>
      </form>

      {generate.error && (
        <div className="p-4 rounded-sm flex items-center gap-3" style={{ background: "oklch(0.65 0.22 27 / 0.1)", border: "1px solid oklch(0.65 0.22 27 / 0.3)" }}>
          <AlertCircle size={16} style={{ color: "oklch(0.65 0.22 27)" }} />
          <span style={{ color: "oklch(0.65 0.22 27)", fontSize: "0.875rem" }}>{generate.error.message}</span>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <CheckCircle size={16} style={{ color: "oklch(0.72 0.12 75)" }} />
            <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", color: "oklch(0.72 0.12 75)", fontWeight: 600 }}>DUAL-AGENT PIPELINE COMPLETE</span>
          </div>
          <AgentOutput label="Claude — Initial Draft" content={result.statement} color="oklch(0.72 0.12 75)" />
          <AgentOutput label="Manus — QA Review" content={result.qaReview} color="oklch(0.65 0.15 200)" />
          <div className="rounded-sm p-4" style={{ background: "oklch(0.72 0.12 75 / 0.08)", border: "2px solid oklch(0.72 0.12 75 / 0.4)" }}>
            <div className="flex items-center gap-2 mb-3">
              <CheckCircle size={14} style={{ color: "oklch(0.72 0.12 75)" }} />
              <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 700, letterSpacing: "0.15em", textTransform: "uppercase", color: "oklch(0.72 0.12 75)" }}>FINAL STATEMENT — Claude + Manus Reviewed</span>
            </div>
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.85 0.005 65)", lineHeight: 1.8 }}>
              <Streamdown>{result.finalStatement}</Streamdown>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Dual Review Tab ──────────────────────────────────────────────────────────
function DualReviewTab() {
  const [task, setTask] = useState("");
  const [context, setContext] = useState("Delzar Solutions LLC — Cherokee Nation member-owned federal IT services company. Buy Indian Act eligible. NAICS: 541511, 541512, 541519. SAM.gov UEI: TKMXZNCBPS27. Contact: dominique@delzarsolutionsllc.com");
  const [result, setResult] = useState<{
    claudeOutput: string; manusOutput: string;
    claudeReviewOfManus: string; manusReviewOfClaude: string;
    synthesis: string; improvements: string[];
  } | null>(null);

  const review = trpc.copilot.dualReview.useMutation({ onSuccess: setResult });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 p-4 rounded-sm" style={{ background: "oklch(0.65 0.15 200 / 0.08)", border: "1px solid oklch(0.65 0.15 200 / 0.2)" }}>
        <ArrowLeftRight size={16} style={{ color: "oklch(0.65 0.15 200)" }} />
        <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.70 0.005 65)" }}>
          Both agents work on your task <strong style={{ color: "oklch(0.65 0.15 200)" }}>simultaneously</strong>, then review each other's output, then synthesize the best result. 4-step pipeline, zero blind spots.
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Task / Question</label>
          <Textarea value={task} onChange={e => setTask(e.target.value)} rows={3} placeholder="e.g., What is the best strategy to win the IHS Tahlequah IT recompete? / Review this proposal section... / What are the top 3 risks in our current pipeline?" className="bg-transparent border-white/10 text-white resize-none" />
        </div>
        <div>
          <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Context (pre-filled with Delzar profile)</label>
          <Textarea value={context} onChange={e => setContext(e.target.value)} rows={3} className="bg-transparent border-white/10 text-white resize-none" />
        </div>
        <Button onClick={() => { setResult(null); review.mutate({ task, context }); }} disabled={review.isPending || !task.trim()} className="w-full" style={{ background: "linear-gradient(135deg, oklch(0.65 0.15 200), oklch(0.55 0.12 200))", color: "white", fontWeight: 700, borderRadius: "2px" }}>
          {review.isPending ? <><Loader2 size={14} className="animate-spin mr-2" />Running 4-Step Dual-Agent Review...</> : <><Brain size={14} className="mr-2" />Launch Manus + Claude Cross-Review</>}
        </Button>
      </div>

      {result && (
        <div className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            <AgentOutput label="Claude — Initial Output" content={result.claudeOutput} color="oklch(0.72 0.12 75)" />
            <AgentOutput label="Manus — Initial Output" content={result.manusOutput} color="oklch(0.65 0.15 200)" />
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <AgentOutput label="Claude Reviews Manus" content={result.claudeReviewOfManus} color="oklch(0.72 0.12 75)" />
            <AgentOutput label="Manus Reviews Claude" content={result.manusReviewOfClaude} color="oklch(0.65 0.15 200)" />
          </div>
          <div className="rounded-sm p-4" style={{ background: "oklch(0.65 0.15 200 / 0.08)", border: "2px solid oklch(0.65 0.15 200 / 0.4)" }}>
            <div className="flex items-center gap-2 mb-3">
              <CheckCircle size={14} style={{ color: "oklch(0.65 0.15 200)" }} />
              <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 700, letterSpacing: "0.15em", textTransform: "uppercase", color: "oklch(0.65 0.15 200)" }}>SYNTHESIS — Best of Both Agents</span>
            </div>
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.85 0.005 65)", lineHeight: 1.8 }}>
              <Streamdown>{result.synthesis}</Streamdown>
            </div>
          </div>
          {result.improvements.length > 0 && (
            <div className="p-4 rounded-sm" style={{ background: "oklch(0.12 0.04 250 / 0.8)", border: "1px solid oklch(0.72 0.12 75 / 0.15)" }}>
              <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", color: "oklch(0.55 0.005 65)", marginBottom: "0.75rem" }}>NEXT ITERATION IMPROVEMENTS</p>
              <ul className="space-y-1">
                {result.improvements.map((imp, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span style={{ color: "oklch(0.72 0.12 75)", fontSize: "0.75rem", marginTop: "2px" }}>→</span>
                    <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.65 0.005 65)" }}>{imp}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Strategy Tab ─────────────────────────────────────────────────────────────
function StrategyTab() {
  const [opps, setOpps] = useState("IHS Tahlequah IT Recompete ($10M+), IHS Policy Management System ($2.5M), Buy Indian Industry Day Registration");
  const [blockers, setBlockers] = useState("SAM.gov registration expiring April 27, 2026");
  const [result, setResult] = useState<{ claudeStrategy: string; manusStrategy: string; jointPlan: string } | null>(null);

  const strategy = trpc.copilot.weeklyStrategy.useMutation({ onSuccess: setResult });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 p-4 rounded-sm" style={{ background: "oklch(0.72 0.12 75 / 0.08)", border: "1px solid oklch(0.72 0.12 75 / 0.2)" }}>
        <TrendingUp size={16} style={{ color: "oklch(0.72 0.12 75)" }} />
        <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.70 0.005 65)" }}>
          Claude generates a <strong style={{ color: "oklch(0.72 0.12 75)" }}>GovCon strategy</strong>, Manus generates an <strong style={{ color: "oklch(0.65 0.15 200)" }}>AI-powered action plan</strong>, then both are synthesized into your <strong style={{ color: "white" }}>joint 7-day battle plan</strong>.
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Current Opportunities in Pipeline</label>
          <Textarea value={opps} onChange={e => setOpps(e.target.value)} rows={3} className="bg-transparent border-white/10 text-white resize-none" />
        </div>
        <div>
          <label className="block mb-1.5" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Current Blockers</label>
          <Textarea value={blockers} onChange={e => setBlockers(e.target.value)} rows={2} className="bg-transparent border-white/10 text-white resize-none" />
        </div>
        <Button onClick={() => { setResult(null); strategy.mutate({ currentOpportunities: opps.split(",").map(s => s.trim()).filter(Boolean), blockers: blockers ? blockers.split(",").map(s => s.trim()).filter(Boolean) : undefined }); }} disabled={strategy.isPending} className="w-full" style={{ background: "linear-gradient(135deg, oklch(0.72 0.12 75), oklch(0.62 0.10 75))", color: "oklch(0.12 0.04 250)", fontWeight: 700, borderRadius: "2px" }}>
          {strategy.isPending ? <><Loader2 size={14} className="animate-spin mr-2" />Generating Joint Strategy...</> : <><TrendingUp size={14} className="mr-2" />Generate 7-Day Joint Battle Plan</>}
        </Button>
      </div>

      {result && (
        <div className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            <AgentOutput label="Claude — GovCon Strategy" content={result.claudeStrategy} color="oklch(0.72 0.12 75)" />
            <AgentOutput label="Manus — AI Action Plan" content={result.manusStrategy} color="oklch(0.65 0.15 200)" />
          </div>
          <div className="rounded-sm p-5" style={{ background: "oklch(0.72 0.12 75 / 0.08)", border: "2px solid oklch(0.72 0.12 75 / 0.4)" }}>
            <div className="flex items-center gap-2 mb-4">
              <Shield size={14} style={{ color: "oklch(0.72 0.12 75)" }} />
              <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 700, letterSpacing: "0.15em", textTransform: "uppercase", color: "oklch(0.72 0.12 75)" }}>JOINT 7-DAY BATTLE PLAN — Claude + Manus</span>
            </div>
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.85 0.005 65)", lineHeight: 1.8 }}>
              <Streamdown>{result.jointPlan}</Streamdown>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Health Check ─────────────────────────────────────────────────────────────
function HealthCheck() {
  const health = trpc.copilot.healthCheck.useQuery(undefined, { refetchInterval: 30000 });
  return (
    <div className="flex items-center gap-3 flex-wrap">
      <AgentBadge name="Claude Anthropic" active={health.data?.claude ?? false} />
      <AgentBadge name="Manus AI" active={health.data?.manus ?? false} />
      {health.isLoading && <Loader2 size={12} className="animate-spin" style={{ color: "oklch(0.55 0.005 65)" }} />}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function CoPilot() {
  return (
    <div className="min-h-screen" style={{ background: "oklch(0.10 0.04 250)" }}>
      {/* Header */}
      <div style={{ background: "oklch(0.12 0.04 250)", borderBottom: "1px solid oklch(0.72 0.12 75 / 0.15)" }}>
        <div className="container mx-auto px-6 py-5 max-w-7xl">
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <Link href="/" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.55 0.005 65)", letterSpacing: "0.05em", textDecoration: "none" }}>
                  ← DELZAR SOLUTIONS
                </Link>
              </div>
              <h1 style={{ fontFamily: "'Playfair Display', serif", fontSize: "clamp(1.5rem, 3vw, 2.25rem)", fontWeight: 700, color: "white", lineHeight: 1.2 }}>
                AI Co-Pilot Command Center
              </h1>
              <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.60 0.005 65)", marginTop: "0.5rem" }}>
                Manus ↔ Claude Anthropic — Bidirectional dual-agent intelligence system
              </p>
            </div>
            <HealthCheck />
          </div>
        </div>
      </div>

      {/* Stats Bar */}
      <div style={{ background: "oklch(0.10 0.04 250)", borderBottom: "1px solid oklch(1 0 0 / 0.06)" }}>
        <div className="container mx-auto px-6 py-3 max-w-7xl">
          <div className="flex items-center gap-6 flex-wrap">
            {[
              { label: "Agents Active", value: "2", color: "oklch(0.72 0.12 75)" },
              { label: "Pipeline Steps", value: "4", color: "oklch(0.65 0.15 200)" },
              { label: "Cross-Reviews", value: "2x per task", color: "oklch(0.72 0.12 75)" },
              { label: "Model", value: "claude-3-5-sonnet", color: "oklch(0.65 0.15 200)" },
            ].map((stat, i) => (
              <div key={i} className="flex items-center gap-2">
                <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", color: "oklch(0.45 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>{stat.label}:</span>
                <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", fontWeight: 700, color: stat.color }}>{stat.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-6 py-8 max-w-7xl">
        {/* How It Works */}
        <div className="grid md:grid-cols-4 gap-3 mb-8">
          {[
            { step: "01", title: "Both agents work", desc: "Claude and Manus tackle your task simultaneously with different perspectives", color: "oklch(0.72 0.12 75)" },
            { step: "02", title: "Cross-review", desc: "Claude reviews Manus output. Manus reviews Claude output. No blind spots.", color: "oklch(0.65 0.15 200)" },
            { step: "03", title: "Synthesis", desc: "Best elements from both outputs are merged into a superior final result", color: "oklch(0.72 0.12 75)" },
            { step: "04", title: "Improvements", desc: "System identifies 3-5 specific improvements for the next iteration", color: "oklch(0.65 0.15 200)" },
          ].map((item, i) => (
            <div key={i} className="p-4 rounded-sm" style={{ background: "oklch(0.12 0.04 250 / 0.8)", border: `1px solid ${item.color}20` }}>
              <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.5rem", fontWeight: 700, color: `${item.color}`, opacity: 0.3, lineHeight: 1, marginBottom: "0.5rem" }}>{item.step}</div>
              <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "0.9rem", fontWeight: 600, color: "white", marginBottom: "0.35rem" }}>{item.title}</div>
              <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", color: "oklch(0.55 0.005 65)", lineHeight: 1.5 }}>{item.desc}</div>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <Tabs defaultValue="capability">
          <TabsList className="mb-6" style={{ background: "oklch(0.12 0.04 250)", border: "1px solid oklch(1 0 0 / 0.1)" }}>
            <TabsTrigger value="capability" className="data-[state=active]:bg-[oklch(0.72_0.12_75/0.15)] data-[state=active]:text-[oklch(0.72_0.12_75)]">
              <FileText size={14} className="mr-2" />Capability Statement
            </TabsTrigger>
            <TabsTrigger value="review" className="data-[state=active]:bg-[oklch(0.65_0.15_200/0.15)] data-[state=active]:text-[oklch(0.65_0.15_200)]">
              <ArrowLeftRight size={14} className="mr-2" />Dual Review
            </TabsTrigger>
            <TabsTrigger value="strategy" className="data-[state=active]:bg-[oklch(0.72_0.12_75/0.15)] data-[state=active]:text-[oklch(0.72_0.12_75)]">
              <TrendingUp size={14} className="mr-2" />Weekly Strategy
            </TabsTrigger>
          </TabsList>

          <TabsContent value="capability">
            <Card style={{ background: "oklch(0.12 0.04 250 / 0.8)", border: "1px solid oklch(1 0 0 / 0.08)", borderRadius: "4px" }}>
              <CardHeader>
                <CardTitle style={{ fontFamily: "'Playfair Display', serif", color: "white", fontSize: "1.25rem" }}>
                  Capability Statement Generator
                  <Badge className="ml-3 text-xs" style={{ background: "oklch(0.72 0.12 75 / 0.15)", color: "oklch(0.72 0.12 75)", border: "1px solid oklch(0.72 0.12 75 / 0.3)" }}>Claude + Manus QA</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent><CapabilityTab /></CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="review">
            <Card style={{ background: "oklch(0.12 0.04 250 / 0.8)", border: "1px solid oklch(1 0 0 / 0.08)", borderRadius: "4px" }}>
              <CardHeader>
                <CardTitle style={{ fontFamily: "'Playfair Display', serif", color: "white", fontSize: "1.25rem" }}>
                  Dual-Agent Cross-Review
                  <Badge className="ml-3 text-xs" style={{ background: "oklch(0.65 0.15 200 / 0.15)", color: "oklch(0.65 0.15 200)", border: "1px solid oklch(0.65 0.15 200 / 0.3)" }}>4-Step Pipeline</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent><DualReviewTab /></CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="strategy">
            <Card style={{ background: "oklch(0.12 0.04 250 / 0.8)", border: "1px solid oklch(1 0 0 / 0.08)", borderRadius: "4px" }}>
              <CardHeader>
                <CardTitle style={{ fontFamily: "'Playfair Display', serif", color: "white", fontSize: "1.25rem" }}>
                  Weekly Strategy Advisor
                  <Badge className="ml-3 text-xs" style={{ background: "oklch(0.72 0.12 75 / 0.15)", color: "oklch(0.72 0.12 75)", border: "1px solid oklch(0.72 0.12 75 / 0.3)" }}>Joint Battle Plan</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent><StrategyTab /></CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
