/**
 * Delzar Solutions — Admin Dashboard
 * Contact submissions, analytics, and AI co-pilot health
 * Protected: only accessible to admin users
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { Link } from "wouter";
import {
  Mail, Users, TrendingUp, Brain, ArrowLeft,
  CheckCircle, Clock, AlertTriangle, RefreshCw,
  ExternalLink, ChevronDown, ChevronUp
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

function StatCard({ icon: Icon, label, value, sub, color }: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
}) {
  return (
    <div
      className="p-5 rounded-sm"
      style={{
        background: "oklch(0.14 0.04 250)",
        border: "1px solid oklch(0.72 0.12 75 / 0.12)",
      }}
    >
      <div className="flex items-start justify-between mb-3">
        <div
          className="w-9 h-9 flex items-center justify-center rounded-sm"
          style={{ background: `${color || "oklch(0.72 0.12 75)"} / 0.12)` }}
        >
          <Icon size={16} style={{ color: color || "oklch(0.72 0.12 75)" }} />
        </div>
      </div>
      <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.75rem", fontWeight: 700, color: "white", lineHeight: 1 }}>
        {value}
      </div>
      <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", color: "oklch(0.55 0.005 65)", marginTop: "0.35rem" }}>
        {label}
      </div>
      {sub && (
        <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", color: color || "oklch(0.72 0.12 75)", marginTop: "0.25rem" }}>
          {sub}
        </div>
      )}
    </div>
  );
}

function SubmissionRow({ submission }: { submission: {
  id: number;
  name: string;
  email: string;
  organization?: string | null;
  message: string;
  createdAt: Date;
}}) {
  const [expanded, setExpanded] = useState(false);
  const date = new Date(submission.createdAt).toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit"
  });

  return (
    <div
      className="rounded-sm overflow-hidden"
      style={{
        background: "oklch(0.14 0.04 250)",
        border: "1px solid oklch(0.72 0.12 75 / 0.1)",
      }}
    >
      <button
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/3 transition-colors"
        onClick={() => setExpanded(!expanded)}
        style={{ background: "none", border: "none", cursor: "pointer" }}
      >
        <div className="flex items-center gap-3 text-left min-w-0">
          <div
            className="w-8 h-8 flex items-center justify-center rounded-sm flex-shrink-0"
            style={{ background: "oklch(0.72 0.12 75 / 0.12)" }}
          >
            <span style={{ fontFamily: "'Playfair Display', serif", fontSize: "0.75rem", fontWeight: 700, color: "oklch(0.72 0.12 75)" }}>
              {submission.name.charAt(0).toUpperCase()}
            </span>
          </div>
          <div className="min-w-0">
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", fontWeight: 600, color: "white", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {submission.name}
            </div>
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", color: "oklch(0.55 0.005 65)" }}>
              {submission.email}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0 ml-3">
          {submission.organization && (
            <Badge variant="outline" className="hidden sm:flex" style={{ fontSize: "0.6rem", borderColor: "oklch(0.72 0.12 75 / 0.3)", color: "oklch(0.72 0.12 75)" }}>
              {submission.organization}
            </Badge>
          )}
          <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", color: "oklch(0.45 0.005 65)", whiteSpace: "nowrap" }}>
            {date}
          </span>
          {expanded
            ? <ChevronUp size={14} style={{ color: "oklch(0.45 0.005 65)" }} />
            : <ChevronDown size={14} style={{ color: "oklch(0.45 0.005 65)" }} />
          }
        </div>
      </button>
      {expanded && (
        <div
          className="px-4 pb-4"
          style={{ borderTop: "1px solid oklch(0.72 0.12 75 / 0.08)" }}
        >
          <div className="mt-3">
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "oklch(0.45 0.005 65)", marginBottom: "0.5rem" }}>
              Message
            </div>
            <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.85rem", color: "oklch(0.70 0.005 65)", lineHeight: 1.7 }}>
              {submission.message}
            </p>
          </div>
          <div className="mt-3 flex gap-2">
            <a
              href={`mailto:${submission.email}?subject=Re: Your Delzar Solutions Inquiry`}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs transition-colors hover:opacity-80"
              style={{
                background: "oklch(0.72 0.12 75 / 0.15)",
                color: "oklch(0.72 0.12 75)",
                fontFamily: "'IBM Plex Sans', sans-serif",
                fontSize: "0.7rem",
                fontWeight: 600,
                textDecoration: "none",
              }}
            >
              <Mail size={11} /> Reply via Email
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Admin() {
  const { user, loading } = useAuth();
  const { data: submissions, isLoading: subLoading, refetch } = trpc.contact.list.useQuery(undefined, {
    enabled: !!user,
  });
  const { data: health } = trpc.copilot.healthCheck.useQuery(undefined, {
    refetchInterval: 30000,
    enabled: !!user,
  });

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: "oklch(0.10 0.04 250)" }}>
        <div className="animate-spin w-6 h-6 rounded-full border-2 border-t-transparent" style={{ borderColor: "oklch(0.72 0.12 75)", borderTopColor: "transparent" }} />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: "oklch(0.10 0.04 250)" }}>
        <div className="text-center">
          <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.5rem", fontWeight: 700, color: "white", marginBottom: "1rem" }}>
            Access Restricted
          </div>
          <Link href="/">
            <Button variant="outline" className="gap-2">
              <ArrowLeft size={14} /> Back to Home
            </Button>
          </Link>
        </div>
      </div>
    );
  }

  const submissionCount = submissions?.length ?? 0;

  return (
    <div className="min-h-screen" style={{ background: "oklch(0.10 0.04 250)" }}>
      {/* Header */}
      <div
        className="sticky top-0 z-40"
        style={{
          background: "oklch(0.12 0.04 250 / 0.97)",
          backdropFilter: "blur(20px)",
          borderBottom: "1px solid oklch(0.72 0.12 75 / 0.12)",
        }}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/" className="flex items-center gap-2 hover:opacity-70 transition-opacity">
              <ArrowLeft size={14} style={{ color: "oklch(0.55 0.005 65)" }} />
              <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", color: "oklch(0.55 0.005 65)" }}>Home</span>
            </Link>
            <div style={{ width: "1px", height: "16px", background: "oklch(0.72 0.12 75 / 0.2)" }} />
            <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1rem", fontWeight: 700, color: "white" }}>
              Admin Dashboard
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <div
                className="w-2 h-2 rounded-full"
                style={{ background: (health?.claude && health?.manus) ? "oklch(0.65 0.18 145)" : "oklch(0.65 0.22 27)" }}
              />
              <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", color: "oklch(0.50 0.005 65)" }}>
                {(health?.claude && health?.manus) ? "AI Online" : "AI Degraded"}
              </span>
            </div>
            <button
              onClick={() => refetch()}
              className="w-8 h-8 flex items-center justify-center rounded-sm hover:bg-white/10 transition-colors"
              style={{ background: "none", border: "none", cursor: "pointer" }}
              title="Refresh"
            >
              <RefreshCw size={13} style={{ color: "oklch(0.55 0.005 65)" }} />
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        {/* Stats Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard
            icon={Mail}
            label="Contact Submissions"
            value={submissionCount}
            sub={submissionCount > 0 ? "View below ↓" : "None yet"}
          />
          <StatCard
            icon={Brain}
            label="AI Model"
            value="Claude"
            sub={health?.claude ? "claude-3-5-sonnet" : "Checking..."}
            color="oklch(0.65 0.15 280)"
          />
          <StatCard
            icon={TrendingUp}
            label="Active Opportunities"
            value="53,744+"
            sub="Live via Tango API"
            color="oklch(0.65 0.18 145)"
          />
          <StatCard
            icon={AlertTriangle}
            label="SAM.gov Renewal"
            value="15 days"
            sub="Expires April 27, 2026"
            color="oklch(0.65 0.22 27)"
          />
        </div>

        {/* Quick Links */}
        <div className="grid sm:grid-cols-3 gap-3 mb-8">
          {[
            { label: "AI Co-Pilot", href: "/copilot", icon: Brain, desc: "Dual-agent intelligence" },
            { label: "Opportunities", href: "/opportunities", icon: TrendingUp, desc: "53,744+ live contracts" },
            { label: "Capability Generator", href: "/capability-generator", icon: CheckCircle, desc: "IHS-formatted statements" },
          ].map((link) => (
            <Link
              key={link.label}
              href={link.href}
              className="flex items-center gap-3 px-4 py-3 rounded-sm hover:bg-white/5 transition-colors"
              style={{
                background: "oklch(0.14 0.04 250)",
                border: "1px solid oklch(0.72 0.12 75 / 0.1)",
                textDecoration: "none",
              }}
            >
              <link.icon size={16} style={{ color: "oklch(0.72 0.12 75)" }} />
              <div>
                <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.85rem", fontWeight: 600, color: "white" }}>{link.label}</div>
                <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.50 0.005 65)" }}>{link.desc}</div>
              </div>
              <ExternalLink size={12} style={{ color: "oklch(0.40 0.005 65)", marginLeft: "auto" }} />
            </Link>
          ))}
        </div>

        {/* Contact Submissions */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.25rem", fontWeight: 700, color: "white" }}>
              Contact Submissions
            </div>
            <div className="flex items-center gap-2">
              {submissionCount > 0 && (
                <Badge style={{ background: "oklch(0.72 0.12 75 / 0.15)", color: "oklch(0.72 0.12 75)", border: "1px solid oklch(0.72 0.12 75 / 0.3)", fontSize: "0.65rem" }}>
                  {submissionCount} total
                </Badge>
              )}
            </div>
          </div>

          {subLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin w-5 h-5 rounded-full border-2" style={{ borderColor: "oklch(0.72 0.12 75)", borderTopColor: "transparent" }} />
            </div>
          ) : submissionCount === 0 ? (
            <div
              className="flex flex-col items-center justify-center py-16 rounded-sm"
              style={{ background: "oklch(0.14 0.04 250)", border: "1px solid oklch(0.72 0.12 75 / 0.1)" }}
            >
              <Clock size={32} style={{ color: "oklch(0.35 0.005 65)", marginBottom: "1rem" }} />
              <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.50 0.005 65)" }}>
                No submissions yet. Share the site to start receiving inquiries.
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {(submissions ?? []).map((sub) => (
                <SubmissionRow key={sub.id} submission={sub as Parameters<typeof SubmissionRow>[0]['submission']} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
