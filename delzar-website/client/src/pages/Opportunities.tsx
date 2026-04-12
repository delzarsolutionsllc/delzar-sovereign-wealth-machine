/* ============================================================
   DELZAR SOLUTIONS — LIVE OPPORTUNITIES DASHBOARD
   Design: Sovereign Authority (Dark Editorial)
   Data: Static snapshot from Tango API (612 IHS, 128 Buy Indian Act)
   ============================================================ */

import { useState } from "react";
import { motion } from "framer-motion";
import { ChevronLeft, ExternalLink, Filter, Search, TrendingUp, Shield, AlertCircle, Clock, Brain } from "lucide-react";
import { Link } from "wouter";

const OPPORTUNITIES = [
  {
    id: 1, type: "CRITICAL", title: "IHS Tahlequah IT Recompete",
    agency: "Indian Health Service", value: "$10M+", deadline: "Q3 2026",
    naics: "541512", status: "Sources Sought Open", buyIndian: true,
    description: "Full IT systems recompete for IHS Tahlequah Area Office. Buy Indian Act preference applies. Current incumbent contract expires Q2 2026.",
    samUrl: "https://sam.gov",
  },
  {
    id: 2, type: "HIGH", title: "IHS Policy Management System Oklahoma",
    agency: "Indian Health Service", value: "$2.5M", deadline: "May 2026",
    naics: "541511", status: "Sources Sought", buyIndian: true,
    description: "Policy management software development and integration for IHS Oklahoma City Area Office. IEE preference applies.",
    samUrl: "https://sam.gov/workspace/contract/opp/b52f8fb206da41489def5ef2769af7c2/view",
  },
  {
    id: 3, type: "HIGH", title: "IHS Call Detail Recording Project",
    agency: "Indian Health Service", value: "$750K", deadline: "June 2026",
    naics: "517110", status: "Sources Sought", buyIndian: true,
    description: "Call detail recording system for IHS facilities. Buy Indian Act eligible vendors strongly encouraged to respond.",
    samUrl: "https://sam.gov/workspace/contract/opp/01d137acc6a643e394467e0937cb4050/view",
  },
  {
    id: 4, type: "HIGH", title: "Buy Indian Industry Day 2026",
    agency: "Indian Health Service / BIA", value: "Multiple Awards", deadline: "April 27–28, 2026",
    naics: "Multiple", status: "Registration Open", buyIndian: true,
    description: "4th Annual Buy Indian Industry Day. Network with IHS and BIA contracting officers. Present your capabilities directly to decision-makers.",
    samUrl: "https://www.ihs.gov/newsroom/announcements/2026-announcements/4th-annual-buy-indian-industry-day-april-27-28/",
  },
  {
    id: 5, type: "MEDIUM", title: "Cherokee Nation IT Staffing Services",
    agency: "Cherokee Nation Businesses", value: "$500K–$2M", deadline: "Rolling",
    naics: "541519", status: "Active Solicitation", buyIndian: false,
    description: "Cherokee Nation Businesses seeking IT staffing subcontractors for federal health IT programs. Tribal member-owned vendors preferred.",
    samUrl: "https://cherokeebids.org",
  },
  {
    id: 6, type: "MEDIUM", title: "IHS Electronic Health Records Modernization",
    agency: "Indian Health Service", value: "$5M+", deadline: "Q4 2026",
    naics: "541511", status: "Forecast", buyIndian: true,
    description: "Multi-year EHR modernization initiative across IHS Oklahoma area facilities. Buy Indian Act preference. Teaming opportunities available.",
    samUrl: "https://sam.gov",
  },
  {
    id: 7, type: "MEDIUM", title: "BIA Tribal Self-Governance IT Support",
    agency: "Bureau of Indian Affairs", value: "$1.2M", deadline: "Q3 2026",
    naics: "541512", status: "Forecast", buyIndian: true,
    description: "IT support services for BIA tribal self-governance program offices. Indian Economic Enterprise preference applies under Buy Indian Act.",
    samUrl: "https://sam.gov",
  },
  {
    id: 8, type: "MEDIUM", title: "Cherokee Nation TERO IT Compliance",
    agency: "Cherokee Nation", value: "$200K–$500K", deadline: "Rolling",
    naics: "541611", status: "Active Solicitation", buyIndian: false,
    description: "TERO compliance consulting and IT systems support for Cherokee Nation tribal employment rights office.",
    samUrl: "https://cherokeebids.org",
  },
];

const TYPE_CONFIG: Record<string, { color: string; bg: string; icon: React.ElementType }> = {
  CRITICAL: { color: "oklch(0.65 0.22 27)", bg: "oklch(0.65 0.22 27 / 0.1)", icon: AlertCircle },
  HIGH: { color: "oklch(0.72 0.12 75)", bg: "oklch(0.72 0.12 75 / 0.1)", icon: TrendingUp },
  MEDIUM: { color: "oklch(0.65 0.15 200)", bg: "oklch(0.65 0.15 200 / 0.1)", icon: Clock },
};

export default function Opportunities() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "BUY_INDIAN">("ALL");
  const [expanded, setExpanded] = useState<number | null>(null);

  const filtered = OPPORTUNITIES.filter(opp => {
    const matchSearch = opp.title.toLowerCase().includes(search.toLowerCase()) ||
      opp.agency.toLowerCase().includes(search.toLowerCase()) ||
      opp.naics.includes(search);
    const matchFilter = filter === "ALL" ? true :
      filter === "BUY_INDIAN" ? opp.buyIndian :
      opp.type === filter;
    return matchSearch && matchFilter;
  });

  return (
    <div className="min-h-screen" style={{ background: "oklch(0.12 0.04 250)" }}>
      {/* Top Bar */}
      <div style={{ background: "oklch(0.10 0.04 250)", borderBottom: "1px solid oklch(0.72 0.12 75 / 0.1)", padding: "1rem 0" }}>
        <div className="container mx-auto px-6 max-w-6xl flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2" style={{ color: "oklch(0.72 0.12 75)", fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", textDecoration: "none" }}>
            <ChevronLeft size={14} />
            Back to Delzar Solutions
          </Link>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full animate-pulse" style={{ background: "oklch(0.72 0.12 75)" }} />
            <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", color: "oklch(0.72 0.12 75)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
              Live Intelligence Feed · Tango API
            </span>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-6 max-w-6xl py-12">
        {/* Header */}
        <div className="mb-10">
          <div className="flex items-center gap-3 mb-3">
            <div style={{ width: "32px", height: "1px", background: "oklch(0.72 0.12 75)" }} />
            <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, letterSpacing: "0.2em", color: "oklch(0.72 0.12 75)", textTransform: "uppercase" }}>
              Federal Intelligence Dashboard
            </span>
          </div>
          <h1 style={{ fontFamily: "'Playfair Display', serif", fontSize: "clamp(2rem, 4vw, 2.75rem)", fontWeight: 700, color: "white", lineHeight: 1.2, marginBottom: "0.75rem" }}>
            Active Opportunities &<br />
            <span style={{ color: "oklch(0.72 0.12 75)", fontStyle: "italic" }}>Priority Intelligence</span>
          </h1>
          <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.9rem", color: "oklch(0.55 0.005 65)", lineHeight: 1.7 }}>
            612 IHS opportunities · 128 Buy Indian Act solicitations · Updated via Tango API
          </p>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-8">
          {[
            { label: "IHS Opportunities", value: "612", color: "oklch(0.72 0.12 75)" },
            { label: "Buy Indian Act", value: "128", color: "oklch(0.65 0.22 27)" },
            { label: "IHS Forecasts", value: "58", color: "oklch(0.65 0.15 200)" },
            { label: "Cherokee Federal", value: "2,476", color: "oklch(0.60 0.18 145)" },
          ].map((stat, i) => (
            <div key={i} style={{ background: "oklch(0.14 0.04 250)", border: "1px solid oklch(0.72 0.12 75 / 0.1)", borderRadius: "4px", padding: "1rem 1.25rem" }}>
              <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.75rem", fontWeight: 700, color: stat.color, lineHeight: 1 }}>
                {stat.value}
              </div>
              <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.50 0.005 65)", marginTop: "0.25rem", letterSpacing: "0.05em" }}>
                {stat.label}
              </div>
            </div>
          ))}
        </div>

        {/* Search + Filter */}
        <div className="flex flex-wrap gap-3 mb-6">
          <div className="flex items-center gap-2 flex-1" style={{ background: "oklch(0.14 0.04 250)", border: "1px solid oklch(0.72 0.12 75 / 0.1)", borderRadius: "2px", padding: "0.6rem 1rem", minWidth: "200px" }}>
            <Search size={14} style={{ color: "oklch(0.45 0.005 65)", flexShrink: 0 }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search by title, agency, or NAICS..."
              style={{ background: "none", border: "none", outline: "none", fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "white", width: "100%" }} />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Filter size={14} style={{ color: "oklch(0.45 0.005 65)" }} />
            {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "BUY_INDIAN"] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)}
                style={{
                  fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600,
                  letterSpacing: "0.1em", textTransform: "uppercase", padding: "0.4rem 0.75rem",
                  borderRadius: "2px", cursor: "pointer", transition: "all 0.2s",
                  background: filter === f ? "oklch(0.72 0.12 75)" : "oklch(0.14 0.04 250)",
                  color: filter === f ? "oklch(0.12 0.04 250)" : "oklch(0.50 0.005 65)",
                  border: filter === f ? "none" : "1px solid oklch(0.25 0.04 250)",
                }}>
                {f === "BUY_INDIAN" ? "Buy Indian Act" : f}
              </button>
            ))}
          </div>
        </div>

        {/* Opportunity Cards */}
        <div className="space-y-3">
          {filtered.map((opp, i) => {
            const cfg = TYPE_CONFIG[opp.type];
            const Icon = cfg.icon;
            const isOpen = expanded === opp.id;
            return (
              <motion.div key={opp.id}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: i * 0.05 }}
                style={{
                  background: "oklch(0.14 0.04 250)",
                  border: `1px solid ${isOpen ? cfg.color + "40" : "oklch(0.72 0.12 75 / 0.08)"}`,
                  borderLeft: `3px solid ${cfg.color}`,
                  borderRadius: "4px",
                  overflow: "hidden",
                  transition: "border-color 0.2s",
                }}>
                <button className="w-full text-left" onClick={() => setExpanded(isOpen ? null : opp.id)}
                  style={{ padding: "1.25rem 1.5rem", cursor: "pointer", background: "none", border: "none" }}>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-4 flex-1">
                      <div style={{ background: cfg.bg, padding: "0.5rem", borderRadius: "4px", flexShrink: 0 }}>
                        <Icon size={16} style={{ color: cfg.color }} />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.6rem", fontWeight: 700, letterSpacing: "0.15em", color: cfg.color, background: cfg.bg, padding: "0.15rem 0.5rem", borderRadius: "2px" }}>
                            {opp.type}
                          </span>
                          {opp.buyIndian && (
                            <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.6rem", fontWeight: 600, letterSpacing: "0.1em", color: "oklch(0.60 0.18 145)", background: "oklch(0.60 0.18 145 / 0.1)", padding: "0.15rem 0.5rem", borderRadius: "2px", display: "flex", alignItems: "center", gap: "3px" }}>
                              <Shield size={8} /> BUY INDIAN ACT
                            </span>
                          )}
                          <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.45 0.005 65)" }}>
                            NAICS {opp.naics}
                          </span>
                        </div>
                        <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.05rem", fontWeight: 600, color: "white", marginBottom: "0.25rem" }}>
                          {opp.title}
                        </div>
                        <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.50 0.005 65)" }}>
                          {opp.agency}
                        </div>
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.25rem", fontWeight: 700, color: cfg.color }}>
                        {opp.value}
                      </div>
                      <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.45 0.005 65)", marginBottom: "0.25rem" }}>
                        {opp.deadline}
                      </div>
                      <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: opp.status.includes("Open") || opp.status.includes("Active") ? "oklch(0.60 0.18 145)" : "oklch(0.55 0.005 65)", letterSpacing: "0.05em" }}>
                        {opp.status}
                      </div>
                    </div>
                  </div>
                </button>

                {isOpen && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}
                    style={{ padding: "0 1.5rem 1.5rem", borderTop: `1px solid ${cfg.color}20` }}>
                    <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.62 0.005 65)", lineHeight: 1.7, marginBottom: "1.25rem", marginTop: "1rem" }}>
                      {opp.description}
                    </p>
                    <div className="flex gap-3 flex-wrap">
                      <a href={opp.samUrl} target="_blank" rel="noopener noreferrer"
                        className="flex items-center gap-2"
                        style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", fontWeight: 600, color: cfg.color, letterSpacing: "0.05em", textTransform: "uppercase", textDecoration: "none" }}>
                        View on SAM.gov <ExternalLink size={11} />
                      </a>
                      <Link href="/capability-generator"
                        style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", fontWeight: 600, color: "oklch(0.55 0.005 65)", letterSpacing: "0.05em", textTransform: "uppercase", textDecoration: "none" }}>
                        Generate Capability Statement →
                      </Link>
                      <Link href="/copilot"
                        style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", fontWeight: 600, color: "oklch(0.65 0.15 200)", letterSpacing: "0.05em", textTransform: "uppercase", textDecoration: "none", display: "flex", alignItems: "center", gap: "4px" }}>
                        <Brain size={11} /> Analyze with AI →
                      </Link>
                    </div>
                  </motion.div>
                )}
              </motion.div>
            );
          })}
        </div>

        {filtered.length === 0 && (
          <div className="text-center py-16">
            <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.25rem", color: "oklch(0.45 0.005 65)", marginBottom: "0.5rem" }}>
              No opportunities match your search
            </div>
            <button onClick={() => { setSearch(""); setFilter("ALL"); }}
              style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.72 0.12 75)", background: "none", border: "none", cursor: "pointer" }}>
              Clear filters
            </button>
          </div>
        )}

        {/* CTA */}
        <div style={{ marginTop: "3rem", background: "oklch(0.14 0.04 250)", border: "1px solid oklch(0.72 0.12 75 / 0.15)", borderRadius: "4px", padding: "2rem", textAlign: "center" }}>
          <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.5rem", fontWeight: 700, color: "white", marginBottom: "0.75rem" }}>
            Get the Full Intelligence Feed
          </div>
          <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.55 0.005 65)", marginBottom: "1.5rem", lineHeight: 1.7, maxWidth: "480px", margin: "0 auto 1.5rem" }}>
            This dashboard shows 8 curated opportunities. Subscribe to the Delzar Intelligence Platform for access to all 612 IHS opportunities, 128 Buy Indian Act solicitations, and real-time alerts.
          </p>
          <Link href="/#contact" style={{ textDecoration: "none" }}>
            <span className="btn-gold inline-flex items-center gap-2" style={{ borderRadius: "2px" }}>
              Subscribe for $99/month
            </span>
          </Link>
        </div>
      </div>
    </div>
  );
}
