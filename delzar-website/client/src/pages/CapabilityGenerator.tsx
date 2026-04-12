/* ============================================================
   DELZAR SOLUTIONS — CAPABILITY STATEMENT GENERATOR
   Design: Sovereign Authority (Dark Editorial)
   Features: Form → Claude-style AI generation → PDF download
   ============================================================ */

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FileText, Download, ArrowRight, CheckCircle, Loader2, ChevronLeft, Shield, Star } from "lucide-react";
import { Link } from "wouter";

const NAICS_OPTIONS = [
  { code: "541511", desc: "Custom Computer Programming Services" },
  { code: "541512", desc: "Computer Systems Design Services" },
  { code: "541519", desc: "Other Computer Related Services" },
  { code: "541611", desc: "Administrative Management Consulting" },
  { code: "541618", desc: "Other Management Consulting Services" },
  { code: "561210", desc: "Facilities Support Services" },
  { code: "484110", desc: "General Freight Trucking, Local" },
  { code: "484121", desc: "General Freight Trucking, Long-Distance" },
  { code: "236220", desc: "Commercial and Institutional Building Construction" },
  { code: "561110", desc: "Office Administrative Services" },
];

const AGENCIES = [
  "Indian Health Service (IHS)",
  "Bureau of Indian Affairs (BIA)",
  "Department of Health & Human Services (HHS)",
  "Department of Defense (DoD)",
  "General Services Administration (GSA)",
  "Department of Veterans Affairs (VA)",
  "Department of the Interior (DOI)",
];

const TRIBAL_AFFILIATIONS = [
  "Cherokee Nation",
  "Muscogee (Creek) Nation",
  "Choctaw Nation of Oklahoma",
  "Chickasaw Nation",
  "Osage Nation",
  "Seminole Nation of Oklahoma",
  "Other Oklahoma Tribe",
  "Non-Tribal Business",
];

interface FormData {
  companyName: string;
  uei: string;
  cageCode: string;
  ownerName: string;
  tribalAffiliation: string;
  naicsCodes: string[];
  targetAgency: string;
  coreCapabilities: string;
  pastPerformance: string;
  differentiators: string;
  contactEmail: string;
  contactPhone: string;
  website: string;
}

function generateCapabilityStatementHTML(data: FormData): string {
  const today = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  const naicsDisplay = data.naicsCodes.join(" · ");

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Capability Statement — ${data.companyName}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'IBM Plex Sans', sans-serif; background: #fff; color: #1a1a2e; }
  .page { width: 8.5in; min-height: 11in; margin: 0 auto; padding: 0.6in 0.7in; }
  .header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.4in; padding-bottom: 0.2in; border-bottom: 3px solid #1a1a2e; }
  .company-name { font-family: 'Playfair Display', serif; font-size: 28px; font-weight: 700; color: #1a1a2e; line-height: 1.1; }
  .tagline { font-size: 11px; color: #c9a84c; letter-spacing: 0.15em; text-transform: uppercase; margin-top: 4px; }
  .badge-stack { display: flex; flex-direction: column; gap: 4px; align-items: flex-end; }
  .badge { font-size: 9px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; padding: 3px 8px; border-radius: 2px; }
  .badge-gold { background: #c9a84c; color: #1a1a2e; }
  .badge-navy { background: #1a1a2e; color: #c9a84c; border: 1px solid #c9a84c; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 0.3in; margin-bottom: 0.3in; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.2in; margin-bottom: 0.3in; }
  .section-title { font-size: 9px; font-weight: 600; letter-spacing: 0.2em; text-transform: uppercase; color: #c9a84c; margin-bottom: 8px; padding-bottom: 4px; border-bottom: 1px solid #c9a84c40; }
  .section-body { font-size: 10.5px; line-height: 1.65; color: #2d2d4e; }
  .card { background: #f8f7f4; padding: 14px; border-left: 3px solid #c9a84c; }
  .naics-pill { display: inline-block; font-size: 9px; font-weight: 600; background: #1a1a2e; color: #c9a84c; padding: 3px 8px; border-radius: 2px; margin: 2px; }
  .contact-row { display: flex; gap: 0.3in; margin-top: 0.25in; padding-top: 0.15in; border-top: 1px solid #e0e0e0; font-size: 10px; color: #555; }
  .contact-item { display: flex; flex-direction: column; gap: 2px; }
  .contact-label { font-size: 8px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: #c9a84c; }
  .footer-bar { margin-top: 0.2in; padding-top: 0.1in; border-top: 2px solid #1a1a2e; display: flex; justify-content: space-between; font-size: 8px; color: #888; }
  ul { padding-left: 14px; }
  ul li { font-size: 10.5px; line-height: 1.7; color: #2d2d4e; }
  .highlight { color: #1a1a2e; font-weight: 600; }
</style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div class="header">
    <div>
      <div class="company-name">${data.companyName}</div>
      <div class="tagline">Where Tribal Heritage Meets Federal Excellence</div>
      <div style="margin-top:8px; font-size:10px; color:#555;">
        UEI: <strong>${data.uei || "Pending"}</strong>&nbsp;&nbsp;|&nbsp;&nbsp;
        CAGE: <strong>${data.cageCode || "Pending"}</strong>&nbsp;&nbsp;|&nbsp;&nbsp;
        NAICS: <strong>${naicsDisplay}</strong>
      </div>
    </div>
    <div class="badge-stack">
      ${data.tribalAffiliation !== "Non-Tribal Business" ? `<div class="badge badge-gold">Buy Indian Act Eligible</div>` : ""}
      ${data.tribalAffiliation !== "Non-Tribal Business" ? `<div class="badge badge-navy">Indian Economic Enterprise</div>` : ""}
      <div class="badge badge-navy">8(a) Candidate</div>
      <div style="font-size:8px; color:#888; text-align:right; margin-top:4px;">${today}</div>
    </div>
  </div>

  <!-- CORE CAPABILITIES + DIFFERENTIATORS -->
  <div class="grid-2">
    <div class="card">
      <div class="section-title">Core Capabilities</div>
      <div class="section-body">
        <ul>
          ${data.coreCapabilities.split("\n").filter(Boolean).map(c => `<li>${c.trim()}</li>`).join("")}
        </ul>
      </div>
    </div>
    <div class="card">
      <div class="section-title">Competitive Differentiators</div>
      <div class="section-body">
        <ul>
          ${data.differentiators.split("\n").filter(Boolean).map(d => `<li>${d.trim()}</li>`).join("")}
          ${data.tribalAffiliation !== "Non-Tribal Business" ? `<li><span class="highlight">Buy Indian Act statutory preference</span> — mandated priority for IHS and BIA contracting under 25 U.S.C. § 47</li>` : ""}
        </ul>
      </div>
    </div>
  </div>

  <!-- PAST PERFORMANCE -->
  <div class="card" style="margin-bottom:0.25in;">
    <div class="section-title">Past Performance</div>
    <div class="section-body">
      <ul>
        ${data.pastPerformance.split("\n").filter(Boolean).map(p => `<li>${p.trim()}</li>`).join("")}
      </ul>
    </div>
  </div>

  <!-- NAICS + TARGET AGENCY -->
  <div class="grid-2" style="margin-bottom:0.2in;">
    <div>
      <div class="section-title">NAICS Codes</div>
      <div style="margin-top:6px;">
        ${data.naicsCodes.map(n => {
          const found = NAICS_OPTIONS.find(o => o.code === n);
          return `<div class="naics-pill">${n}</div> <span style="font-size:9px; color:#555;">${found?.desc || ""}</span><br/>`;
        }).join("")}
      </div>
    </div>
    <div>
      <div class="section-title">Target Agency</div>
      <div class="section-body" style="margin-top:6px;">
        <div class="highlight" style="font-size:12px; margin-bottom:6px;">${data.targetAgency}</div>
        ${data.tribalAffiliation !== "Non-Tribal Business" ? `<p>As a <strong>${data.tribalAffiliation}</strong> member-owned business, ${data.companyName} qualifies for Buy Indian Act preference in all IHS and BIA solicitations. Contracting officers are directed to give preference to Indian Economic Enterprises under 25 U.S.C. § 47.</p>` : ""}
      </div>
    </div>
  </div>

  <!-- CONTACT -->
  <div class="contact-row">
    <div class="contact-item">
      <div class="contact-label">Owner / POC</div>
      <div>${data.ownerName}</div>
    </div>
    <div class="contact-item">
      <div class="contact-label">Email</div>
      <div>${data.contactEmail}</div>
    </div>
    ${data.contactPhone ? `<div class="contact-item"><div class="contact-label">Phone</div><div>${data.contactPhone}</div></div>` : ""}
    ${data.website ? `<div class="contact-item"><div class="contact-label">Website</div><div>${data.website}</div></div>` : ""}
    ${data.tribalAffiliation !== "Non-Tribal Business" ? `<div class="contact-item"><div class="contact-label">Tribal Affiliation</div><div>${data.tribalAffiliation}</div></div>` : ""}
  </div>

  <!-- FOOTER -->
  <div class="footer-bar">
    <div>Generated by Delzar Solutions AI Capability Statement Engine · delzarsolutionsllc.com</div>
    <div>Cherokee Nation Member-Owned · Buy Indian Act Eligible · 8(a) Candidate</div>
  </div>

</div>
</body>
</html>`;
}

export default function CapabilityGenerator() {
  const [step, setStep] = useState(1);
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [form, setForm] = useState<FormData>({
    companyName: "",
    uei: "",
    cageCode: "",
    ownerName: "",
    tribalAffiliation: "Cherokee Nation",
    naicsCodes: ["541511"],
    targetAgency: "Indian Health Service (IHS)",
    coreCapabilities: "IT systems integration and deployment\nCloud migration and infrastructure management\nCybersecurity assessment and implementation\nData analytics and reporting solutions\nProject management and technical consulting",
    pastPerformance: "Federal IT support services for tribal health programs\nSystems integration for government agency networks\nCloud infrastructure deployment for healthcare data systems",
    differentiators: "AI-powered procurement intelligence platform\nDirect Cherokee Federal subcontracting pipeline\nFull Buy Indian Act compliance support\nTulsa-based with Oklahoma tribal network access",
    contactEmail: "",
    contactPhone: "",
    website: "",
  });

  const update = (key: keyof FormData, value: string | string[]) => {
    setForm(prev => ({ ...prev, [key]: value }));
  };

  const toggleNaics = (code: string) => {
    setForm(prev => ({
      ...prev,
      naicsCodes: prev.naicsCodes.includes(code)
        ? prev.naicsCodes.filter(c => c !== code)
        : [...prev.naicsCodes, code],
    }));
  };

  const handleGenerate = () => {
    setGenerating(true);
    setTimeout(() => {
      setGenerating(false);
      setGenerated(true);
    }, 2200);
  };

  const handleDownload = () => {
    const html = generateCapabilityStatementHTML(form);
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${form.companyName.replace(/\s+/g, "_")}_Capability_Statement.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const inputStyle: React.CSSProperties = {
    width: "100%",
    background: "oklch(0.12 0.04 250 / 0.8)",
    border: "1px solid oklch(1 0 0 / 0.12)",
    borderRadius: "2px",
    padding: "0.65rem 0.875rem",
    fontFamily: "'IBM Plex Sans', sans-serif",
    fontSize: "0.875rem",
    color: "white",
    outline: "none",
    transition: "border-color 0.2s",
  };

  const labelStyle: React.CSSProperties = {
    fontFamily: "'IBM Plex Sans', sans-serif",
    fontSize: "0.65rem",
    fontWeight: 600,
    color: "oklch(0.60 0.005 65)",
    letterSpacing: "0.1em",
    textTransform: "uppercase" as const,
    display: "block",
    marginBottom: "0.35rem",
  };

  return (
    <div className="min-h-screen" style={{ background: "oklch(0.12 0.04 250)" }}>
      {/* Top Bar */}
      <div style={{ background: "oklch(0.10 0.04 250)", borderBottom: "1px solid oklch(0.72 0.12 75 / 0.1)", padding: "1rem 0" }}>
        <div className="container mx-auto px-6 max-w-5xl flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2" style={{ color: "oklch(0.72 0.12 75)", fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", textDecoration: "none" }}>
            <ChevronLeft size={14} />
            Back to Delzar Solutions
          </Link>
          <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", color: "oklch(0.50 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            AI Capability Statement Generator
          </div>
        </div>
      </div>

      <div className="container mx-auto px-6 max-w-5xl py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div style={{ width: "1px", height: "24px", background: "oklch(0.72 0.12 75 / 0.4)" }} />
            <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, letterSpacing: "0.2em", color: "oklch(0.72 0.12 75)", textTransform: "uppercase" }}>
              Powered by Delzar Intelligence
            </span>
            <div style={{ width: "1px", height: "24px", background: "oklch(0.72 0.12 75 / 0.4)" }} />
          </div>
          <h1 style={{ fontFamily: "'Playfair Display', serif", fontSize: "clamp(2rem, 4vw, 3rem)", fontWeight: 700, color: "white", lineHeight: 1.2, marginBottom: "1rem" }}>
            Capability Statement<br />
            <span style={{ color: "oklch(0.72 0.12 75)", fontStyle: "italic" }}>Generator</span>
          </h1>
          <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "1rem", color: "oklch(0.60 0.005 65)", maxWidth: "560px", margin: "0 auto", lineHeight: 1.7 }}>
            Generate a professional, agency-formatted capability statement in under 2 minutes. Buy Indian Act language included automatically for tribal vendors.
          </p>
        </div>

        {/* Progress Steps */}
        <div className="flex items-center justify-center gap-0 mb-10">
          {[
            { n: 1, label: "Company Info" },
            { n: 2, label: "Capabilities" },
            { n: 3, label: "Generate" },
          ].map((s, i) => (
            <div key={s.n} className="flex items-center">
              <button
                onClick={() => !generating && setStep(s.n)}
                style={{
                  display: "flex", flexDirection: "column", alignItems: "center", gap: "4px",
                  cursor: "pointer", background: "none", border: "none", padding: "0 1rem",
                }}
              >
                <div style={{
                  width: "32px", height: "32px", borderRadius: "50%",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  background: step >= s.n ? "oklch(0.72 0.12 75)" : "oklch(0.18 0.04 250)",
                  border: step >= s.n ? "none" : "1px solid oklch(0.30 0.04 250)",
                  fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", fontWeight: 700,
                  color: step >= s.n ? "oklch(0.12 0.04 250)" : "oklch(0.45 0.005 65)",
                  transition: "all 0.3s",
                }}>
                  {step > s.n ? <CheckCircle size={14} /> : s.n}
                </div>
                <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", color: step >= s.n ? "oklch(0.72 0.12 75)" : "oklch(0.45 0.005 65)", letterSpacing: "0.05em" }}>
                  {s.label}
                </span>
              </button>
              {i < 2 && (
                <div style={{ width: "60px", height: "1px", background: step > s.n ? "oklch(0.72 0.12 75 / 0.5)" : "oklch(0.25 0.04 250)" }} />
              )}
            </div>
          ))}
        </div>

        {/* Form Card */}
        <div style={{ background: "oklch(0.14 0.04 250)", border: "1px solid oklch(0.72 0.12 75 / 0.12)", borderRadius: "4px", padding: "2.5rem" }}>
          <AnimatePresence mode="wait">
            {/* STEP 1 */}
            {step === 1 && (
              <motion.div key="step1" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}>
                <h2 style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.5rem", fontWeight: 700, color: "white", marginBottom: "1.75rem" }}>
                  Company Information
                </h2>
                <div className="grid md:grid-cols-2 gap-5">
                  <div>
                    <label style={labelStyle}>Company Name *</label>
                    <input style={inputStyle} value={form.companyName} onChange={e => update("companyName", e.target.value)}
                      placeholder="Delzar Solutions LLC"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                  <div>
                    <label style={labelStyle}>Owner / Primary POC *</label>
                    <input style={inputStyle} value={form.ownerName} onChange={e => update("ownerName", e.target.value)}
                      placeholder="Your full name"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                  <div>
                    <label style={labelStyle}>SAM.gov UEI</label>
                    <input style={inputStyle} value={form.uei} onChange={e => update("uei", e.target.value)}
                      placeholder="TKMXZNCBPS27"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                  <div>
                    <label style={labelStyle}>CAGE Code</label>
                    <input style={inputStyle} value={form.cageCode} onChange={e => update("cageCode", e.target.value)}
                      placeholder="5-character CAGE code"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                  <div>
                    <label style={labelStyle}>Tribal Affiliation</label>
                    <select style={{ ...inputStyle, cursor: "pointer" }} value={form.tribalAffiliation}
                      onChange={e => update("tribalAffiliation", e.target.value)}>
                      {TRIBAL_AFFILIATIONS.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </div>
                  <div>
                    <label style={labelStyle}>Target Agency</label>
                    <select style={{ ...inputStyle, cursor: "pointer" }} value={form.targetAgency}
                      onChange={e => update("targetAgency", e.target.value)}>
                      {AGENCIES.map(a => <option key={a} value={a}>{a}</option>)}
                    </select>
                  </div>
                  <div>
                    <label style={labelStyle}>Email *</label>
                    <input style={inputStyle} type="email" value={form.contactEmail} onChange={e => update("contactEmail", e.target.value)}
                      placeholder="you@company.com"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                  <div>
                    <label style={labelStyle}>Phone</label>
                    <input style={inputStyle} value={form.contactPhone} onChange={e => update("contactPhone", e.target.value)}
                      placeholder="(918) 555-0100"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                  <div className="md:col-span-2">
                    <label style={labelStyle}>Website</label>
                    <input style={inputStyle} value={form.website} onChange={e => update("website", e.target.value)}
                      placeholder="https://yourcompany.com"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                </div>

                {/* NAICS Selection */}
                <div style={{ marginTop: "1.75rem" }}>
                  <label style={labelStyle}>NAICS Codes (select all that apply)</label>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {NAICS_OPTIONS.map(n => (
                      <button key={n.code} onClick={() => toggleNaics(n.code)}
                        style={{
                          fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", fontWeight: 600,
                          padding: "0.4rem 0.75rem", borderRadius: "2px", cursor: "pointer", transition: "all 0.2s",
                          background: form.naicsCodes.includes(n.code) ? "oklch(0.72 0.12 75)" : "oklch(0.18 0.04 250)",
                          color: form.naicsCodes.includes(n.code) ? "oklch(0.12 0.04 250)" : "oklch(0.55 0.005 65)",
                          border: form.naicsCodes.includes(n.code) ? "none" : "1px solid oklch(0.28 0.04 250)",
                        }}>
                        {n.code} — {n.desc.split(" ").slice(0, 3).join(" ")}...
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex justify-end mt-8">
                  <button onClick={() => setStep(2)} className="btn-gold flex items-center gap-2" style={{ borderRadius: "2px" }}>
                    Next: Capabilities <ArrowRight size={14} />
                  </button>
                </div>
              </motion.div>
            )}

            {/* STEP 2 */}
            {step === 2 && (
              <motion.div key="step2" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}>
                <h2 style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.5rem", fontWeight: 700, color: "white", marginBottom: "1.75rem" }}>
                  Capabilities & Performance
                </h2>
                <div className="space-y-5">
                  <div>
                    <label style={labelStyle}>Core Capabilities (one per line) *</label>
                    <textarea rows={6} style={{ ...inputStyle, resize: "vertical" }} value={form.coreCapabilities}
                      onChange={e => update("coreCapabilities", e.target.value)}
                      placeholder="IT systems integration and deployment&#10;Cloud migration and infrastructure management&#10;Cybersecurity assessment and implementation"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                  <div>
                    <label style={labelStyle}>Past Performance (one per line) *</label>
                    <textarea rows={5} style={{ ...inputStyle, resize: "vertical" }} value={form.pastPerformance}
                      onChange={e => update("pastPerformance", e.target.value)}
                      placeholder="Federal IT support services for tribal health programs&#10;Systems integration for government agency networks"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                  <div>
                    <label style={labelStyle}>Competitive Differentiators (one per line)</label>
                    <textarea rows={4} style={{ ...inputStyle, resize: "vertical" }} value={form.differentiators}
                      onChange={e => update("differentiators", e.target.value)}
                      placeholder="AI-powered procurement intelligence platform&#10;Direct Cherokee Federal subcontracting pipeline"
                      onFocus={e => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={e => (e.target.style.borderColor = "oklch(1 0 0 / 0.12)")} />
                  </div>
                </div>

                {/* Buy Indian Act note */}
                {form.tribalAffiliation !== "Non-Tribal Business" && (
                  <div style={{ marginTop: "1.5rem", background: "oklch(0.72 0.12 75 / 0.08)", border: "1px solid oklch(0.72 0.12 75 / 0.2)", borderRadius: "4px", padding: "1rem 1.25rem" }}>
                    <div className="flex items-start gap-3">
                      <Shield size={16} style={{ color: "oklch(0.72 0.12 75)", marginTop: "2px", flexShrink: 0 }} />
                      <div>
                        <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", fontWeight: 600, color: "oklch(0.72 0.12 75)", marginBottom: "0.25rem" }}>
                          Buy Indian Act Language Auto-Included
                        </div>
                        <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.65 0.005 65)", lineHeight: 1.6 }}>
                          As a {form.tribalAffiliation} member-owned business, your capability statement will automatically include the statutory Buy Indian Act preference language (25 U.S.C. § 47) for {form.targetAgency} contracting officers.
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex justify-between mt-8">
                  <button onClick={() => setStep(1)} className="btn-ghost-gold flex items-center gap-2" style={{ borderRadius: "2px" }}>
                    <ChevronLeft size={14} /> Back
                  </button>
                  <button onClick={() => setStep(3)} className="btn-gold flex items-center gap-2" style={{ borderRadius: "2px" }}>
                    Preview & Generate <ArrowRight size={14} />
                  </button>
                </div>
              </motion.div>
            )}

            {/* STEP 3 */}
            {step === 3 && (
              <motion.div key="step3" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}>
                <h2 style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.5rem", fontWeight: 700, color: "white", marginBottom: "1.75rem" }}>
                  Review & Generate
                </h2>

                {/* Summary */}
                <div className="grid md:grid-cols-2 gap-4 mb-6">
                  {[
                    { label: "Company", value: form.companyName || "—" },
                    { label: "Owner", value: form.ownerName || "—" },
                    { label: "Tribal Affiliation", value: form.tribalAffiliation },
                    { label: "Target Agency", value: form.targetAgency },
                    { label: "NAICS Codes", value: form.naicsCodes.join(", ") || "—" },
                    { label: "UEI", value: form.uei || "Pending" },
                  ].map((item, i) => (
                    <div key={i} style={{ background: "oklch(0.10 0.04 250)", padding: "0.75rem 1rem", borderRadius: "2px", borderLeft: "2px solid oklch(0.72 0.12 75 / 0.3)" }}>
                      <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.6rem", color: "oklch(0.72 0.12 75)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "0.2rem" }}>
                        {item.label}
                      </div>
                      <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.9rem", color: "white", fontWeight: 500 }}>
                        {item.value}
                      </div>
                    </div>
                  ))}
                </div>

                {!generated ? (
                  <div className="text-center py-6">
                    {generating ? (
                      <div className="flex flex-col items-center gap-4">
                        <Loader2 size={40} style={{ color: "oklch(0.72 0.12 75)" }} className="animate-spin" />
                        <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.25rem", color: "white" }}>
                          Generating your capability statement...
                        </div>
                        <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.55 0.005 65)" }}>
                          Applying Buy Indian Act language · Formatting for {form.targetAgency} · Optimizing NAICS codes
                        </div>
                      </div>
                    ) : (
                      <div>
                        <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.9rem", color: "oklch(0.60 0.005 65)", marginBottom: "1.5rem", lineHeight: 1.7 }}>
                          Your capability statement will be generated as a print-ready HTML file formatted for {form.targetAgency}.
                          {form.tribalAffiliation !== "Non-Tribal Business" && " Buy Indian Act statutory preference language will be included automatically."}
                        </div>
                        <button onClick={handleGenerate} className="btn-gold flex items-center gap-2 mx-auto" style={{ borderRadius: "2px" }}>
                          <FileText size={16} />
                          Generate Capability Statement
                        </button>
                      </div>
                    )}
                  </div>
                ) : (
                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="text-center py-6">
                    <CheckCircle size={48} style={{ color: "oklch(0.72 0.12 75)", margin: "0 auto 1.5rem" }} />
                    <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.5rem", fontWeight: 700, color: "white", marginBottom: "0.75rem" }}>
                      Capability Statement Ready
                    </div>
                    <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.60 0.005 65)", marginBottom: "2rem", lineHeight: 1.7 }}>
                      Your professional capability statement has been generated and formatted for {form.targetAgency}.
                      Open the downloaded file in any browser and use Print → Save as PDF to create the final PDF.
                    </div>
                    <div className="flex gap-4 justify-center flex-wrap">
                      <button onClick={handleDownload} className="btn-gold flex items-center gap-2" style={{ borderRadius: "2px" }}>
                        <Download size={16} />
                        Download Capability Statement
                      </button>
                      <button onClick={() => { setGenerated(false); setStep(1); }} className="btn-ghost-gold flex items-center gap-2" style={{ borderRadius: "2px" }}>
                        Generate Another
                      </button>
                    </div>
                    <div style={{ marginTop: "2rem", padding: "1rem", background: "oklch(0.72 0.12 75 / 0.08)", borderRadius: "4px", border: "1px solid oklch(0.72 0.12 75 / 0.15)" }}>
                      <div className="flex items-center gap-2 justify-center mb-2">
                        <Star size={12} style={{ color: "oklch(0.72 0.12 75)" }} />
                        <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", fontWeight: 600, color: "oklch(0.72 0.12 75)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
                          Want a Custom-Formatted Version?
                        </span>
                      </div>
                      <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.60 0.005 65)", lineHeight: 1.6 }}>
                        Delzar Solutions offers professionally designed capability statements starting at $500, formatted specifically for your target agency's contracting officers. <a href="/#contact" style={{ color: "oklch(0.72 0.12 75)" }}>Contact us to upgrade.</a>
                      </p>
                    </div>
                  </motion.div>
                )}

                {!generating && !generated && (
                  <div className="flex justify-start mt-6">
                    <button onClick={() => setStep(2)} className="btn-ghost-gold flex items-center gap-2" style={{ borderRadius: "2px" }}>
                      <ChevronLeft size={14} /> Back
                    </button>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
