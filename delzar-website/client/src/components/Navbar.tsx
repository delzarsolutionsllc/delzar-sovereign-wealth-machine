/**
 * Delzar Solutions — Premium Navbar
 * Design: 21st.dev-inspired dark editorial with mega-menu dropdown
 * Features: Responsive, no overflow, keyboard accessible, smooth scroll
 */
import { useState, useEffect, useRef } from "react";
import { Link, useLocation } from "wouter";
import { Menu, X, ChevronDown, Shield, Cpu, FileText, TrendingUp, Brain, Search } from "lucide-react";

const NAV_SECTIONS = [
  { label: "About", href: "#about" },
  { label: "Services", href: "#services" },
  { label: "Platform", href: "#platform" },
  { label: "Intelligence", href: "#intelligence" },
  { label: "Contact", href: "#contact" },
];

const NAV_TOOLS = [
  {
    label: "Opportunities",
    href: "/opportunities",
    icon: Search,
    desc: "53,744+ live federal opportunities",
  },
  {
    label: "Capability Statement",
    href: "/capability-generator",
    icon: FileText,
    desc: "AI-generated, agency-ready in minutes",
  },
  {
    label: "AI Co-Pilot",
    href: "/copilot",
    icon: Brain,
    desc: "Manus + Claude dual-agent intelligence",
  },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [location] = useLocation();
  const dropdownRef = useRef<HTMLDivElement>(null);
  const isHomePage = location === "/";

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 50);
    window.addEventListener("scroll", handler, { passive: true });
    return () => window.removeEventListener("scroll", handler);
  }, []);

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setToolsOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileOpen(false);
    setToolsOpen(false);
  }, [location]);

  const handleSectionLink = (href: string) => {
    if (!isHomePage) {
      window.location.href = `/${href}`;
    } else {
      const el = document.querySelector(href);
      if (el) el.scrollIntoView({ behavior: "smooth" });
    }
    setMobileOpen(false);
  };

  return (
    <>
      <nav
        className="fixed top-0 left-0 right-0 z-50 transition-all duration-500"
        style={{
          background: scrolled || !isHomePage
            ? "oklch(0.12 0.04 250 / 0.97)"
            : "transparent",
          backdropFilter: scrolled || !isHomePage ? "blur(20px)" : "none",
          borderBottom: scrolled || !isHomePage
            ? "1px solid oklch(0.72 0.12 75 / 0.12)"
            : "none",
        }}
        role="navigation"
        aria-label="Main navigation"
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">

            {/* ── Logo ─────────────────────────────────────── */}
            <Link href="/" className="flex items-center gap-3 flex-shrink-0" aria-label="Delzar Solutions home">
              <div
                className="w-8 h-8 flex items-center justify-center flex-shrink-0"
                style={{
                  background: "linear-gradient(135deg, oklch(0.72 0.12 75), oklch(0.62 0.10 75))",
                  clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)",
                }}
                aria-hidden="true"
              >
                <span style={{ color: "oklch(0.12 0.04 250)", fontSize: "0.65rem", fontWeight: 900 }}>DS</span>
              </div>
              <div className="hidden sm:block">
                <div style={{ fontFamily: "'Playfair Display', serif", fontWeight: 700, fontSize: "0.95rem", color: "white", lineHeight: 1 }}>
                  DELZAR
                </div>
                <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.5rem", letterSpacing: "0.2em", color: "oklch(0.72 0.12 75)", textTransform: "uppercase" }}>
                  SOLUTIONS LLC
                </div>
              </div>
            </Link>

            {/* ── Desktop Nav ───────────────────────────────── */}
            <div className="hidden lg:flex items-center gap-1">
              {/* Section links */}
              {isHomePage && NAV_SECTIONS.map((link) => (
                <button
                  key={link.label}
                  onClick={() => handleSectionLink(link.href)}
                  className="nav-link px-3 py-2 rounded-sm hover:bg-white/5 transition-colors"
                  style={{ background: "none", border: "none", cursor: "pointer" }}
                >
                  {link.label}
                </button>
              ))}

              {/* Tools dropdown */}
              <div ref={dropdownRef} className="relative">
                <button
                  onClick={() => setToolsOpen(!toolsOpen)}
                  className="nav-link px-3 py-2 rounded-sm hover:bg-white/5 transition-colors flex items-center gap-1"
                  style={{ background: "none", border: "none", cursor: "pointer" }}
                  aria-expanded={toolsOpen}
                  aria-haspopup="true"
                >
                  Tools
                  <ChevronDown
                    size={12}
                    className="transition-transform duration-200"
                    style={{ transform: toolsOpen ? "rotate(180deg)" : "rotate(0deg)" }}
                  />
                </button>

                {/* Mega dropdown */}
                {toolsOpen && (
                  <div
                    className="absolute top-full left-1/2 -translate-x-1/2 mt-2 w-72 rounded-sm overflow-hidden shadow-2xl"
                    style={{
                      background: "oklch(0.14 0.04 250)",
                      border: "1px solid oklch(0.72 0.12 75 / 0.2)",
                    }}
                    role="menu"
                  >
                    <div className="p-1">
                      {NAV_TOOLS.map((tool) => (
                        <Link
                          key={tool.label}
                          href={tool.href}
                          className="flex items-start gap-3 px-3 py-3 rounded-sm hover:bg-white/5 transition-colors group"
                          role="menuitem"
                          onClick={() => setToolsOpen(false)}
                        >
                          <div
                            className="w-8 h-8 flex items-center justify-center flex-shrink-0 mt-0.5 rounded-sm"
                            style={{ background: "oklch(0.72 0.12 75 / 0.12)" }}
                          >
                            <tool.icon size={14} style={{ color: "oklch(0.72 0.12 75)" }} />
                          </div>
                          <div>
                            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", fontWeight: 600, color: "white" }}>
                              {tool.label}
                            </div>
                            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.55 0.005 65)", marginTop: "0.1rem" }}>
                              {tool.desc}
                            </div>
                          </div>
                        </Link>
                      ))}
                    </div>
                    <div
                      className="px-4 py-2 flex items-center justify-between"
                      style={{ borderTop: "1px solid oklch(0.72 0.12 75 / 0.1)" }}
                    >
                      <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", color: "oklch(0.50 0.005 65)" }}>
                        Powered by Claude Anthropic AI
                      </span>
                      <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "oklch(0.72 0.12 75)" }} />
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* ── CTA + Mobile Toggle ───────────────────────── */}
            <div className="flex items-center gap-3">
              <a
                href={isHomePage ? "#contact" : "/#contact"}
                className="hidden md:inline-flex btn-gold items-center gap-2"
                style={{ borderRadius: "2px", fontSize: "0.65rem", padding: "0.6rem 1.25rem" }}
              >
                Get Brief
              </a>
              <button
                className="lg:hidden flex items-center justify-center w-9 h-9 rounded-sm text-white hover:bg-white/10 transition-colors"
                onClick={() => setMobileOpen(!mobileOpen)}
                aria-label={mobileOpen ? "Close menu" : "Open menu"}
                aria-expanded={mobileOpen}
              >
                {mobileOpen ? <X size={18} /> : <Menu size={18} />}
              </button>
            </div>
          </div>
        </div>

        {/* ── Mobile Menu ───────────────────────────────────── */}
        <div
          className="lg:hidden overflow-hidden transition-all duration-300"
          style={{
            maxHeight: mobileOpen ? "600px" : "0",
            background: "oklch(0.11 0.04 250)",
            borderTop: mobileOpen ? "1px solid oklch(0.72 0.12 75 / 0.1)" : "none",
          }}
        >
          <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col gap-1">
            {isHomePage && NAV_SECTIONS.map((link) => (
              <button
                key={link.label}
                onClick={() => handleSectionLink(link.href)}
                className="text-left px-3 py-2.5 rounded-sm nav-link hover:bg-white/5 transition-colors w-full"
                style={{ background: "none", border: "none", cursor: "pointer" }}
              >
                {link.label}
              </button>
            ))}
            <div className="my-1" style={{ height: "1px", background: "oklch(0.72 0.12 75 / 0.1)" }} />
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.6rem", fontWeight: 600, letterSpacing: "0.15em", textTransform: "uppercase", color: "oklch(0.50 0.005 65)", padding: "0.5rem 0.75rem 0.25rem" }}>
              Tools
            </div>
            {NAV_TOOLS.map((tool) => (
              <Link
                key={tool.label}
                href={tool.href}
                className="flex items-center gap-3 px-3 py-2.5 rounded-sm hover:bg-white/5 transition-colors"
                onClick={() => setMobileOpen(false)}
              >
                <tool.icon size={14} style={{ color: "oklch(0.72 0.12 75)", flexShrink: 0 }} />
                <span className="nav-link">{tool.label}</span>
              </Link>
            ))}
            <div className="mt-2 pt-2" style={{ borderTop: "1px solid oklch(0.72 0.12 75 / 0.1)" }}>
              <a
                href={isHomePage ? "#contact" : "/#contact"}
                className="btn-gold w-full flex items-center justify-center"
                style={{ borderRadius: "2px" }}
                onClick={() => setMobileOpen(false)}
              >
                Get Intelligence Brief
              </a>
            </div>
          </div>
        </div>
      </nav>

      {/* Spacer for non-home pages */}
      {!isHomePage && <div className="h-16" />}
    </>
  );
}
