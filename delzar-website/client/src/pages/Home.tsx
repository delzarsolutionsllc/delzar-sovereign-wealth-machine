/* ============================================================
   DELZAR SOLUTIONS — HOME PAGE
   Design: Sovereign Authority (Dark Editorial)
   Sections: Nav, Hero, Stats, About, Services, Platform, Why Us, Contact, Footer
   ============================================================ */

import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  Shield, Cpu, FileText, Users, TrendingUp, Globe,
  ChevronRight, Mail, Phone, MapPin, Star, CheckCircle,
  ArrowRight, Menu, X, ExternalLink
} from "lucide-react";

const HERO_BG = "https://d2xsxph8kpxj0f.cloudfront.net/310519663524019622/WSYVqEy5pxMrF9UiLhg7gD/delzar-hero-bg-JsjZmxC7YThRrHed7v25nn.webp";
const ABOUT_BG = "https://d2xsxph8kpxj0f.cloudfront.net/310519663524019622/WSYVqEy5pxMrF9UiLhg7gD/delzar-about-bg-Kj6UqWMUbJLW4FiFfbrUAW.webp";
const SERVICES_BG = "https://d2xsxph8kpxj0f.cloudfront.net/310519663524019622/WSYVqEy5pxMrF9UiLhg7gD/delzar-services-bg-MnhjZ2rbjE3f8JQY5GKGyz.webp";
const PLATFORM_BG = "https://d2xsxph8kpxj0f.cloudfront.net/310519663524019622/WSYVqEy5pxMrF9UiLhg7gD/delzar-platform-card-LsuDeHHycvuqSG7UtiMfGc.webp";

// ─── Animated Counter ───────────────────────────────────────
function AnimatedCounter({ target, suffix = "" }: { target: number; suffix?: string }) {
  const [count, setCount] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !started.current) {
        started.current = true;
        const duration = 2000;
        const steps = 60;
        const increment = target / steps;
        let current = 0;
        const timer = setInterval(() => {
          current += increment;
          if (current >= target) {
            setCount(target);
            clearInterval(timer);
          } else {
            setCount(Math.floor(current));
          }
        }, duration / steps);
      }
    });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [target]);

  return <span ref={ref}>{count.toLocaleString()}{suffix}</span>;
}

// ─── Scroll Reveal Hook ──────────────────────────────────────
function useReveal() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("visible");
        }
      },
      { threshold: 0.1 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  return ref;
}

// ─── Navigation ─────────────────────────────────────────────
function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 50);
    window.addEventListener("scroll", handler);
    return () => window.removeEventListener("scroll", handler);
  }, []);

  const links = ["About", "Services", "Platform", "Intelligence", "Contact"];

  return (
    <nav
      className="fixed top-0 left-0 right-0 z-50 transition-all duration-500"
      style={{
        background: scrolled
          ? "oklch(0.12 0.04 250 / 0.95)"
          : "transparent",
        backdropFilter: scrolled ? "blur(20px)" : "none",
        borderBottom: scrolled ? "1px solid oklch(0.72 0.12 75 / 0.1)" : "none",
      }}
    >
      <div className="container mx-auto px-6 py-4 flex items-center justify-between max-w-7xl">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 flex items-center justify-center"
            style={{
              background: "linear-gradient(135deg, oklch(0.72 0.12 75), oklch(0.62 0.10 75))",
              clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)",
            }}
          >
            <span style={{ color: "oklch(0.12 0.04 250)", fontSize: "0.7rem", fontWeight: 900 }}>DS</span>
          </div>
          <div>
            <div style={{ fontFamily: "'Playfair Display', serif", fontWeight: 700, fontSize: "1rem", color: "white", lineHeight: 1 }}>
              DELZAR
            </div>
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.55rem", letterSpacing: "0.2em", color: "oklch(0.72 0.12 75)", textTransform: "uppercase" }}>
              SOLUTIONS LLC
            </div>
          </div>
        </div>

        {/* Desktop Links */}
        <div className="hidden md:flex items-center gap-8">
          {links.map((link) => (
            <a key={link} href={`#${link.toLowerCase()}`} className="nav-link">
              {link}
            </a>
          ))}
        </div>

        {/* CTA */}
        <div className="hidden md:flex items-center gap-3">
          <a href="#contact" className="btn-gold" style={{ borderRadius: "2px", fontSize: "0.65rem" }}>
            Get Intelligence Brief
          </a>
        </div>

        {/* Mobile Toggle */}
        <button
          className="md:hidden text-white"
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Mobile Menu */}
      {mobileOpen && (
        <div style={{ background: "oklch(0.12 0.04 250 / 0.98)", borderTop: "1px solid oklch(0.72 0.12 75 / 0.1)" }}>
          <div className="container mx-auto px-6 py-4 flex flex-col gap-4">
            {links.map((link) => (
              <a
                key={link}
                href={`#${link.toLowerCase()}`}
                className="nav-link py-2"
                onClick={() => setMobileOpen(false)}
              >
                {link}
              </a>
            ))}
            <a href="#contact" className="btn-gold text-center mt-2" style={{ borderRadius: "2px" }}>
              Get Intelligence Brief
            </a>
          </div>
        </div>
      )}
    </nav>
  );
}

// ─── Hero Section ────────────────────────────────────────────
function HeroSection() {
  return (
    <section
      id="hero"
      className="relative min-h-screen flex items-center overflow-hidden"
      style={{ background: "oklch(0.12 0.04 250)" }}
    >
      {/* Background Image */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: `url(${HERO_BG})`,
          backgroundSize: "cover",
          backgroundPosition: "center right",
          opacity: 0.45,
        }}
      />
      {/* Dark overlay gradient */}
      <div
        className="absolute inset-0"
        style={{
          background: "linear-gradient(105deg, oklch(0.12 0.04 250 / 0.95) 40%, oklch(0.12 0.04 250 / 0.4) 100%)",
        }}
      />

      {/* Gold accent line — left edge */}
      <div
        className="absolute left-0 top-0 bottom-0 w-1"
        style={{ background: "linear-gradient(180deg, transparent, oklch(0.72 0.12 75), transparent)" }}
      />

      <div className="container relative z-10 mx-auto px-6 max-w-7xl pt-24 pb-16">
        <div className="max-w-3xl">
          {/* Label */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6 }}
            className="flex items-center gap-3 mb-6"
          >
            <div className="gold-rule w-12" />
            <span className="section-label">Cherokee Nation Member-Owned · Buy Indian Act Certified</span>
          </motion.div>

          {/* Headline */}
          <motion.h1
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.1 }}
            style={{
              fontFamily: "'Playfair Display', serif",
              fontSize: "clamp(2.5rem, 6vw, 4.5rem)",
              fontWeight: 700,
              lineHeight: 1.1,
              color: "white",
              marginBottom: "1.5rem",
            }}
          >
            Where Tribal Heritage
            <br />
            <span style={{ color: "oklch(0.72 0.12 75)", fontStyle: "italic" }}>
              Meets Federal Excellence
            </span>
          </motion.h1>

          {/* Subheadline */}
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.2 }}
            style={{
              fontFamily: "'IBM Plex Sans', sans-serif",
              fontSize: "1.125rem",
              color: "oklch(0.75 0.005 65)",
              lineHeight: 1.7,
              maxWidth: "560px",
              marginBottom: "2.5rem",
            }}
          >
            AI-powered federal procurement intelligence for tribal vendors. We turn the Buy Indian Act 
            from a policy footnote into your most powerful competitive advantage.
          </motion.p>

          {/* CTAs */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.3 }}
            className="flex flex-wrap gap-4 items-center"
          >
            <a href="#platform" className="btn-gold flex items-center gap-2" style={{ borderRadius: "2px" }}>
              Access Intelligence Platform
              <ArrowRight size={14} />
            </a>
            <a href="#contact" className="btn-ghost-gold flex items-center gap-2" style={{ borderRadius: "2px" }}>
              Request Capability Statement
            </a>
          </motion.div>

          {/* Trust indicators */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.7, delay: 0.5 }}
            className="flex flex-wrap gap-6 mt-12 pt-8"
            style={{ borderTop: "1px solid oklch(1 0 0 / 0.08)" }}
          >
            {[
              "Buy Indian Act Eligible",
              "8(a) Candidate",
              "NAICS 541511 · 541512 · 541519",
            ].map((badge) => (
              <div key={badge} className="flex items-center gap-2">
                <CheckCircle size={12} style={{ color: "oklch(0.72 0.12 75)" }} />
                <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.65 0.005 65)", letterSpacing: "0.05em" }}>
                  {badge}
                </span>
              </div>
            ))}
          </motion.div>
        </div>
      </div>

      {/* Scroll indicator */}
      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2">
        <div style={{ width: "1px", height: "40px", background: "linear-gradient(180deg, transparent, oklch(0.72 0.12 75))" }} className="animate-gold-pulse" />
      </div>
    </section>
  );
}

// ─── Stats Section ───────────────────────────────────────────
function StatsSection() {
  const ref = useReveal();
  const stats = [
    { number: 53744, suffix: "+", label: "Active Federal Opportunities" },
    { number: 10, suffix: "M+", label: "IHS Tahlequah Recompete Value" },
    { number: 39, suffix: "", label: "Oklahoma Tribal Nations Served" },
    { number: 99, suffix: "/mo", label: "Vendor Intelligence Subscription" },
  ];

  return (
    <section style={{ background: "oklch(0.10 0.04 250)", padding: "5rem 0" }}>
      <div className="container mx-auto px-6 max-w-7xl">
        <div ref={ref} className="reveal grid grid-cols-2 md:grid-cols-4 gap-8">
          {stats.map((stat, i) => (
            <div key={i} className="text-center" style={{ padding: "2rem 1rem", borderRight: i < 3 ? "1px solid oklch(0.72 0.12 75 / 0.1)" : "none" }}>
              <div className="stat-number">
                <AnimatedCounter target={stat.number} suffix={stat.suffix} />
              </div>
              <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", color: "oklch(0.55 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase", marginTop: "0.5rem" }}>
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── About Section ───────────────────────────────────────────
function AboutSection() {
  const ref = useReveal();
  return (
    <section
      id="about"
      className="relative overflow-hidden"
      style={{ padding: "8rem 0" }}
    >
      {/* Background */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: `url(${ABOUT_BG})`,
          backgroundSize: "cover",
          backgroundPosition: "center",
          opacity: 0.2,
        }}
      />
      <div className="absolute inset-0" style={{ background: "linear-gradient(180deg, oklch(0.10 0.04 250), oklch(0.12 0.04 250 / 0.85), oklch(0.10 0.04 250))" }} />

      <div className="container relative z-10 mx-auto px-6 max-w-7xl">
        <div className="grid md:grid-cols-2 gap-16 items-center">
          {/* Left — Text */}
          <div ref={ref} className="reveal">
            <div className="flex items-center gap-3 mb-4">
              <div className="gold-rule w-12" />
              <span className="section-label">Our Mission</span>
            </div>
            <h2 style={{ fontFamily: "'Playfair Display', serif", fontSize: "clamp(2rem, 4vw, 3rem)", fontWeight: 700, color: "white", lineHeight: 1.2, marginBottom: "2rem" }}>
              Sovereign Intelligence.<br />
              <span style={{ color: "oklch(0.72 0.12 75)", fontStyle: "italic" }}>Federal Results.</span>
            </h2>
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "1rem", color: "oklch(0.70 0.005 65)", lineHeight: 1.8 }}>
              <p style={{ marginBottom: "1.25rem" }}>
                Delzar Solutions LLC is a Cherokee Nation member-owned federal IT services company built on a singular conviction: that tribal sovereignty and federal excellence are not competing forces — they are complementary strengths. We exist to prove that point in every contract we pursue and every vendor we empower.
              </p>
              <p style={{ marginBottom: "1.25rem" }}>
                Our AI-powered procurement intelligence platform gives tribal vendors the same institutional knowledge that large prime contractors have spent decades accumulating. We decode the Buy Indian Act, map IDIQ vehicles, track recompetes, and generate agency-ready capability statements — so our clients walk into every opportunity prepared.
              </p>
              <p>
                Founded in Oklahoma and rooted in Cherokee Nation heritage, we bring cultural authority and technical precision to the federal marketplace. When you work with Delzar, you are not just hiring a contractor — you are activating a strategic intelligence system built specifically for tribal business.
              </p>
            </div>
          </div>

          {/* Right — Credentials grid */}
          <div className="grid grid-cols-2 gap-4">
            {[
              { icon: Shield, title: "Buy Indian Act", desc: "Statutory preference that gives tribal vendors a decisive advantage in IHS and BIA contracting" },
              { icon: Cpu, title: "AI Intelligence", desc: "28-agent AI swarm powered by Claude Anthropic + live Tango API federal data" },
              { icon: FileText, title: "Capability Statements", desc: "Agency-formatted, NAICS-coded capability statements generated in minutes" },
              { icon: Users, title: "Tribal Network", desc: "TERO contacts for all 39 Oklahoma tribal nations and growing federal prime relationships" },
            ].map((item, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                viewport={{ once: true }}
                className="glass-card p-5"
                style={{ borderRadius: "4px" }}
              >
                <item.icon size={20} style={{ color: "oklch(0.72 0.12 75)", marginBottom: "0.75rem" }} />
                <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1rem", fontWeight: 600, color: "white", marginBottom: "0.5rem" }}>
                  {item.title}
                </div>
                <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.60 0.005 65)", lineHeight: 1.6 }}>
                  {item.desc}
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

// ─── Services Section ────────────────────────────────────────
function ServicesSection() {
  const services = [
    {
      icon: FileText,
      title: "Capability Statement Services",
      description: "IHS-formatted, NAICS-coded capability statements that get you on the right desks. We generate agency-specific versions for IHS, BIA, HHS, and DoD — each tailored to the contracting officer's evaluation criteria.",
      price: "$500 – $2,500",
      tag: "Revenue Ready Today",
    },
    {
      icon: Shield,
      title: "Buy Indian Act Compliance",
      description: "Full compliance audit and certification support for the Buy Indian Act (25 U.S.C. § 47). We verify your IEE status, identify eligible contracts, and prepare your submission package for tribal preference consideration.",
      price: "$1,500 – $5,000",
      tag: "Statutory Advantage",
    },
    {
      icon: Cpu,
      title: "Federal IT Services",
      description: "Direct federal IT contracting across NAICS 541511, 541512, and 541519. From systems integration to cloud migration, we deliver enterprise-grade technical services with tribal set-aside eligibility.",
      price: "Contract-Based",
      tag: "Core Competency",
    },
    {
      icon: TrendingUp,
      title: "GovCon Strategy Consulting",
      description: "End-to-end federal contracting strategy for tribal businesses. We map your IDIQ vehicle options, identify teaming partners, build your pipeline, and prepare your SAM.gov registration for maximum opportunity capture.",
      price: "$150/hr",
      tag: "Expert Guidance",
    },
    {
      icon: Users,
      title: "Subcontracting Pipeline",
      description: "We connect tribal vendors with prime contractors — including Cherokee Federal — who have active IHS and HHS contracts requiring Buy Indian Act compliant subcontractors. No SAM.gov registration required to start.",
      price: "Commission-Based",
      tag: "Immediate Access",
    },
    {
      icon: Globe,
      title: "Tribal Vendor Matchmaking",
      description: "Our AI-powered three-sided marketplace matches tribal vendors to federal opportunities and prime contractors simultaneously. Powered by the tribal-matchmaking skill and live Tango API data from 53,000+ active solicitations.",
      price: "Platform Included",
      tag: "AI-Powered",
    },
  ];

  return (
    <section
      id="services"
      className="relative overflow-hidden"
      style={{ padding: "8rem 0" }}
    >
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: `url(${SERVICES_BG})`,
          backgroundSize: "cover",
          backgroundPosition: "center",
          opacity: 0.12,
        }}
      />
      <div className="absolute inset-0" style={{ background: "oklch(0.10 0.04 250 / 0.92)" }} />

      <div className="container relative z-10 mx-auto px-6 max-w-7xl">
        <div className="text-center mb-16">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="gold-rule w-12" />
            <span className="section-label">What We Do</span>
            <div className="gold-rule w-12" />
          </div>
          <h2 style={{ fontFamily: "'Playfair Display', serif", fontSize: "clamp(2rem, 4vw, 3rem)", fontWeight: 700, color: "white", lineHeight: 1.2 }}>
            Six Revenue Streams.<br />
            <span style={{ color: "oklch(0.72 0.12 75)", fontStyle: "italic" }}>One Sovereign Platform.</span>
          </h2>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {services.map((service, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: i * 0.08 }}
              viewport={{ once: true }}
              className="glass-card p-7 flex flex-col"
              style={{ borderRadius: "4px" }}
            >
              <div className="flex items-start justify-between mb-4">
                <div
                  className="w-10 h-10 flex items-center justify-center"
                  style={{ background: "oklch(0.72 0.12 75 / 0.1)", borderRadius: "2px" }}
                >
                  <service.icon size={18} style={{ color: "oklch(0.72 0.12 75)" }} />
                </div>
                <span
                  style={{
                    fontFamily: "'IBM Plex Sans', sans-serif",
                    fontSize: "0.6rem",
                    fontWeight: 600,
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                    color: "oklch(0.72 0.12 75)",
                    background: "oklch(0.72 0.12 75 / 0.1)",
                    padding: "0.25rem 0.5rem",
                    borderRadius: "2px",
                  }}
                >
                  {service.tag}
                </span>
              </div>
              <h3 style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.125rem", fontWeight: 600, color: "white", marginBottom: "0.75rem", lineHeight: 1.3 }}>
                {service.title}
              </h3>
              <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.85rem", color: "oklch(0.60 0.005 65)", lineHeight: 1.7, flex: 1, marginBottom: "1.25rem" }}>
                {service.description}
              </p>
              <div className="flex items-center justify-between pt-4" style={{ borderTop: "1px solid oklch(0.72 0.12 75 / 0.1)" }}>
                <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.85rem", fontWeight: 600, color: "oklch(0.72 0.12 75)" }}>
                  {service.price}
                </span>
                <a href="#contact" className="flex items-center gap-1" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.72 0.12 75)", letterSpacing: "0.05em", textTransform: "uppercase" }}>
                  Engage <ChevronRight size={12} />
                </a>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── Platform Section ────────────────────────────────────────
function PlatformSection() {
  const features = [
    "Live feed from 53,744+ active federal opportunities via Tango API",
    "AI-powered opportunity scoring using Buy Indian Act eligibility criteria",
    "Automated capability statement generation for any agency or NAICS code",
    "Recompete tracker with 90-day advance alerts for expiring IHS contracts",
    "Cherokee Federal and prime contractor teaming opportunity matching",
    "Full TERO directory for all 39 Oklahoma tribal nations",
    "SAM.gov registration monitoring and expiration alerts",
    "Claude Anthropic AI analysis of every opportunity in your pipeline",
  ];

  return (
    <section
      id="platform"
      className="relative overflow-hidden"
      style={{ padding: "8rem 0", background: "oklch(0.12 0.04 250)" }}
    >
      <div className="container mx-auto px-6 max-w-7xl">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left — Platform card image */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.7 }}
            viewport={{ once: true }}
            className="relative"
          >
            <div
              className="relative overflow-hidden"
              style={{ borderRadius: "4px", border: "1px solid oklch(0.72 0.12 75 / 0.2)" }}
            >
              <img
                src={PLATFORM_BG}
                alt="Delzar Intelligence Platform"
                className="w-full"
                style={{ display: "block" }}
              />
              {/* Overlay badge */}
              <div
                className="absolute top-4 left-4"
                style={{
                  background: "oklch(0.12 0.04 250 / 0.9)",
                  border: "1px solid oklch(0.72 0.12 75 / 0.3)",
                  padding: "0.5rem 1rem",
                  borderRadius: "2px",
                }}
              >
                <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.6rem", color: "oklch(0.72 0.12 75)", letterSpacing: "0.15em", textTransform: "uppercase" }}>
                  LIVE INTELLIGENCE
                </div>
                <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.25rem", fontWeight: 700, color: "white" }}>
                  53,744 Opportunities
                </div>
              </div>
              {/* Price badge */}
              <div
                className="absolute bottom-4 right-4"
                style={{
                  background: "linear-gradient(135deg, oklch(0.72 0.12 75), oklch(0.62 0.10 75))",
                  padding: "0.75rem 1.25rem",
                  borderRadius: "2px",
                  textAlign: "center",
                }}
              >
                <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.6rem", fontWeight: 600, color: "oklch(0.12 0.04 250)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
                  Starting at
                </div>
                <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.5rem", fontWeight: 700, color: "oklch(0.12 0.04 250)", lineHeight: 1 }}>
                  $99<span style={{ fontSize: "0.75rem" }}>/mo</span>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Right — Copy */}
          <div>
            <div className="flex items-center gap-3 mb-4">
              <div className="gold-rule w-12" />
              <span className="section-label">Intelligence Platform</span>
            </div>
            <h2 style={{ fontFamily: "'Playfair Display', serif", fontSize: "clamp(1.75rem, 3.5vw, 2.75rem)", fontWeight: 700, color: "white", lineHeight: 1.2, marginBottom: "1.25rem" }}>
              The Federal Intelligence<br />
              <span style={{ color: "oklch(0.72 0.12 75)", fontStyle: "italic" }}>Tribal Vendors Deserve</span>
            </h2>
            <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "1rem", color: "oklch(0.65 0.005 65)", lineHeight: 1.8, marginBottom: "2rem" }}>
              Large prime contractors spend millions on business development intelligence. For $99/month, tribal vendors get the same institutional knowledge — powered by Claude Anthropic AI, live Tango federal data, and 28 specialized intelligence agents.
            </p>

            <div className="space-y-3 mb-8">
              {features.map((feature, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: 20 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.4, delay: i * 0.06 }}
                  viewport={{ once: true }}
                  className="flex items-start gap-3"
                >
                  <CheckCircle size={14} style={{ color: "oklch(0.72 0.12 75)", marginTop: "3px", flexShrink: 0 }} />
                  <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.70 0.005 65)", lineHeight: 1.5 }}>
                    {feature}
                  </span>
                </motion.div>
              ))}
            </div>

            <div className="flex gap-4">
              <a href="#contact" className="btn-gold flex items-center gap-2" style={{ borderRadius: "2px" }}>
                Start Free Trial <ArrowRight size={14} />
              </a>
              <a href="#contact" className="btn-ghost-gold" style={{ borderRadius: "2px" }}>
                Learn More
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

// ─── Intelligence Feed Section ────────────────────────────────
function IntelligenceSection() {
  const alerts = [
    {
      type: "CRITICAL",
      title: "IHS Tahlequah IT Recompete",
      value: "$10M+",
      deadline: "Q3 2026",
      status: "Sources Sought Open",
      naics: "541512",
    },
    {
      type: "HIGH",
      title: "Buy Indian Industry Day",
      value: "Registration Open",
      deadline: "April 27–28, 2026",
      status: "Register Now",
      naics: "Multiple",
    },
    {
      type: "HIGH",
      title: "IHS Policy Management System",
      value: "$2.5M",
      deadline: "May 2026",
      status: "Sources Sought",
      naics: "541511",
    },
    {
      type: "MEDIUM",
      title: "SAM.gov Registration Alert",
      value: "Expiring April 27",
      deadline: "15 Days",
      status: "Action Required",
      naics: "All NAICS",
    },
  ];

  const typeColors: Record<string, string> = {
    CRITICAL: "oklch(0.65 0.22 27)",
    HIGH: "oklch(0.72 0.12 75)",
    MEDIUM: "oklch(0.65 0.15 200)",
  };

  return (
    <section
      id="intelligence"
      style={{ padding: "8rem 0", background: "oklch(0.10 0.04 250)" }}
    >
      <div className="container mx-auto px-6 max-w-7xl">
        <div className="flex items-start justify-between mb-12 flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-3 mb-4">
              <div className="gold-rule w-12" />
              <span className="section-label">Live Intelligence Feed</span>
            </div>
            <h2 style={{ fontFamily: "'Playfair Display', serif", fontSize: "clamp(1.75rem, 3.5vw, 2.75rem)", fontWeight: 700, color: "white", lineHeight: 1.2 }}>
              Active Alerts &amp;<br />
              <span style={{ color: "oklch(0.72 0.12 75)", fontStyle: "italic" }}>Priority Opportunities</span>
            </h2>
          </div>
          <div
            className="flex items-center gap-2 px-4 py-2"
            style={{ background: "oklch(0.72 0.12 75 / 0.1)", border: "1px solid oklch(0.72 0.12 75 / 0.2)", borderRadius: "2px" }}
          >
            <div className="w-2 h-2 rounded-full animate-gold-pulse" style={{ background: "oklch(0.72 0.12 75)" }} />
            <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.72 0.12 75)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
              Live via Tango API · 53,744 Opportunities
            </span>
          </div>
        </div>

        <div className="grid md:grid-cols-2 gap-4">
          {alerts.map((alert, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: i * 0.1 }}
              viewport={{ once: true }}
              className="glass-card p-6"
              style={{ borderRadius: "4px", borderLeft: `3px solid ${typeColors[alert.type]}` }}
            >
              <div className="flex items-start justify-between mb-3">
                <span
                  style={{
                    fontFamily: "'IBM Plex Sans', sans-serif",
                    fontSize: "0.6rem",
                    fontWeight: 700,
                    letterSpacing: "0.15em",
                    color: typeColors[alert.type],
                    background: `${typeColors[alert.type]}20`,
                    padding: "0.2rem 0.5rem",
                    borderRadius: "2px",
                  }}
                >
                  {alert.type}
                </span>
                <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.50 0.005 65)" }}>
                  NAICS {alert.naics}
                </span>
              </div>
              <h3 style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.125rem", fontWeight: 600, color: "white", marginBottom: "0.5rem" }}>
                {alert.title}
              </h3>
              <div className="flex items-center justify-between">
                <div>
                  <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "1.25rem", fontWeight: 700, color: "oklch(0.72 0.12 75)" }}>
                    {alert.value}
                  </div>
                  <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", color: "oklch(0.55 0.005 65)" }}>
                    Deadline: {alert.deadline}
                  </div>
                </div>
                <a
                  href="#contact"
                  className="flex items-center gap-1"
                  style={{
                    fontFamily: "'IBM Plex Sans', sans-serif",
                    fontSize: "0.7rem",
                    fontWeight: 600,
                    color: typeColors[alert.type],
                    letterSpacing: "0.05em",
                    textTransform: "uppercase",
                  }}
                >
                  {alert.status} <ExternalLink size={10} />
                </a>
              </div>
            </motion.div>
          ))}
        </div>

        <div className="text-center mt-8">
          <a href="#platform" className="btn-ghost-gold inline-flex items-center gap-2" style={{ borderRadius: "2px" }}>
            View Full Intelligence Dashboard <ArrowRight size={14} />
          </a>
        </div>
      </div>
    </section>
  );
}

// ─── Why Us Section ──────────────────────────────────────────
function WhyUsSection() {
  const points = [
    {
      number: "01",
      title: "Statutory Advantage",
      body: "The Buy Indian Act (25 U.S.C. § 47) mandates preference for Indian Economic Enterprises in IHS and BIA contracting. As a Cherokee Nation member-owned business, Delzar carries this statutory advantage into every federal opportunity we pursue — and we teach our clients to do the same.",
    },
    {
      number: "02",
      title: "AI-Powered Intelligence",
      body: "We deploy 28 specialized AI agents — powered by Claude Anthropic and live Tango API federal data — to analyze every opportunity, score vendor fit, generate capability statements, and track recompetes. No other tribal GovCon firm operates at this level of intelligence automation.",
    },
    {
      number: "03",
      title: "Immediate Revenue Paths",
      body: "We do not just advise — we activate. Our clients can generate revenue within days through capability statement sales, subcontracting pipeline access, and the tribal vendor platform. We have identified $57,495/month in revenue streams that require zero federal registration to start.",
    },
    {
      number: "04",
      title: "Cherokee Federal Pipeline",
      body: "Our direct relationship with Cherokee Federal — one of the largest Native American-owned federal contractors — creates immediate subcontracting opportunities for tribal vendors. We map active IHS and HHS contracts and connect qualified vendors to teaming opportunities that most firms never find.",
    },
  ];

  return (
    <section
      style={{ padding: "8rem 0", background: "oklch(0.12 0.04 250)" }}
    >
      <div className="container mx-auto px-6 max-w-7xl">
        <div className="grid lg:grid-cols-2 gap-16">
          {/* Left — Sticky header */}
          <div className="lg:sticky lg:top-24 lg:self-start">
            <div className="flex items-center gap-3 mb-4">
              <div className="gold-rule w-12" />
              <span className="section-label">Why Delzar</span>
            </div>
            <h2 style={{ fontFamily: "'Playfair Display', serif", fontSize: "clamp(2rem, 4vw, 3rem)", fontWeight: 700, color: "white", lineHeight: 1.2, marginBottom: "1.5rem" }}>
              Four Reasons We<br />
              <span style={{ color: "oklch(0.72 0.12 75)", fontStyle: "italic" }}>Win Where Others Don't</span>
            </h2>
            <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "1rem", color: "oklch(0.60 0.005 65)", lineHeight: 1.8, marginBottom: "2.5rem" }}>
              The federal marketplace is not a level playing field. Delzar exists to give tribal businesses the intelligence, tools, and relationships to compete — and win — on their own terms.
            </p>
            <a href="#contact" className="btn-gold inline-flex items-center gap-2" style={{ borderRadius: "2px" }}>
              Schedule a Strategy Call <ArrowRight size={14} />
            </a>
          </div>

          {/* Right — Points */}
          <div className="space-y-6">
            {points.map((point, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: 30 }}
                whileInView={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                viewport={{ once: true }}
                className="glass-card p-7"
                style={{ borderRadius: "4px" }}
              >
                <div className="flex items-start gap-5">
                  <div
                    style={{
                      fontFamily: "'Playfair Display', serif",
                      fontSize: "2.5rem",
                      fontWeight: 700,
                      color: "oklch(0.72 0.12 75 / 0.2)",
                      lineHeight: 1,
                      flexShrink: 0,
                      width: "3rem",
                    }}
                  >
                    {point.number}
                  </div>
                  <div>
                    <h3 style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.25rem", fontWeight: 600, color: "white", marginBottom: "0.75rem" }}>
                      {point.title}
                    </h3>
                    <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.875rem", color: "oklch(0.62 0.005 65)", lineHeight: 1.8 }}>
                      {point.body}
                    </p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

// ─── Contact Section ─────────────────────────────────────────
function ContactSection() {
  const [form, setForm] = useState({ name: "", email: "", org: "", message: "" });
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
  };

  return (
    <section
      id="contact"
      style={{ padding: "8rem 0", background: "oklch(0.10 0.04 250)" }}
    >
      <div className="container mx-auto px-6 max-w-7xl">
        <div className="grid lg:grid-cols-2 gap-16">
          {/* Left — Info */}
          <div>
            <div className="flex items-center gap-3 mb-4">
              <div className="gold-rule w-12" />
              <span className="section-label">Get In Touch</span>
            </div>
            <h2 style={{ fontFamily: "'Playfair Display', serif", fontSize: "clamp(2rem, 4vw, 3rem)", fontWeight: 700, color: "white", lineHeight: 1.2, marginBottom: "1.5rem" }}>
              Ready to Activate<br />
              <span style={{ color: "oklch(0.72 0.12 75)", fontStyle: "italic" }}>Your Federal Pipeline?</span>
            </h2>
            <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "1rem", color: "oklch(0.60 0.005 65)", lineHeight: 1.8, marginBottom: "3rem" }}>
              Whether you need a capability statement, a recompete intelligence brief, or a full GovCon strategy session — we are ready to deploy. Contact us and receive a complimentary intelligence brief on the top 3 federal opportunities matching your NAICS codes.
            </p>

            <div className="space-y-5">
              {[
                { icon: Mail, label: "Email", value: "dominique@delzarsolutionsllc.com" },
                { icon: MapPin, label: "Location", value: "Oklahoma · Serving All 39 Tribal Nations" },
                { icon: Star, label: "Certifications", value: "Buy Indian Act · 8(a) Candidate · IEE" },
              ].map((item, i) => (
                <div key={i} className="flex items-start gap-4">
                  <div
                    className="w-9 h-9 flex items-center justify-center flex-shrink-0"
                    style={{ background: "oklch(0.72 0.12 75 / 0.1)", borderRadius: "2px" }}
                  >
                    <item.icon size={16} style={{ color: "oklch(0.72 0.12 75)" }} />
                  </div>
                  <div>
                    <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.50 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "0.2rem" }}>
                      {item.label}
                    </div>
                    <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.9rem", color: "oklch(0.80 0.005 65)" }}>
                      {item.value}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right — Form */}
          <div className="glass-card p-8" style={{ borderRadius: "4px" }}>
            {submitted ? (
              <div className="flex flex-col items-center justify-center h-full text-center py-12">
                <CheckCircle size={48} style={{ color: "oklch(0.72 0.12 75)", marginBottom: "1.5rem" }} />
                <h3 style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.5rem", fontWeight: 700, color: "white", marginBottom: "0.75rem" }}>
                  Intelligence Brief Requested
                </h3>
                <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.9rem", color: "oklch(0.60 0.005 65)", lineHeight: 1.7 }}>
                  Dominique will respond within 24 hours with your complimentary intelligence brief on the top 3 federal opportunities matching your profile.
                </p>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-5">
                <h3 style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.25rem", fontWeight: 600, color: "white", marginBottom: "0.5rem" }}>
                  Request Intelligence Brief
                </h3>
                <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.55 0.005 65)", marginBottom: "1.5rem" }}>
                  Complimentary for qualified tribal vendors and federal contractors.
                </p>

                {[
                  { key: "name", label: "Full Name", placeholder: "Your name", type: "text" },
                  { key: "email", label: "Email Address", placeholder: "your@email.com", type: "email" },
                  { key: "org", label: "Organization / Tribe", placeholder: "Company or tribal affiliation", type: "text" },
                ].map((field) => (
                  <div key={field.key}>
                    <label
                      htmlFor={field.key}
                      style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", fontWeight: 600, color: "oklch(0.60 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: "0.4rem" }}
                    >
                      {field.label}
                    </label>
                    <input
                      id={field.key}
                      type={field.type}
                      placeholder={field.placeholder}
                      value={form[field.key as keyof typeof form]}
                      onChange={(e) => setForm({ ...form, [field.key]: e.target.value })}
                      required
                      style={{
                        width: "100%",
                        background: "oklch(0.12 0.04 250 / 0.8)",
                        border: "1px solid oklch(1 0 0 / 0.1)",
                        borderRadius: "2px",
                        padding: "0.75rem 1rem",
                        fontFamily: "'IBM Plex Sans', sans-serif",
                        fontSize: "0.875rem",
                        color: "white",
                        outline: "none",
                        transition: "border-color 0.2s",
                      }}
                      onFocus={(e) => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                      onBlur={(e) => (e.target.style.borderColor = "oklch(1 0 0 / 0.1)")}
                    />
                  </div>
                ))}

                <div>
                  <label
                    htmlFor="message"
                    style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", fontWeight: 600, color: "oklch(0.60 0.005 65)", letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: "0.4rem" }}
                  >
                    What Are You Working On?
                  </label>
                  <textarea
                    id="message"
                    rows={4}
                    placeholder="Describe your federal contracting goals, current challenges, or specific opportunities you're pursuing..."
                    value={form.message}
                    onChange={(e) => setForm({ ...form, message: e.target.value })}
                    style={{
                      width: "100%",
                      background: "oklch(0.12 0.04 250 / 0.8)",
                      border: "1px solid oklch(1 0 0 / 0.1)",
                      borderRadius: "2px",
                      padding: "0.75rem 1rem",
                      fontFamily: "'IBM Plex Sans', sans-serif",
                      fontSize: "0.875rem",
                      color: "white",
                      outline: "none",
                      resize: "vertical",
                      transition: "border-color 0.2s",
                    }}
                    onFocus={(e) => (e.target.style.borderColor = "oklch(0.72 0.12 75 / 0.5)")}
                    onBlur={(e) => (e.target.style.borderColor = "oklch(1 0 0 / 0.1)")}
                  />
                </div>

                <button type="submit" className="btn-gold w-full flex items-center justify-center gap-2" style={{ borderRadius: "2px" }}>
                  Request Intelligence Brief <ArrowRight size={14} />
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

// ─── Footer ──────────────────────────────────────────────────
function Footer() {
  return (
    <footer style={{ background: "oklch(0.08 0.04 250)", padding: "4rem 0 2rem" }}>
      <div className="container mx-auto px-6 max-w-7xl">
        <div className="gold-rule mb-8" />
        <div className="grid md:grid-cols-3 gap-8 mb-8">
          {/* Brand */}
          <div>
            <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "1.25rem", fontWeight: 700, color: "white", marginBottom: "0.25rem" }}>
              DELZAR SOLUTIONS LLC
            </div>
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.7rem", color: "oklch(0.72 0.12 75)", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: "1rem" }}>
              Where Tribal Heritage Meets Federal Excellence
            </div>
            <p style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.50 0.005 65)", lineHeight: 1.7 }}>
              Cherokee Nation member-owned federal IT services company. Buy Indian Act eligible. 8(a) candidate.
            </p>
          </div>

          {/* Quick Links */}
          <div>
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.72 0.12 75)", letterSpacing: "0.2em", textTransform: "uppercase", marginBottom: "1rem" }}>
              Quick Links
            </div>
            <div className="space-y-2">
              {["About", "Services", "Platform", "Intelligence", "Contact"].map((link) => (
                <a
                  key={link}
                  href={`#${link.toLowerCase()}`}
                  style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.85rem", color: "oklch(0.55 0.005 65)", display: "block", transition: "color 0.2s" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "oklch(0.72 0.12 75)")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "oklch(0.55 0.005 65)")}
                >
                  {link}
                </a>
              ))}
            </div>
          </div>

          {/* Certifications */}
          <div>
            <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.65rem", fontWeight: 600, color: "oklch(0.72 0.12 75)", letterSpacing: "0.2em", textTransform: "uppercase", marginBottom: "1rem" }}>
              Certifications & NAICS
            </div>
            <div className="space-y-2">
              {[
                "Buy Indian Act Eligible (IEE)",

                "8(a) Candidate",
                "NAICS 541511 · 541512 · 541519",
                "NAICS 541611 · 541618",
              ].map((cert) => (
                <div key={cert} className="flex items-center gap-2">
                  <div className="w-1 h-1 rounded-full" style={{ background: "oklch(0.72 0.12 75)", flexShrink: 0 }} />
                  <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.55 0.005 65)" }}>
                    {cert}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="gold-rule mb-6" />
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", color: "oklch(0.40 0.005 65)" }}>
            © 2026 Delzar Solutions LLC. All rights reserved. Cherokee Nation member-owned business.
          </div>
          <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", color: "oklch(0.40 0.005 65)" }}>
            Powered by Claude Anthropic AI · Tango Federal API · Manus Intelligence Platform
          </div>
        </div>
      </div>
    </footer>
  );
}

// ─── Main Home Page ──────────────────────────────────────────
export default function Home() {
  return (
    <div className="min-h-screen" style={{ background: "oklch(0.12 0.04 250)" }}>
      <Navbar />
      <HeroSection />
      <StatsSection />
      <AboutSection />
      <ServicesSection />
      <PlatformSection />
      <IntelligenceSection />
      <WhyUsSection />
      <ContactSection />
      <Footer />
    </div>
  );
}
