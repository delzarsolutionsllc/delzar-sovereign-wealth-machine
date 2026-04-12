# Delzar Solutions LLC — Website TODO

## Completed
- [x] Dark editorial design system (Sovereign Authority — navy/gold, Playfair Display + IBM Plex Sans)
- [x] Home page — 10 sections: Nav, Hero, Stats, About, Services, Platform, Intelligence, Why Us, Contact, Footer
- [x] /opportunities page — live Tango API dashboard
- [x] /capability-generator page — AI-powered PDF generator
- [x] WOSB references removed
- [x] 6 Google Calendar events created
- [x] Full-stack upgrade (web-db-user) — tRPC, Drizzle ORM, MySQL, auth
- [x] Database schema: contact_submissions + opportunities_cache tables
- [x] tRPC router: contact form submission (saves to DB + notifies owner)
- [x] tRPC router: Tango API proxy (server-side, hides API key)
- [x] tRPC router: capability statement generator
- [x] Wire Contact form to real tRPC mutation (contact.submit)
- [x] Add owner notification on contact form submission
- [x] Update index.html with canonical URL, OG tags, Twitter Card, JSON-LD schema
- [x] Run pnpm db:push to sync schema

## Co-Pilot 10x System — COMPLETED
- [x] Wire Anthropic Claude API as primary intelligence engine (server/copilot.ts)
- [x] Build callClaude() and callManus() as independent agent functions
- [x] Implement dualAgentReview() — 4-step pipeline: parallel → cross-review → synthesis → improvements
- [x] Implement generateCapabilityStatement() — Claude writes, Manus QA, Claude finalizes
- [x] Implement analyzeOpportunity() — Claude scores, Manus validates, GO/NO-GO
- [x] Implement generateWeeklyStrategy() — joint 7-day battle plan
- [x] Add tRPC routes: copilot.generateCapabilityStatement, analyzeOpportunity, weeklyStrategy, dualReview, healthCheck
- [x] Build /copilot page — AI Co-Pilot Command Center with 3 tabs
- [x] Add real-time agent health check (30s polling)
- [x] Create .copilot/tasks-for-claude.json (5 tasks Manus assigns to Claude)
- [x] Create .copilot/tasks-for-manus.json (5 tasks Claude assigns to Manus)
- [x] Write COLLABORATION.md protocol document
- [x] Add CODEOWNERS file
- [x] Add issue templates: ai-task, bug-report, feature-request
- [x] Push all code to GitHub (delzarsolutionsllc/delzar-solutions-website)
- [x] CI workflow file created locally (needs GitHub UI push for workflows permission)

## Backlog
- [x] Vitest tests for co-pilot tRPC routes (MANUS-003) — 8 tests passing
- [ ] Opportunity analyzer UI on Opportunities page (MANUS-004 in task queue)
- [ ] SAM.gov renewal guide (CLAUDE-001 in task queue — CRITICAL, due April 27)
- [ ] IHS Tahlequah recompete strategy (CLAUDE-002 in task queue)
- [ ] Buy Indian Industry Day prep brief (CLAUDE-003 in task queue)
- [ ] Stripe integration ($99/month vendor subscription)
- [x] Admin dashboard (/admin — contact submissions, AI health, quick links)
- [ ] LinkedIn article auto-posting workflow
- [ ] Opportunity management in /admin (update status/priority/notes on cached opportunities)
- [x] Vitest tests for co-pilot tRPC routes (MANUS-003) — 8 tests passing

## Urgent Fixes (DJ Requested)
- [ ] Remove ALL "AI-powered" / "AI-Powered" language from every page and component
- [ ] Remove ALL Tango API references (source concealment — competitive intelligence)
- [ ] Replace AI/Tango language with neutral intelligence/procurement messaging
- [ ] Configure 21st.dev Magic MCP server with API key
- [ ] Integrate 21st.dev premium UI components throughout site
- [ ] Wire delzarsolutionsllc.com domain in all meta/OG/canonical tags
- [ ] Update ARIA chatbot — remove "AI" branding from visible UI labels
