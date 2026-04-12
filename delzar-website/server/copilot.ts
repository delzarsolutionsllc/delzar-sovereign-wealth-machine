/**
 * Delzar Solutions — Manus ↔ Claude Anthropic Co-Pilot Engine
 *
 * Architecture:
 *   - Claude Anthropic (claude-3-5-sonnet-20241022) = Primary intelligence engine
 *   - Manus LLM (invokeLLM) = QA reviewer and orchestrator
 *   - Both agents check each other's outputs and generate improvement recommendations
 *
 * Capabilities:
 *   1. Capability Statement Generator (Claude writes, Manus QA-reviews)
 *   2. Opportunity Analyzer (Claude scores, Manus validates)
 *   3. Strategy Advisor (Claude strategizes, Manus cross-checks)
 *   4. Code/Content QA (Manus writes, Claude reviews)
 *   5. Joint Intelligence Reports (both agents contribute simultaneously)
 */

import Anthropic from "@anthropic-ai/sdk";
import { invokeLLM } from "./_core/llm";

// ─── Anthropic Client ─────────────────────────────────────────────────────────
function getAnthropicClient() {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error("ANTHROPIC_API_KEY not set");
  return new Anthropic({ apiKey });
}

// ─── Claude Direct Call ───────────────────────────────────────────────────────
export async function callClaude(
  systemPrompt: string,
  userMessage: string,
  model = "claude-3-5-sonnet-20241022"
): Promise<string> {
  const client = getAnthropicClient();
  const message = await client.messages.create({
    model,
    max_tokens: 2048,
    system: systemPrompt,
    messages: [{ role: "user", content: userMessage }],
  });
  const block = message.content[0];
  return block.type === "text" ? block.text : "";
}

// ─── Manus LLM Call ───────────────────────────────────────────────────────────
export async function callManus(systemPrompt: string, userMessage: string): Promise<string> {
  const response = await invokeLLM({
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
  });
  const content = response.choices?.[0]?.message?.content;
  if (typeof content === "string") return content;
  return "";
}

// ─── DUAL-AGENT REVIEW ────────────────────────────────────────────────────────
/**
 * Both agents work on the same task, then review each other's output.
 * Returns a synthesized result with both perspectives and a final recommendation.
 */
export async function dualAgentReview(params: {
  task: string;
  context: string;
  claudeRole: string;
  manusRole: string;
}): Promise<{
  claudeOutput: string;
  manusOutput: string;
  claudeReviewOfManus: string;
  manusReviewOfClaude: string;
  synthesis: string;
  improvements: string[];
}> {
  const { task, context, claudeRole, manusRole } = params;

  // Step 1: Both agents work on the task simultaneously
  const [claudeOutput, manusOutput] = await Promise.all([
    callClaude(
      `You are ${claudeRole}. You are part of a dual-agent AI team for Delzar Solutions LLC, a Cherokee Nation member-owned federal IT services company. Your co-agent is Manus AI. You will both work on tasks and review each other's outputs to produce the best possible result.`,
      `TASK: ${task}\n\nCONTEXT:\n${context}`
    ),
    callManus(
      `You are ${manusRole}. You are part of a dual-agent AI team for Delzar Solutions LLC, a Cherokee Nation member-owned federal IT services company. Your co-agent is Claude Anthropic. You will both work on tasks and review each other's outputs to produce the best possible result.`,
      `TASK: ${task}\n\nCONTEXT:\n${context}`
    ),
  ]);

  // Step 2: Cross-review — each agent reviews the other's output
  const [claudeReviewOfManus, manusReviewOfClaude] = await Promise.all([
    callClaude(
      `You are ${claudeRole}. You are reviewing your co-agent Manus AI's output. Be constructive, specific, and identify both strengths and improvements. Focus on accuracy, completeness, and strategic value for a tribal GovCon business.`,
      `MANUS OUTPUT TO REVIEW:\n${manusOutput}\n\nORIGINAL TASK: ${task}\n\nProvide a structured review: 1) What Manus got right, 2) What needs improvement, 3) Specific suggestions.`
    ),
    callManus(
      `You are ${manusRole}. You are reviewing your co-agent Claude Anthropic's output. Be constructive, specific, and identify both strengths and improvements. Focus on accuracy, completeness, and strategic value for a tribal GovCon business.`,
      `CLAUDE OUTPUT TO REVIEW:\n${claudeOutput}\n\nORIGINAL TASK: ${task}\n\nProvide a structured review: 1) What Claude got right, 2) What needs improvement, 3) Specific suggestions.`
    ),
  ]);

  // Step 3: Claude synthesizes both outputs + reviews into a final recommendation
  const synthesis = await callClaude(
    `You are the synthesis agent for Delzar Solutions LLC's dual-agent AI team. You have two outputs from Manus AI and Claude, plus each agent's review of the other. Synthesize the best elements from both into a single, superior final output. Be decisive and produce a complete, actionable result.`,
    `TASK: ${task}\n\nCLAUDE OUTPUT:\n${claudeOutput}\n\nMANUS OUTPUT:\n${manusOutput}\n\nCLAUDE'S REVIEW OF MANUS:\n${claudeReviewOfManus}\n\nMANUS'S REVIEW OF CLAUDE:\n${manusReviewOfClaude}\n\nProduce the final synthesized output and list 3-5 specific improvements for the next iteration.`
  );

  // Extract improvements from synthesis
  const improvementMatch = synthesis.match(/improvement[s]?[:\s]+([\s\S]+?)(?:\n\n|$)/i);
  const improvements = improvementMatch
    ? improvementMatch[1].split(/\n[-•*\d.]+\s+/).filter(Boolean).slice(0, 5)
    : ["Review synthesis for improvement details"];

  return {
    claudeOutput,
    manusOutput,
    claudeReviewOfManus,
    manusReviewOfClaude,
    synthesis,
    improvements,
  };
}

// ─── CAPABILITY STATEMENT (Claude writes, Manus QA-reviews) ──────────────────
export async function generateCapabilityStatement(params: {
  companyName: string;
  ownerName?: string;
  naicsCodes: string[];
  coreCapabilities: string;
  targetAgency?: string;
  pastPerformance?: string;
  certifications?: string[];
}): Promise<{ statement: string; qaReview: string; finalStatement: string }> {
  const certList = (params.certifications ?? ["Buy Indian Act Eligible (IEE)", "8(a) Candidate"]).join(", ");
  const naicsList = params.naicsCodes.join(", ");

  const taskContext = `
Company: ${params.companyName}
${params.ownerName ? `Owner: ${params.ownerName}` : ""}
NAICS Codes: ${naicsList}
Core Capabilities: ${params.coreCapabilities}
${params.targetAgency ? `Target Agency: ${params.targetAgency}` : ""}
${params.pastPerformance ? `Past Performance: ${params.pastPerformance}` : ""}
Certifications: ${certList}
Contact: dominique@delzarsolutionsllc.com | delzarsolutionsllc.com
  `.trim();

  // Claude writes the initial capability statement
  const statement = await callClaude(
    `You are a senior federal contracting specialist with 20 years of experience writing capability statements for tribal-owned small businesses. You specialize in IHS, BIA, and HHS contracting. Your statements are concise, agency-ready, and powerfully highlight Buy Indian Act statutory advantages. Format: Company Overview → Core Capabilities → Differentiators → Past Performance → Certifications & NAICS → Contact. Under 500 words. Professional GovCon language.`,
    `Write a professional capability statement for:\n${taskContext}`
  );

  // Manus QA-reviews Claude's statement
  const qaReview = await callManus(
    `You are a GovCon QA specialist reviewing a capability statement written by Claude Anthropic for a Cherokee Nation member-owned federal IT services company. Check for: 1) Accuracy of Buy Indian Act claims, 2) NAICS code relevance, 3) Agency-specific language quality, 4) Missing elements, 5) Competitive positioning. Be specific and actionable.`,
    `CAPABILITY STATEMENT TO REVIEW:\n${statement}\n\nCOMPANY CONTEXT:\n${taskContext}\n\nProvide QA feedback and a revised/improved version if needed.`
  );

  // Claude incorporates Manus QA feedback for the final version
  const finalStatement = await callClaude(
    `You are finalizing a capability statement based on QA feedback. Incorporate the improvements while maintaining professional quality. Output ONLY the final capability statement, no commentary.`,
    `ORIGINAL STATEMENT:\n${statement}\n\nQA FEEDBACK FROM MANUS:\n${qaReview}\n\nProduce the final improved capability statement.`
  );

  return { statement, qaReview, finalStatement };
}

// ─── OPPORTUNITY ANALYZER (Claude scores, Manus validates) ───────────────────
export async function analyzeOpportunity(opportunity: {
  title: string;
  description: string;
  agency: string;
  naics?: string;
  value?: string;
  deadline?: string;
  setAside?: string;
}): Promise<{
  claudeScore: number;
  claudeAnalysis: string;
  manusValidation: string;
  recommendation: string;
  actionItems: string[];
}> {
  const oppText = `
Title: ${opportunity.title}
Agency: ${opportunity.agency}
NAICS: ${opportunity.naics ?? "Not specified"}
Estimated Value: ${opportunity.value ?? "Not specified"}
Deadline: ${opportunity.deadline ?? "Not specified"}
Set-Aside: ${opportunity.setAside ?? "Full and Open"}
Description: ${opportunity.description}
  `.trim();

  const delzarProfile = `
Delzar Solutions LLC is a Cherokee Nation member-owned federal IT services company.
NAICS: 541511, 541512, 541519, 541611, 541618
Certifications: Buy Indian Act Eligible (IEE), 8(a) Candidate
Location: Oklahoma (Tulsa)
Specialties: Federal IT services, GovCon strategy, tribal procurement intelligence
SAM.gov UEI: TKMXZNCBPS27
  `.trim();

  // Claude scores and analyzes
  const claudeAnalysis = await callClaude(
    `You are a federal procurement analyst specializing in tribal business opportunities. Score opportunities 1-10 for fit with the given company profile. Consider: Buy Indian Act eligibility, NAICS alignment, agency relationship, competitive position, and win probability. Be specific and data-driven.`,
    `OPPORTUNITY:\n${oppText}\n\nCOMPANY PROFILE:\n${delzarProfile}\n\nProvide: 1) Score (1-10), 2) Why this is/isn't a good fit, 3) Key risks, 4) Win strategy if pursuing. Start your response with "SCORE: X/10"`
  );

  // Extract score
  const scoreMatch = claudeAnalysis.match(/SCORE:\s*(\d+)/i);
  const claudeScore = scoreMatch ? parseInt(scoreMatch[1]) : 5;

  // Manus validates Claude's analysis
  const manusValidation = await callManus(
    `You are validating an opportunity analysis produced by Claude Anthropic for Delzar Solutions LLC. Check for: accuracy of Buy Indian Act applicability, realistic win probability assessment, completeness of risk analysis, and quality of strategic recommendations. Agree, disagree, or refine Claude's analysis.`,
    `CLAUDE'S ANALYSIS:\n${claudeAnalysis}\n\nOPPORTUNITY:\n${oppText}\n\nCOMPANY PROFILE:\n${delzarProfile}\n\nValidate and refine the analysis.`
  );

  // Synthesize recommendation
  const recommendation = await callClaude(
    `Based on two AI analyses of this federal opportunity, provide a single clear GO/NO-GO recommendation with 3 specific action items if GO. Be decisive.`,
    `CLAUDE ANALYSIS:\n${claudeAnalysis}\n\nMANUS VALIDATION:\n${manusValidation}\n\nProvide: GO or NO-GO, reason in one sentence, and if GO: 3 specific action items.`
  );

  const actionItems = recommendation
    .split(/\n[-•*\d.]+\s+/)
    .filter((line) => line.length > 10)
    .slice(1, 4);

  return { claudeScore, claudeAnalysis, manusValidation, recommendation, actionItems };
}

// ─── STRATEGY ADVISOR (both agents strategize together) ──────────────────────
export async function generateWeeklyStrategy(context: {
  currentOpportunities: string[];
  recentWins?: string[];
  blockers?: string[];
  timeframe?: string;
}): Promise<{ claudeStrategy: string; manusStrategy: string; jointPlan: string }> {
  const contextText = `
Current Opportunities in Pipeline: ${context.currentOpportunities.join(", ")}
${context.recentWins ? `Recent Wins: ${context.recentWins.join(", ")}` : ""}
${context.blockers ? `Current Blockers: ${context.blockers.join(", ")}` : ""}
Timeframe: ${context.timeframe ?? "Next 7 days"}

Company: Delzar Solutions LLC — Cherokee Nation member-owned federal IT services company
Key Advantage: Buy Indian Act (25 U.S.C. § 47) preference in IHS/BIA contracting
SAM.gov Status: EXPIRING April 27, 2026 — CRITICAL ACTION REQUIRED
Top Target: IHS Tahlequah IT Recompete ($10M+, Q3 2026)
  `.trim();

  const [claudeStrategy, manusStrategy] = await Promise.all([
    callClaude(
      `You are a senior GovCon strategist specializing in tribal business development. You have deep knowledge of the Buy Indian Act, IHS contracting, and federal procurement cycles. Generate a specific, actionable weekly strategy for a Cherokee Nation member-owned federal IT company. Prioritize by ROI and urgency. Be specific — name real programs, agencies, and dollar amounts.`,
      `Generate a weekly GovCon strategy for:\n${contextText}`
    ),
    callManus(
      `You are a federal business development expert and AI orchestration specialist. Generate a weekly action plan for a Cherokee Nation member-owned federal IT company that leverages AI tools, data APIs, and automation to maximize competitive advantage. Focus on execution speed and measurable outcomes.`,
      `Generate a weekly AI-powered GovCon action plan for:\n${contextText}`
    ),
  ]);

  // Joint synthesis
  const jointPlan = await callClaude(
    `You are synthesizing two strategic plans from Claude and Manus AI into a single, superior joint action plan for Delzar Solutions LLC. Take the best elements from both. Format as: Priority Actions (numbered, with owner: Claude/Manus/DJ), Timeline, Expected Outcomes, and Success Metrics.`,
    `CLAUDE STRATEGY:\n${claudeStrategy}\n\nMANUS STRATEGY:\n${manusStrategy}\n\nCreate the joint 7-day action plan.`
  );

  return { claudeStrategy, manusStrategy, jointPlan };
}
