/**
 * Delzar Solutions — Live Anthropic Streaming Chat
 * Real-time SSE endpoint using Claude claude-3-5-sonnet-20241022
 * GovCon assistant persona: ARIA (AI Research & Intelligence Assistant)
 */
import Anthropic from "@anthropic-ai/sdk";
import { Request, Response } from "express";

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

const ARIA_SYSTEM_PROMPT = `You are ARIA — the AI Research & Intelligence Assistant for Delzar Solutions LLC, a Cherokee Nation member-owned federal IT services company based in Oklahoma.

Your expertise:
- Federal procurement and government contracting (GovCon)
- Buy Indian Act (25 U.S.C. § 47) — tribal preference in IHS and BIA contracting
- SAM.gov registration, NAICS codes, and set-aside programs
- Indian Health Service (IHS) contracting and recompetes
- 8(a) Business Development Program
- Capability statements and past performance narratives
- IDIQ vehicles, GSA schedules, and teaming arrangements
- Cherokee Federal and tribal prime contractor relationships
- Federal IT services: NAICS 541511, 541512, 541519, 541611, 541618

Delzar Solutions key facts:
- Owner: Dominique Delzar (Cherokee Nation member)
- Email: dominique@delzarsolutionsllc.com
- Services: Federal IT, capability statements, Buy Indian Act compliance, GovCon strategy, tribal vendor matchmaking
- Platform: AI-powered procurement intelligence at $99/month
- Key opportunity: IHS Tahlequah IT Recompete ($10M+, Q3 2026)
- SAM.gov registration expires April 27, 2026 — URGENT renewal needed

Personality: Professional, authoritative, direct. You speak like a senior federal contracting officer who deeply understands tribal business. You give specific, actionable advice — not generic platitudes. You cite specific regulations, dollar amounts, and deadlines when relevant.

Response format: Use markdown for structure when helpful. Keep responses concise and actionable. If asked about pricing or services, direct to dominique@delzarsolutionsllc.com or the contact form.`;

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export async function handleChatStream(req: Request, res: Response) {
  // Set SSE headers
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const { messages, sessionId } = req.body as {
    messages: ChatMessage[];
    sessionId?: string;
  };

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    res.write(`data: ${JSON.stringify({ error: "No messages provided" })}\n\n`);
    res.end();
    return;
  }

  // Sanitize and limit messages
  const sanitized = messages
    .slice(-20) // Keep last 20 messages for context
    .map((m) => ({
      role: m.role as "user" | "assistant",
      content: String(m.content).slice(0, 4000),
    }));

  try {
    const stream = await anthropic.messages.stream({
      model: "claude-3-5-sonnet-20241022",
      max_tokens: 1024,
      system: ARIA_SYSTEM_PROMPT,
      messages: sanitized,
    });

    // Stream tokens as SSE events
    for await (const chunk of stream) {
      if (chunk.type === "content_block_delta" && chunk.delta.type === "text_delta") {
        const text = chunk.delta.text;
        res.write(`data: ${JSON.stringify({ token: text })}\n\n`);
      }
    }

    // Send done signal
    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Stream error";
    console.error("[Chat SSE Error]", message);
    res.write(`data: ${JSON.stringify({ error: message })}\n\n`);
    res.end();
  }
}

export async function handleChatHealth(_req: Request, res: Response) {
  res.json({ status: "ok", model: "claude-3-5-sonnet-20241022", assistant: "ARIA" });
}
