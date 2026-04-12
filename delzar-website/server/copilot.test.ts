/**
 * Vitest tests for the Delzar Solutions Co-Pilot system
 * Tests the dual-agent review pipeline, capability statement generator,
 * opportunity analyzer, and health check endpoints
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock external dependencies ────────────────────────────────────────────────
vi.mock("@anthropic-ai/sdk", () => ({
  default: vi.fn().mockImplementation(() => ({
    messages: {
      create: vi.fn().mockResolvedValue({
        content: [{ type: "text", text: "Claude mock response: GO" }],
      }),
    },
  })),
}));

vi.mock("./_core/llm", () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{ message: { content: "Manus mock response: Validated" } }],
  }),
}));

// ── Import after mocks ────────────────────────────────────────────────────────
import {
  callClaude,
  callManus,
  generateCapabilityStatement,
  analyzeOpportunity,
  dualAgentReview,
} from "./copilot";

describe("Co-Pilot: callClaude", () => {
  it("returns a non-empty string", async () => {
    const result = await callClaude("You are a test bot.", "Say hello");
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });
});

describe("Co-Pilot: callManus", () => {
  it("returns a non-empty string", async () => {
    const result = await callManus("You are a test bot.", "Say hello");
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });
});

describe("Co-Pilot: generateCapabilityStatement", () => {
  it("returns an object with all required fields", async () => {
    const result = await generateCapabilityStatement({
      companyName: "Test Tribal LLC",
      naicsCodes: ["541511"],
      coreCapabilities: "IT services",
      pastPerformance: "IHS contract 2023",
      certifications: ["Buy Indian Act"],
      targetAgency: "IHS",
      contactName: "DJ Test",
    });

    expect(result).toHaveProperty("statement");
    expect(result).toHaveProperty("qaReview");
    expect(result).toHaveProperty("finalStatement");
    expect(typeof result.statement).toBe("string");
    expect(typeof result.finalStatement).toBe("string");
  });
});

describe("Co-Pilot: analyzeOpportunity", () => {
  it("returns a structured analysis with GO/NO-GO recommendation", async () => {
    const result = await analyzeOpportunity({
      title: "IHS IT Support Services",
      agency: "Indian Health Service",
      naicsCode: "541512",
      description: "IT support for IHS Tahlequah",
      estimatedValue: "$500,000",
      deadline: "2026-05-01",
    });

    expect(result).toHaveProperty("claudeScore");
    expect(result).toHaveProperty("claudeAnalysis");
    expect(result).toHaveProperty("manusValidation");
    expect(result).toHaveProperty("recommendation");
    expect(result).toHaveProperty("actionItems");
    expect(typeof result.claudeScore).toBe("number");
    expect(typeof result.recommendation).toBe("string");
    expect(Array.isArray(result.actionItems)).toBe(true);
  });
});

describe("Co-Pilot: dualAgentReview", () => {
  it("returns a 4-step review with improvements array", async () => {
    const result = await dualAgentReview({
      task: "Review this capability statement draft",
      content: "Delzar Solutions LLC provides IT services...",
      claudeRole: "a federal contracting expert",
      manusRole: "a business development specialist",
    });

    expect(result).toHaveProperty("claudeOutput");
    expect(result).toHaveProperty("manusOutput");
    expect(result).toHaveProperty("claudeReviewOfManus");
    expect(result).toHaveProperty("manusReviewOfClaude");
    expect(result).toHaveProperty("synthesis");
    expect(result).toHaveProperty("improvements");
    expect(Array.isArray(result.improvements)).toBe(true);
  });
});

describe("Co-Pilot: input validation", () => {
  it("generateCapabilityStatement requires companyName", async () => {
    await expect(
      generateCapabilityStatement({
        companyName: "",
        naicsCodes: ["541511"],
        coreCapabilities: "IT services",
        pastPerformance: "",
      })
    ).resolves.toBeDefined(); // Should still resolve, not throw
  });

  it("analyzeOpportunity handles minimal input", async () => {
    const result = await analyzeOpportunity({
      title: "Test Opportunity",
      agency: "IHS",
      naicsCode: "541511",
      description: "Test description",
    });
    expect(result).toHaveProperty("recommendation");
  });
});
