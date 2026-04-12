/**
 * ARIA — AI Research & Intelligence Assistant
 * Live Anthropic streaming chatbot for Delzar Solutions
 * Features: SSE streaming, conversation history, markdown rendering,
 *           floating widget, keyboard accessible, mobile responsive
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { MessageCircle, X, Send, Minimize2, Maximize2, Bot, User, Loader2, RotateCcw } from "lucide-react";
import { Streamdown } from "streamdown";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  streaming?: boolean;
}

const WELCOME_MESSAGE: Message = {
  id: "welcome",
  role: "assistant",
  content: `**Hello! I'm ARIA** — your AI Research & Intelligence Assistant from Delzar Solutions.

I specialize in:
- **Buy Indian Act** opportunities and tribal preference strategies
- **Federal procurement** — IHS, BIA, HHS, DoD contracting
- **Capability statements** and SAM.gov registration
- **GovCon strategy** for Cherokee Nation member-owned businesses

⚠️ **Urgent:** Your SAM.gov registration expires **April 27, 2026** — 15 days away.

How can I help you win federal contracts today?`,
};

function generateId() {
  return Math.random().toString(36).slice(2, 9);
}

export default function ARIAChatbot() {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [messages, setMessages] = useState<Message[]>([WELCOME_MESSAGE]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
      setUnreadCount(0);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [isOpen, scrollToBottom]);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // Show unread badge when closed and assistant responds
  useEffect(() => {
    if (!isOpen && messages.length > 1) {
      const lastMsg = messages[messages.length - 1];
      if (lastMsg.role === "assistant" && !lastMsg.streaming) {
        setUnreadCount((c) => c + 1);
      }
    }
  }, [messages, isOpen]);

  const sendMessage = useCallback(async () => {
    const text = input.trim();
    if (!text || isStreaming) return;

    // Abort any ongoing stream
    abortRef.current?.abort();
    abortRef.current = new AbortController();

    const userMsg: Message = { id: generateId(), role: "user", content: text };
    const assistantId = generateId();
    const assistantMsg: Message = { id: assistantId, role: "assistant", content: "", streaming: true };

    setMessages((prev) => [...prev, userMsg, assistantMsg]);
    setInput("");
    setIsStreaming(true);

    // Build conversation history for API
    const history = [...messages, userMsg].map((m) => ({
      role: m.role,
      content: m.content,
    }));

    try {
      const response = await fetch("/api/chat/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: history }),
        signal: abortRef.current.signal,
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      if (!response.body) throw new Error("No response body");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let fullContent = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const data = line.slice(6).trim();
          if (!data) continue;

          try {
            const parsed = JSON.parse(data);
            if (parsed.token) {
              fullContent += parsed.token;
              setMessages((prev) =>
                prev.map((m) =>
                  m.id === assistantId ? { ...m, content: fullContent } : m
                )
              );
            } else if (parsed.done) {
              setMessages((prev) =>
                prev.map((m) =>
                  m.id === assistantId ? { ...m, streaming: false } : m
                )
              );
            } else if (parsed.error) {
              throw new Error(parsed.error);
            }
          } catch {
            // Skip malformed JSON
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") return;
      const errorMsg = err instanceof Error ? err.message : "Connection error";
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantId
            ? { ...m, content: `Sorry, I encountered an error: ${errorMsg}. Please try again.`, streaming: false }
            : m
        )
      );
    } finally {
      setIsStreaming(false);
    }
  }, [input, isStreaming, messages]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const clearConversation = () => {
    abortRef.current?.abort();
    setMessages([WELCOME_MESSAGE]);
    setIsStreaming(false);
  };

  return (
    <>
      {/* ── Floating Button ───────────────────────────────── */}
      <button
        onClick={() => { setIsOpen(true); setIsMinimized(false); }}
        className="fixed bottom-6 right-6 z-50 flex items-center gap-2 shadow-2xl transition-all duration-300 hover:scale-105 active:scale-95"
        style={{
          background: "linear-gradient(135deg, oklch(0.72 0.12 75), oklch(0.62 0.10 75))",
          borderRadius: "28px",
          padding: "0.75rem 1.25rem",
          border: "none",
          cursor: "pointer",
          display: isOpen ? "none" : "flex",
        }}
        aria-label="Open ARIA AI Assistant"
      >
        <MessageCircle size={18} style={{ color: "oklch(0.12 0.04 250)" }} />
        <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.75rem", fontWeight: 700, color: "oklch(0.12 0.04 250)", letterSpacing: "0.05em" }}>
          Ask ARIA
        </span>
        {unreadCount > 0 && (
          <span
            className="absolute -top-1.5 -right-1.5 w-5 h-5 flex items-center justify-center rounded-full text-white"
            style={{ background: "oklch(0.65 0.22 27)", fontSize: "0.6rem", fontWeight: 700 }}
          >
            {unreadCount}
          </span>
        )}
      </button>

      {/* ── Chat Window ───────────────────────────────────── */}
      {isOpen && (
        <div
          className="fixed z-50 shadow-2xl flex flex-col"
          style={{
            bottom: "1.5rem",
            right: "1.5rem",
            width: "min(420px, calc(100vw - 2rem))",
            height: isMinimized ? "56px" : "min(600px, calc(100vh - 6rem))",
            background: "oklch(0.12 0.04 250)",
            border: "1px solid oklch(0.72 0.12 75 / 0.25)",
            borderRadius: "8px",
            overflow: "hidden",
            transition: "height 0.3s ease",
          }}
          role="dialog"
          aria-label="ARIA AI Assistant"
          aria-modal="false"
        >
          {/* Header */}
          <div
            className="flex items-center justify-between px-4 py-3 flex-shrink-0"
            style={{
              background: "linear-gradient(135deg, oklch(0.16 0.04 250), oklch(0.14 0.04 250))",
              borderBottom: "1px solid oklch(0.72 0.12 75 / 0.15)",
            }}
          >
            <div className="flex items-center gap-3">
              <div
                className="w-8 h-8 flex items-center justify-center rounded-sm flex-shrink-0"
                style={{ background: "oklch(0.72 0.12 75 / 0.15)" }}
              >
                <Bot size={16} style={{ color: "oklch(0.72 0.12 75)" }} />
              </div>
              <div>
                <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "0.875rem", fontWeight: 700, color: "white", lineHeight: 1 }}>
                  ARIA
                </div>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "oklch(0.65 0.18 145)" }} />
                  <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.6rem", color: "oklch(0.55 0.005 65)", letterSpacing: "0.05em" }}>
                    {isStreaming ? "Thinking..." : "Online · Claude AI"}
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={clearConversation}
                className="w-7 h-7 flex items-center justify-center rounded-sm hover:bg-white/10 transition-colors"
                title="Clear conversation"
                aria-label="Clear conversation"
              >
                <RotateCcw size={13} style={{ color: "oklch(0.55 0.005 65)" }} />
              </button>
              <button
                onClick={() => setIsMinimized(!isMinimized)}
                className="w-7 h-7 flex items-center justify-center rounded-sm hover:bg-white/10 transition-colors"
                aria-label={isMinimized ? "Expand chat" : "Minimize chat"}
              >
                {isMinimized
                  ? <Maximize2 size={13} style={{ color: "oklch(0.55 0.005 65)" }} />
                  : <Minimize2 size={13} style={{ color: "oklch(0.55 0.005 65)" }} />
                }
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="w-7 h-7 flex items-center justify-center rounded-sm hover:bg-white/10 transition-colors"
                aria-label="Close chat"
              >
                <X size={13} style={{ color: "oklch(0.55 0.005 65)" }} />
              </button>
            </div>
          </div>

          {/* Messages */}
          {!isMinimized && (
            <>
              <div
                className="flex-1 overflow-y-auto p-4 flex flex-col gap-4"
                style={{ scrollbarWidth: "thin", scrollbarColor: "oklch(0.25 0.04 250) transparent" }}
              >
                {messages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex gap-2.5 ${msg.role === "user" ? "flex-row-reverse" : "flex-row"}`}
                  >
                    {/* Avatar */}
                    <div
                      className="w-7 h-7 flex items-center justify-center rounded-sm flex-shrink-0 mt-0.5"
                      style={{
                        background: msg.role === "assistant"
                          ? "oklch(0.72 0.12 75 / 0.15)"
                          : "oklch(0.20 0.04 250)",
                      }}
                    >
                      {msg.role === "assistant"
                        ? <Bot size={13} style={{ color: "oklch(0.72 0.12 75)" }} />
                        : <User size={13} style={{ color: "oklch(0.65 0.005 65)" }} />
                      }
                    </div>

                    {/* Bubble */}
                    <div
                      className="max-w-[80%] rounded-sm px-3 py-2.5"
                      style={{
                        background: msg.role === "assistant"
                          ? "oklch(0.16 0.04 250)"
                          : "oklch(0.72 0.12 75 / 0.15)",
                        border: msg.role === "assistant"
                          ? "1px solid oklch(0.72 0.12 75 / 0.1)"
                          : "1px solid oklch(0.72 0.12 75 / 0.3)",
                      }}
                    >
                      {msg.streaming && !msg.content ? (
                        <div className="flex items-center gap-2">
                          <Loader2 size={12} className="animate-spin" style={{ color: "oklch(0.72 0.12 75)" }} />
                          <span style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.8rem", color: "oklch(0.55 0.005 65)" }}>
                            Analyzing...
                          </span>
                        </div>
                      ) : (
                        <div
                          style={{
                            fontFamily: "'IBM Plex Sans', sans-serif",
                            fontSize: "0.825rem",
                            color: msg.role === "assistant" ? "oklch(0.82 0.005 65)" : "oklch(0.90 0.005 65)",
                            lineHeight: 1.6,
                          }}
                          className="chat-markdown"
                        >
                          <Streamdown>{msg.content}</Streamdown>
                          {msg.streaming && (
                            <span
                              className="inline-block w-0.5 h-3.5 ml-0.5 animate-pulse"
                              style={{ background: "oklch(0.72 0.12 75)", verticalAlign: "text-bottom" }}
                            />
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                <div ref={messagesEndRef} />
              </div>

              {/* Input */}
              <div
                className="flex-shrink-0 p-3"
                style={{ borderTop: "1px solid oklch(0.72 0.12 75 / 0.1)" }}
              >
                <div
                  className="flex items-end gap-2 rounded-sm overflow-hidden"
                  style={{
                    background: "oklch(0.16 0.04 250)",
                    border: "1px solid oklch(0.72 0.12 75 / 0.2)",
                  }}
                >
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask about Buy Indian Act, SAM.gov, IHS contracts..."
                    rows={1}
                    disabled={isStreaming}
                    className="flex-1 bg-transparent resize-none px-3 py-2.5 outline-none"
                    style={{
                      fontFamily: "'IBM Plex Sans', sans-serif",
                      fontSize: "0.825rem",
                      color: "white",
                      maxHeight: "120px",
                      minHeight: "40px",
                    }}
                    onInput={(e) => {
                      const el = e.currentTarget;
                      el.style.height = "auto";
                      el.style.height = Math.min(el.scrollHeight, 120) + "px";
                    }}
                    aria-label="Message ARIA"
                  />
                  <button
                    onClick={sendMessage}
                    disabled={!input.trim() || isStreaming}
                    className="flex items-center justify-center w-9 h-9 m-1.5 rounded-sm transition-all duration-200 flex-shrink-0"
                    style={{
                      background: input.trim() && !isStreaming
                        ? "linear-gradient(135deg, oklch(0.72 0.12 75), oklch(0.62 0.10 75))"
                        : "oklch(0.20 0.04 250)",
                      border: "none",
                      cursor: input.trim() && !isStreaming ? "pointer" : "not-allowed",
                    }}
                    aria-label="Send message"
                  >
                    {isStreaming
                      ? <Loader2 size={14} className="animate-spin" style={{ color: "oklch(0.55 0.005 65)" }} />
                      : <Send size={14} style={{ color: input.trim() ? "oklch(0.12 0.04 250)" : "oklch(0.40 0.005 65)" }} />
                    }
                  </button>
                </div>
                <div className="mt-1.5 text-center" style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "0.55rem", color: "oklch(0.35 0.005 65)", letterSpacing: "0.05em" }}>
                  ARIA · Powered by Claude Anthropic · Delzar Solutions LLC
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
}
