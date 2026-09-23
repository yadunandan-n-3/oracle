"use client";

import { useState, useRef, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { askCopilot, listMissions } from "@/lib/api";
import Layout from "@/components/layout/Layout";
import { Bot, Send, User, RefreshCw, Lightbulb } from "lucide-react";

const SUGGESTED_QUESTIONS = [
  "What is my highest-risk asset?",
  "Show me critical findings",
  "What should I patch first?",
  "Show me the attack path",
  "Give me an executive summary",
  "What is my risk breakdown?",
];

interface Message {
  role: "user" | "assistant";
  content: string;
  sources?: string[];
  suggestedQuestions?: string[];
}

export default function CopilotPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content:
        "Hello! I'm the ORACLE AI Security Analyst. I can help you understand your security posture, analyze findings, and recommend actions. What would you like to know?",
      suggestedQuestions: SUGGESTED_QUESTIONS,
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState("");
  const [selectedMission, setSelectedMission] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const { data: missions } = useQuery({
    queryKey: ["missions"],
    queryFn: () => listMissions({ limit: 50 }),
  });

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async (question: string) => {
    if (!question.trim() || loading) return;

    const userMessage: Message = { role: "user", content: question };
    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setLoading(true);

    try {
      const response = await askCopilot({
        question: question.trim(),
        mission_id: selectedMission || undefined,
        conversation_id: conversationId || undefined,
      });

      setConversationId(response.conversation_id);

      const assistantMessage: Message = {
        role: "assistant",
        content: response.answer,
        sources: response.sources,
        suggestedQuestions: response.suggested_questions,
      };
      setMessages((prev) => [...prev, assistantMessage]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "I encountered an error processing your request. Please try again.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout>
      <div className="p-6 h-[calc(100vh-4rem)] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-2xl font-bold text-white">AI Security Analyst</h1>
            <p className="text-sm text-slate-500 mt-1">
              Ask questions about your security posture
            </p>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={selectedMission}
              onChange={(e) => setSelectedMission(e.target.value)}
              className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-white focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
            >
              <option value="">All Missions</option>
              {(missions || []).map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
            </select>
            <button
              onClick={() => {
                setMessages([
                  {
                    role: "assistant",
                    content:
                      "Hello! I'm the ORACLE AI Security Analyst. I can help you understand your security posture, analyze findings, and recommend actions. What would you like to know?",
                    suggestedQuestions: SUGGESTED_QUESTIONS,
                  },
                ]);
                setConversationId("");
              }}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Chat Messages */}
        <div className="flex-1 overflow-y-auto space-y-4 mb-4">
          {messages.map((msg, idx) => (
            <div key={idx} className="flex gap-3">
              <div
                className={`flex-shrink-0 h-8 w-8 rounded-full flex items-center justify-center ${
                  msg.role === "assistant"
                    ? "bg-emerald-500/20"
                    : "bg-blue-500/20"
                }`}
              >
                {msg.role === "assistant" ? (
                  <Bot className="h-4 w-4 text-emerald-400" />
                ) : (
                  <User className="h-4 w-4 text-blue-400" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div
                  className={`rounded-xl p-4 ${
                    msg.role === "assistant"
                      ? "bg-slate-900 border border-slate-800"
                      : "bg-blue-500/10 border border-blue-500/20"
                  }`}
                >
                  <div className="text-sm text-slate-300 whitespace-pre-wrap leading-relaxed">
                    {msg.content}
                  </div>

                  {msg.sources && msg.sources.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-slate-800">
                      <p className="text-xs text-slate-500 mb-1">Sources:</p>
                      <div className="flex flex-wrap gap-1.5">
                        {msg.sources.map((s, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 bg-slate-800 rounded text-xs text-slate-400"
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {msg.suggestedQuestions && msg.suggestedQuestions.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-slate-800">
                      <p className="text-xs text-slate-500 mb-2">
                        Suggested follow-ups:
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {msg.suggestedQuestions.map((q, i) => (
                          <button
                            key={i}
                            onClick={() => handleSend(q)}
                            className="flex items-center gap-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs text-slate-300 transition-colors"
                          >
                            <Lightbulb className="h-3 w-3 text-yellow-400" />
                            {q}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex gap-3">
              <div className="flex-shrink-0 h-8 w-8 rounded-full bg-emerald-500/20 flex items-center justify-center">
                <Bot className="h-4 w-4 text-emerald-400" />
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <RefreshCw className="h-3 w-3 animate-spin" />
                  Analyzing...
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-3">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend(input);
            }}
            className="flex items-center gap-3"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about risks, findings, assets, or attack paths..."
              className="flex-1 bg-transparent text-sm text-white placeholder-slate-500 focus:outline-none"
              disabled={loading}
            />
            <button
              type="submit"
              disabled={!input.trim() || loading}
              className="p-2 bg-emerald-500 hover:bg-emerald-600 disabled:bg-emerald-500/50 rounded-lg transition-colors"
            >
              <Send className="h-4 w-4 text-white" />
            </button>
          </form>
        </div>
      </div>
    </Layout>
  );
}
