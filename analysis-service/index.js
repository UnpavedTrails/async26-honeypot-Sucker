require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const { GoogleGenAI, Type } = require('@google/genai');

const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '10000', 10);

// Service role key: same trusted, server-side-only pattern as the honeypot
// backend. This service needs more than the honeypot though - it has to
// SELECT and UPDATE raw_logs, and INSERT into analysis, none of which the
// restricted `anon` key (used later by the dashboard) is allowed to do.
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

// This schema is what makes the output reliable: Gemini is constrained to
// return exactly this shape, so there's no JSON.parse() gambling and no
// prompting-and-praying for well-formed output.
const ANALYSIS_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    intent_label: {
      type: Type.STRING,
      enum: ['recon', 'credential-stuffing', 'injection-attempt', 'vulnerability-scan', 'benign']
    },
    severity_score: { type: Type.INTEGER },
    narration: { type: Type.STRING },
    recommended_action: { type: Type.STRING }
  },
  required: ['intent_label', 'severity_score', 'narration', 'recommended_action']
};

function buildPrompt(sessionId, logs) {
  const lines = logs.map((log, i) => (
    `[${i + 1}] ${log.timestamp} - ${log.method} ${log.path}\n` +
    `  IP: ${log.ip_address}\n` +
    `  User-Agent: ${log.user_agent}\n` +
    `  Body: ${JSON.stringify(log.body)}`
  )).join('\n\n');

  return `You are a security analyst reviewing activity on a honeypot decoy server. Below is a sequence of requests from one visitor session (session ID: ${sessionId}). None of this is real production traffic - this server exists only to attract and log this activity. Analyze the sequence as a whole, not each request in isolation, and determine what this visitor is likely doing.

Requests in this session:
${lines}

Classify the intent, rate severity from 1 (clearly benign/harmless) to 5 (active, aggressive attack), write a short plain-English explanation of what's happening and why, and recommend one concrete response action.`;
}

// Gemini's API has documented, ongoing "high demand" 503 errors that can hit
// one specific model while others stay healthy. Trying a short list of
// current-generation models in sequence meaningfully improves the odds of
// getting a response, without needing to wait a full poll cycle to retry.
const MODEL_CANDIDATES = ['gemini-3.8-flash', 'gemini-3-flash-preview', 'gemini-3.1-flash-lite'];

async function generateWithFallback(prompt) {
  let lastError;
  for (const model of MODEL_CANDIDATES) {
    try {
      return await ai.models.generateContent({
        model,
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          responseSchema: ANALYSIS_SCHEMA
        }
      });
    } catch (err) {
      lastError = err;
      console.warn(`[model fallback] ${model} unavailable, trying next candidate...`);
    }
  }
  throw lastError;
}

async function analyzeSession(sessionId, logs) {
  const prompt = buildPrompt(sessionId, logs);

  const response = await generateWithFallback(prompt);

  const result = JSON.parse(response.text);

  const { error: insertError } = await supabase.from('analysis').insert([{
    session_id: sessionId,
    intent_label: result.intent_label,
    severity_score: result.severity_score,
    narration: result.narration,
    recommended_action: result.recommended_action
  }]);
  if (insertError) throw new Error(`insert failed: ${insertError.message}`);

  const ids = logs.map((l) => l.id);
  const { error: updateError } = await supabase
    .from('raw_logs')
    .update({ analyzed: true })
    .in('id', ids);
  if (updateError) throw new Error(`mark-analyzed failed: ${updateError.message}`);

  console.log(`[analyzed] session ${sessionId}: ${result.intent_label} (severity ${result.severity_score})`);
}

async function pollOnce() {
  const { data: logs, error } = await supabase
    .from('raw_logs')
    .select('id, session_id, ip_address, timestamp, method, path, body, user_agent')
    .eq('analyzed', false)
    .order('timestamp', { ascending: true });

  if (error) {
    console.error('[poll error]', error.message);
    return;
  }
  if (!logs || logs.length === 0) return;

  // Group unanalyzed rows by session, so each attacker "session" gets
  // analyzed as one sequence rather than as isolated, context-free requests.
  const sessions = {};
  for (const log of logs) {
    (sessions[log.session_id] ||= []).push(log);
  }

  for (const [sessionId, sessionLogs] of Object.entries(sessions)) {
    try {
      await analyzeSession(sessionId, sessionLogs);
    } catch (err) {
      // Left as analyzed=false on purpose - a failed call (network hiccup,
      // rate limit, etc.) just gets retried automatically on the next poll,
      // instead of silently losing that batch.
      console.error(`[analysis error] session ${sessionId}:`, err.message);
    }
  }
}

console.log(`Analysis service started. Polling every ${POLL_INTERVAL_MS / 1000}s...`);
pollOnce();
setInterval(pollOnce, POLL_INTERVAL_MS);
