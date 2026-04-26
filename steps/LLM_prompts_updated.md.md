
# LLM Prompts — Tool Selection, Verdict + RAG (Singapore-focused)

This document contains the exact prompts (system + user), required JSON schemas, and examples you should paste into your OpenAI ChatCompletion HTTP Request nodes in n8n.

Guidelines
- Use temperature: 0.0–0.2 for deterministic output.
- Always instruct the model to return ONLY valid JSON following the schema.
- If including ChromaDB retrievals, include them in the evidence object as "sources" and ask the model to cite source ids.
- Limit reply length from the model for the user-facing short_reply (<=2 sentences).

1) Tool Selector prompt (decides which MCP tools to run)
System message:
You are a tool-selection agent. Given a short inbound message, detect the minimal set of scanning tools required to safely determine whether the content is malicious. Consider cost/time tradeoffs: prefer lightweight checks (follow_redirects, whois) unless the message has clear indicators of risk (shortened URL, banking request, OTP request, download link). Return ONLY valid JSON with fields: tools (array of tool names), priority ("low"|"normal"|"high"), reason (1-2 sentences). Allowed tools: ["follow_redirects","whois","urlscan","virustotal","ocr","screenshot"].

User message (use this JSON structure; substitute variables):
{
  "message": "{{message_text}}",
  "urls": {{urls_array}},           // array or []
  "media_type": "{{media_type}}",   // "none" | "image" | "document"
  "contains_otp_request": {{true_or_false}},
  "sender_country": "SG"
}

Required JSON response schema:
{
  "tools": ["follow_redirects","whois","urlscan","virustotal","ocr","screenshot"], // subset
  "priority": "low|normal|high",
  "reason": "short 1-2 sentence reason for choice"
}

Examples
- If the message contains a shortened link and urgent bank language:
{
  "tools": ["follow_redirects","whois","urlscan","virustotal"],
  "priority": "high",
  "reason": "Shortened link + bank verification language suggests phishing; run URL analysis + VT + urlscan and domain age."
}

- If the message is text-only asking for general info:
{
  "tools": [],
  "priority": "low",
  "reason": "No URL or media and no credential request; no deep scans needed. Provide general safety advice."
}

2) RAG retrieval prompt (for ChromaDB; used only to fetch sources — not a model prompt)
- Query Chroma with an embedding of the inbound text.
- Request top_k=5; include metadata (id, title, url, chunk).
- Map returned items to:
"sources": [
  { "id": "mas-2023-xyz", "title":"MAS: Phishing advisory", "text":"<chunk text>", "url":"https://..." },
  ...
]
- Attach this "sources" array into the final LLM prompt evidence.

3) Final Verdict + Reply prompt (uses MCP results + RAG sources)
System message:
You are an expert scam analyst serving Singapore residents. Use Singapore context (MAS, ScamShield 7726, Singapore Police Force). Output only valid JSON following the schema below. Keep the short_reply <= 2 sentences, friendly, simple. If uncertain, return "Suspicious" with confidence around 40.

User message (example — provide structured evidence):
{
  "instruction": "Based on the evidence below, produce a verdict, confidence (0-100), recommended actions, a short WhatsApp reply (<=2 sentences) and a short explanation with citations (if sources provided). Return only JSON.",
  "evidence": {
    "text": "{{message_text}}",
    "urls": {{urls}},
    "mcp_results": {{mcp_results}},
    "ocr_text": "{{ocr_text}}",          // optional
    "sources": {{retrieved_sources}}    // optional array of source objects from Chroma
  },
  "policy": {
    "report_to_authorities": false,
    "advice_style": "friendly, Singapore-specific (use examples: 'Do not click', 'You can forward to 7726 (ScamShield)')"
  }
}

Required JSON response schema:
{
  "verdict": "Safe|Suspicious|Malicious",
  "confidence": 0-100,
  "actions": ["ignore","block","report_to_bank","seek_help_spf"],
  "short_reply": "We detected... (<=2 sentences)",
  "explanation": "1-2 sentences with scanner citations (e.g., 'VirusTotal: 17/60 flagged; urlscan shows form requesting credentials')",
  "cited_sources": ["mas-2023-xyz"]  // optional array
}

Examples
- Malicious:
{
  "verdict":"Malicious",
  "confidence": 92,
  "actions":["block","report_to_bank"],
  "short_reply":"This link looks malicious — do NOT click it. You can forward this to 7726 (ScamShield) or contact your bank.",
  "explanation":"VirusTotal: 18/60 flags; urlscan captured a fake bank login form.",
  "cited_sources":["mas-2023-phish-1"]
}

- Suspicious:
{
  "verdict":"Suspicious",
  "confidence": 45,
  "actions":["ignore"],
  "short_reply":"This looks suspicious — avoid clicking the link and do not share any OTPs.",
  "explanation":"Redirects chain shows domain mismatch and domain age < 2 months.",
  "cited_sources":[]
}

4) Tool: If the tool selector returns no tools
- The workflow should skip MCP and generate a short LLM-based reply or use a canned reply:
"Thanks — we reviewed this quickly and it looks like no active URL or credential request. If you want us to investigate further, please forward the message to us or send the link."

5) Prompt engineering tips
- Keep system messages short and prescriptive.
- Provide structured evidence (scanner outputs) rather than raw page HTML.
- Require JSON-only outputs and validate/parse the response in n8n.
- Use low temperature and a deterministic top_p if available.
- Limit token usage with max_tokens; use short models for tool selection.

6) Error handling guidance
- If LLM output is not valid JSON or cannot be parsed, have n8n fallback to:
{ "verdict": "Suspicious", "confidence": 40, "short_reply": "We could not determine safely; please avoid clicking links." }
- Always log LLM outputs and the raw evidence for audits.

7) Example OpenAI ChatCompletions payload (Tool Selector):
POST https://api.openai.com/v1/chat/completions
Headers:
  Authorization: Bearer {{OPENAI_API_KEY}}
  Content-Type: application/json
Body:
{
  "model":"gpt-4o-mini",
  "messages":[
    {"role":"system","content":"You are a tool-selection agent. Return only JSON with fields: tools, priority, reason."},
    {"role":"user","content":"{ \"message\": \"{{message_text}}\", \"urls\": {{urls}}, \"media_type\":\"{{media_type}}\", \"contains_otp_request\": {{contains_otp}} }"}
  ],
  "temperature":0.0,
  "max_tokens":200
}

8) Example OpenAI ChatCompletions payload (Verdict):
POST https://api.openai.com/v1/chat/completions
Headers:
  Authorization: Bearer {{OPENAI_API_KEY}}
Body:
{
  "model":"gpt-4o-mini",
  "messages":[
    {"role":"system","content":"You are an expert scam analyst for Singapore users. Return only JSON as specified."},
    {"role":"user","content": "<insert the evidence JSON composed in the workflow>"}
  ],
  "temperature":0.0,
  "max_tokens":500
}

9) Additional notes
- Ask the LLM to mention 7726 (ScamShield) and ScamShield forwarding if recommending reporting.
- Make sure final short_reply avoids legal commitments (do not auto-report on behalf of user).
- If you include sources, instruct the LLM to include source ids in the explanation.
