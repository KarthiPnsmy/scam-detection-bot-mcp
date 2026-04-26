
# Implementation Steps — Scam & Phishing Detection Copilot (Phase 1 → 3)

This guide steps you through building the system on Railway + n8n (self-hosted n8n: n8nio/n8n:latest). It includes env vars, deployment order, testing steps and checklist.

Summary of phases
- Phase 1: Text + URL detection, LLM tool selection, MCP (selected tools) scanning, LLM verdict, WhatsApp reply.
- Phase 2: Add ChromaDB + RAG (MAS advisories + SMS spam corpus) for evidence-backed replies.
- Phase 3: OCR & screenshot support for images/screenshots; optional Playwright for JS redirects.

Prerequisites
- Railway account with ability to deploy containers/services.
- n8n instance deployed on Railway (you mentioned already deployed).
- Meta BSP (WhatsApp Business) account + phone ID and access token.
- OpenAI account + API key.
- VirusTotal, urlscan, WhoisXMLAPI API keys (optional for Phase 1; recommended).
- Google Vision API key (for OCR) or Tesseract installed on MCP container.
- ChromaDB server (Phase 2) image or host.

Environment variables (set in Railway & n8n)
- For n8n:
  - META_BSP_TOKEN
  - META_PHONE_ID
  - OPENAI_API_KEY
  - N8N_BASE_URL (public webhook base)
  - MCP_BASE_URL
  - CALLBACK_SECRET
  - MCP_API_KEY
  - CHROMA_URL (Phase 2)
  - CHROMA_COLLECTION
  - CHROMA_TOP_K (optional)
- For MCP service:
  - MCP_API_KEY
  - CALLBACK_DEFAULT_SECRET
  - VT_API_KEY
  - URLSCAN_API_KEY
  - WHOIS_API_KEY
  - META_BSP_TOKEN (optional, if MCP should fetch media)
  - GOOGLE_VISION_API_KEY (optional for OCR)

Phase 1 — Build & test
1) Deploy MCP microservice
   - Use the file mcp_microservice_tools.js (Node.js).
   - Create a Railway project, add a service, set Node environment, upload code or link Git repo.
   - Add Railway environment variables (MCP_API_KEY, VT_API_KEY, URLSCAN_API_KEY, etc.)
   - Start the service and ensure /health returns 200.

2) Configure n8n workflow
   - Import the provided n8n JSON (see the importable workflow file).
   - In n8n, create the environment variables (or use Credentials) listed above.
   - Update nodes if needed (Webhook paths, Meta phone ID).

3) Configure Meta BSP webhook
   - Point your Meta webhook (WhatsApp messages) to your n8n public URL:
     https://<your-n8n-base>/webhook/inbound-whatsapp
   - Ensure webhook verification & permissions are set.

4) Test Phase 1
   - Send sample messages from a test number or Meta Sandbox containing:
     - Plain text (no URL)
     - Message with simple URL (http://example.com)
     - Message with shortened link (bit.ly)
   - Observe n8n: tool selector output, MCP /scan call, acknowledgment message to user, and later MCP callback to n8n with final verdict and WhatsApp follow-up.

Phase 1 — Testing & tuning checklist
- Confirm tool selection JSON is valid and includes expected tools.
- Ensure MCP returns callback with X-Callback-Secret header or callback_secret in body and n8n verifies it.
- Confirm OpenAI verdict JSON parses reliably; add fallback if not parseable.
- Check logs for false positives and tune prompts.

Phase 2 — ChromaDB + RAG (adds authoritative citations)
1) Deploy ChromaDB
   - Use Chroma server image or managed provider.
   - Railway can host small Chroma instances; ensure adequate memory (4GB+ recommended for larger corpora).
   - Set CHROMA_URL and CHROMA_COLLECTION in n8n env.

2) Ingest corpus
   - Collect documents: MAS advisories, ScamShield guidance, SPF advisories, curated SMS spam dataset (anonymized).
   - Chunk docs (200–500 tokens), create metadata (id, title, url, source).
   - Create embeddings using OpenAI embeddings (text-embedding-3-small), then insert into Chroma collection (via REST or client).
   - Keep a schedule to refresh or add new advisories.

3) Update n8n workflow
   - The imported workflow includes nodes for embeddings and Chroma query. Enable them and configure CHROMA_URL and CHROMA_COLLECTION.
   - Test retrieval: send message and inspect retrieved sources array included in final model prompt.

Phase 2 — Testing checklist
- Validate relevant MAS advisories are returned for test queries.
- In final verdict, verify model cites source ids in explanation.
- Re-tune prompt to prefer official advisories when recommending reporting.

Phase 3 — OCR & screenshots
1) Enable OCR in MCP
   - Provide META_BSP_TOKEN to MCP so it can fetch media by media_id.
   - Provide GOOGLE_VISION_API_KEY or enable Tesseract in the container.
   - If using Playwright for JS rendering, add Playwright package and necessary dependencies to MCP container; allocate more memory and CPU.

2) Update tool-selection prompt
   - Tool selector can now include "ocr" and "screenshot" when media_type == "image" or when message includes an image.

3) Test OCR pipeline
   - Send screenshot images with clear text and QR codes via WhatsApp.
   - Verify extracted text returned in MCP results, then used by LLM for verdict.

Phase 3 — Testing checklist
- OCR accuracy: verify extracted URLs/phones match screenshot content.
- QR/code extraction: decode QR and pass as URL into MCP pipeline.
- Security: do not auto-download or run unknown attachments; keep malware files in quarantine.

Deployment & hosting notes (Railway)
- n8n:
  - Use a persistent Postgres DB (Railway). Add backups.
  - Ensure public URL for webhooks; configure domain if needed.
- MCP:
  - Small Node container is fine. If you add Playwright/Tesseract, pick a larger plan (more CPU & memory).
- ChromaDB:
  - For small corpora (few thousand chunks) a 4GB container is OK. For larger corpora scale up.
- Secrets:
  - Use Railway environment variables. Never commit keys in code.

Operational tips
- Cache scan results by URL to avoid re-scanning frequently.
- Rate-limit LLM usage — use tool selector to avoid unnecessary scans and LLM calls.
- Keep logs and audit trail for each message (messageId, from, tools requested, verdict, timestamp).
- PDPA: minimize storing PII; ask for consent if you retain content long-term.

Troubleshooting & common issues
- 401 on MCP /scan: check MCP_API_KEY header value in n8n HTTP Request node.
- n8n webhook not reached: verify public URL, firewall, and webhook configuration in Meta BSP.
- OpenAI parse errors: ensure the model returns JSON only; add n8n Function fallback to handle unparsable content.

Appendix — Useful quick commands
- Run MCP locally:
  NODE_ENV=production MCP_API_KEY=xxxx VT_API_KEY=yyyy node mcp_microservice_tools.js
- Health check:
  GET https://<mcp-host>/health
- Example MCP /scan body:
{
  "messageId":"abc",
  "from":"+651234567",
  "text":"Hi click https://bit.ly/abc",
  "urls":["https://bit.ly/abc"],
  "tools":["follow_redirects","urlscan","virustotal"],
  "callback":"https://<n8n-base>/webhook/mcp-callback",
  "callback_secret":"sharedsecret"
}
