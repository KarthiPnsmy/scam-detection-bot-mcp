
/*
mcp_agent.js

MCP microservice with tool manifest + dynamic agent (OpenAI function-calling) support.

Features:
- GET /tools                  -> return available tool manifest (name, description, inputSchema)
- POST /invoke                -> execute a single tool with given input (sync)
- POST /scan                  -> legacy/simple endpoint (accepts tools list and runs them async)
- POST /agent                 -> start an asynchronous "agent" run:
                                - uses OpenAI chat completions with function definitions (tools)
                                - loops: LLM asks to call a tool -> MCP executes tool -> returns result as function response
                                - LLM can request more tools until final answer is returned
                                - final consolidated results are POSTed back to the callback URL provided in the request
- GET /scan/:id               -> debug status

Usage (env vars - set in Railway):
- PORT (optional)
- MCP_API_KEY                 -> expected Bearer token for incoming /scan /agent /invoke requests
- CALLBACK_DEFAULT_SECRET     -> fallback secret header for callbacks
- OPENAI_API_KEY              -> required to run the agent (or set to empty if you want to only use /invoke)
- VT_API_KEY
- URLSCAN_API_KEY
- WHOIS_API_KEY
- META_BSP_TOKEN
- GOOGLE_VISION_API_KEY

NOTES:
- This is a POC. For production: add persistent storage (DB) for scans, better retry/backoff, robust error handling and rate-limits.
- The agent uses OpenAI function calling pattern. It relies on OPENAI_API_KEY.
*/

const express = require('express');
const axios = require('axios');
const got = require('got');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log4js = require('log4js'); // Import log4js
const { log } = require('console');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '10mb' }));

// Configure log4js
// log4js.configure({
//   appenders: {
//     console: { type: 'console' },
//     file: { type: 'file', filename: 'logs/mcp_agent.log' }
//   },
//   categories: {
//     default: { appenders: ['console', 'file'], level: 'debug' }
//   }
// });

// Configure log4js
log4js.configure({
  appenders: {
    console: { 
      type: 'console', 
      layout: {
        type: 'pattern',
        pattern: '[%d] [%p] [%c] %f{1}:%l - %m'
      }
    },
    file: { 
      type: 'dateFile', // Use dateFile appender for log rotation
      filename: 'logs/mcp_agent.log',
      pattern: 'yyyy-MM-dd', // Rotate logs daily
      keepFileExt: true, // Keep the .log extension for rotated files
      compress: true, // Compress rotated log files
      layout: {
        type: 'pattern',
        pattern: '[%d] [%p] [%c] %f{1}:%l - %m'
      }
    }
  },
  categories: {
    default: { appenders: ['console', 'file'], level: 'debug', enableCallStack: true }
  }
});

const logger = log4js.getLogger();

// Middleware to add request ID and timestamp to each request
app.use((req, res, next) => {
  req.requestId = uuidv4();
  req.startTime = new Date();
  logger.info(`[${req.requestId}] Incoming request: ${req.method} ${req.url}`);
  next();
});

// Config
const PORT = process.env.PORT || 3000;
const MCP_API_KEY = process.env.MCP_API_KEY || '';
const CALLBACK_DEFAULT_SECRET = process.env.CALLBACK_DEFAULT_SECRET || 'changeme';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const VT_API_KEY = process.env.VT_API_KEY || '';
const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY || '';
const WHOIS_API_KEY = process.env.WHOIS_API_KEY || '';
const META_BSP_TOKEN = process.env.META_BSP_TOKEN || '';
const GOOGLE_VISION_API_KEY = process.env.GOOGLE_VISION_API_KEY || '';

// In-memory store for POC
const scans = new Map();

// Tool manifest (exposed via /tools)
// Each tool includes: name, description, inputSchema (JSON Schema for validation)
const TOOL_MANIFEST = [
  {
    name: 'follow_redirects',
    description: 'Follow redirects for a URL and return the redirect chain, final URL, status code and content-type.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', format: 'uri' },
        timeout_ms: { type: 'integer' }
      },
      required: ['url']
    }
  },
  // {
  //   name: 'whois',
  //   description: 'Fetch WHOIS / domain registration info and creation date (via a WHOIS API).',
  //   inputSchema: {
  //     type: 'object',
  //     properties: {
  //       domain: { type: 'string' }
  //     },
  //     required: ['domain']
  //   }
  // },
  {
    name: 'urlscan',
    description: 'Submit a URL to urlscan.io and poll for result (returns snapshot JSON).',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', format: 'uri' },
        visibility: { type: 'string', enum: ['public', 'private'] }
      },
      required: ['url']
    }
  },
  {
    name: 'virustotal',
    description: 'Lookup or submit a URL to VirusTotal and return analysis summary.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', format: 'uri' }
      },
      required: ['url']
    }
  },
  {
    name: 'ocr',
    description: 'Fetch media from Meta (media_id) and perform OCR (Google Vision or Tesseract fallback).',
    inputSchema: {
      type: 'object',
      properties: {
        media_id: { type: 'string' }
      },
      required: ['media_id']
    }
  }
];

// Simple middleware for MCP_API_KEY protection
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!MCP_API_KEY) return next(); // open if no key configured
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing bearer token...' });
  const token = auth.split(' ')[1];
  if (token !== MCP_API_KEY) return res.status(403).json({ error: 'Invalid token' });
  return next();
}

// Helper short wait
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

/* --------------------
   Tool implementations
   -------------------- */

async function followRedirectsTool(req, input) {
  logger.info(`[${req.requestId}] followRedirectsTool input: ${JSON.stringify(input)}`);
  const url = input.url;
  try {
    const redirectChain = [];
    const response = await got(url, {
      method: 'GET',
      throwHttpErrors: false,
      followRedirect: true,
      maxRedirects: 10,
      timeout: { request: input.timeout_ms || 15000 },
      hooks: {
        beforeRedirect: [
          (options, response) => {
            redirectChain.push({
              from: response.url || null,
              to: response.headers.location || options.href,
              statusCode: response.statusCode
            });
          }
        ]
      }
    });

    logger.info(`[${req.requestId}] followRedirectsTool response: ${{
      url,
      finalUrl: response.url || url,
      statusCode: response.statusCode,
      redirectChain,
      contentType: response.headers['content-type'] || null,
      length: response.rawBody ? response.rawBody.length : null
    }}`);

    return {
      url,
      finalUrl: response.url || url,
      statusCode: response.statusCode,
      redirectChain,
      contentType: response.headers['content-type'] || null,
      length: response.rawBody ? response.rawBody.length : null
    };
  } catch (err) {
    logger.error(`[${req.requestId}] followRedirectsTool error for URL ${url}: ${err.message}`);
    return { url, error: String(err) };
  }
}

// NOT AVAILABLE IN FREE TIER
// async function whoisTool(input) {
//   if (!WHOIS_API_KEY) return { note: 'no whois api key configured' };
//   try {
//     const domain = input.domain;
//     const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOIS_API_KEY}&domainName=${encodeURIComponent(domain)}&outputFormat=JSON`;
//     const r = await axios.get(url, { timeout: 15000 });
//     const res = r.data;
//     const creation = res.WhoisRecord ? res.WhoisRecord.createdDate : null;
//     const registrar = res.WhoisRecord ? res.WhoisRecord.registrarName : null;
//     return { domain, creationDate: creation, registrar };
//   } catch (err) {
//     return { domain: input.domain, error: String(err) };
//   }
// }

// async function urlscanTool(input) {
//   if (!URLSCAN_API_KEY) return { note: 'no urlscan api key configured' };
//   try {
//     const submit = await axios.post('https://urlscan.io/api/v1/scan/', {
//       url: input.url,
//       visibility: input.visibility || 'public'
//     }, {
//       headers: { 'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json' },
//       timeout: 15000
//     });

//     const uuid = submit.data.uuid;
//     // Poll
//     for (let i = 0; i < 12; i++) {
//       await wait(2000);
//       try {
//         const res = await axios.get(`https://urlscan.io/api/v1/result/${uuid}/`, { timeout: 15000 });
//         if (res && res.data) return { url: input.url, uuid, result: res.data };
//       } catch (err) {
//         // continue
//       }
//     }
//     return { url: input.url, uuid, note: 'timed out polling urlscan' };
//   } catch (err) {
//     return { url: input.url, error: String(err) };
//   }
// }

const extractScanSummary = (apiResponse) => {
  // Basic extraction with fallback values to prevent "undefined" errors
  const { task = {}, page = {}, verdicts = {}, lists = {} } = apiResponse;

  return {
      taskUrl: task.url,
      finalUrl: page.url,
      domainAge: page.apexDomainAgeDays || "Unknown",
      tlsIssuer: page.tlsIssuer || "None",
      rank: page.umbrellaRank || "Unranked",
      brands: verdicts.urlscan?.brands?.map(b => b.name) || [],
      riskScore: verdicts.engines?.score || 0
      // Optional: limit to first 10 URLs to save tokens
      //sampleRequests: (lists.urls || []).slice(0, 10)
  };
};

async function urlscanTool(req, input) {
  logger.info(`[${req.requestId}] Starting urlscanTool with input: ${input}`);
  if (!URLSCAN_API_KEY) {
    logger.error(`[${req.requestId}] URLSCAN_API_KEY is not configured`);
    return { note: 'no urlscan api key configured' };
  }

  try {
    logger.info(`[${req.requestId}] Submitting URL to urlscan.io: ${input.url}`);
    const submit = await axios.post(
      'https://urlscan.io/api/v1/scan/',
      {
        url: input.url,
        visibility: input.visibility || 'public'
      },
      {
        headers: { 'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json' },
        timeout: 15000
      }
    );

    logger.info(`[${req.requestId}] urlscan.io submission response: ${JSON.stringify(submit.data)}`);
    const uuid = submit.data.uuid;
    logger.info(`[${req.requestId}] Polling for urlscan.io results with UUID: ${uuid}`);

    // Poll
    for (let i = 0; i < 10; i++) {
      await wait(5000);
      try {
        logger.info(`[${req.requestId}] Polling attempt ${i + 1} for UUID: ${uuid}`);
        const res = await axios.get(`https://urlscan.io/api/v1/result/${uuid}/`, { timeout: 15000 });
        logger.info(`[${req.requestId}] Polling response for attempt ${i + 1}: HTTP status : ${res.status} , statusText: ${res.statusText}`);
        if (res && res.data) {
          logger.info(`[${req.requestId}] Polling successful for UUID: ${uuid}. Extracting summary...`);
          logger.info(`[${req.requestId}] Extracting scan summary from urlscan.io result for UUID: ${uuid}`);
          const summary = extractScanSummary(res.data);
          logger.info(`[${req.requestId}] Extracted scan summary for UUID: ${uuid}: ${JSON.stringify(summary)}`);

          return { url: input.url, uuid, result: summary };
        }
      } catch (err) {
        logger.error(`[${req.requestId}] Polling attempt ${i + 1} failed for UUID: ${uuid}: ${err.message}`);
      }
    }

    logger.warn(`[${req.requestId}] Polling timed out for urlscan.io UUID: ${uuid}`);
    return { url: input.url, uuid, note: 'timed out polling urlscan' };
  } catch (err) {
    logger.error(`[${req.requestId}] Error during urlscanTool execution for URL ${input.url}: ${err.message}`);
    return { url: input.url, error: String(err) };
  }
}

function simplifyVTResponse(vtJson) {
  const attr = vtJson.data?.attributes || {};
  const results = attr.last_analysis_results || {};

  // Filter for only engines that flagged the item
  const detections = Object.entries(results)
      .filter(([_, details]) => ['malicious', 'suspicious'].includes(details.category))
      .map(([engine, details]) => `${engine}: ${details.result}`);

  return {
      summary: attr.last_analysis_stats,
      reputation: attr.reputation,
      detections: detections,
      context: {
          url: attr.url || attr.host_name,
          title: attr.title,
          categories: attr.categories,
          // Convert unix timestamp to readable date
          first_seen: attr.first_submission_date 
              ? new Date(attr.first_submission_date * 1000).toISOString().split('T')[0] 
              : 'Unknown',
          tags: attr.tags || []
      }
  };
}

async function virustotalTool(req, input) {
  console.log('Starting virustotalTool with input:', input);
  logger.info(`[${req.requestId}] Starting virustotalTool with input: ${input}`);

  if (!VT_API_KEY) return { note: 'no virustotal api key configured' };
  try {
    const urlStr = input.url;
    const encoded = Buffer.from(urlStr).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const lookupUrl = `https://www.virustotal.com/api/v3/urls/${encoded}`;

    try {
      logger.info(`[${req.requestId}] Attempting initial lookup for URL in VirusTotal: ${urlStr}`);
      const lookup = await axios.get(lookupUrl, { headers: { 'x-apikey': VT_API_KEY }, timeout: 15000 });
      logger.info(`[${req.requestId}] Initial VirusTotal lookup response status: ${lookup.status}, statusText: ${lookup.statusText}`);

      const simplifiedVTResponse = simplifyVTResponse(lookup.data);
      logger.info(`[${req.requestId}] Simplified VirusTotal lookup result for URL ${urlStr}: ${JSON.stringify(simplifiedVTResponse)}`);
      //return { url: urlStr, vt_lookup: simplifyVTResponse };
      return simplifiedVTResponse;
    } catch (lookupErr) {
      // submit
      const submit = await axios.post('https://www.virustotal.com/api/v3/urls', `url=${encodeURIComponent(urlStr)}`, {
        headers: { 'x-apikey': VT_API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 15000
      });
      console.log('VirusTotal submission response:', submit.data);
      logger.info(`[${req.requestId}] VirusTotal submission response: ${JSON.stringify(submit.data)}`);

      const analysisId = submit.data.data.id;
      for (let i = 0; i < 12; i++) {
        await wait(3000);
        try {
          console.log(`Polling VirusTotal attempt ${i + 1} for analysis ID: ${analysisId}`);
          const analysis = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: { 'x-apikey': VT_API_KEY }, timeout: 15000 });
          console.log(`VirusTotal analysis response for attempt ${i + 1}:`, analysis.data);

          if (analysis.data && analysis.data.data && analysis.data.data.attributes && analysis.data.data.attributes.status === 'completed') {
            try {
              const final = await axios.get(lookupUrl, { headers: { 'x-apikey': VT_API_KEY }, timeout: 15000 });
              console.log('Final VirusTotal lookup after analysis completion:', final.data);
              logger.info(`[${req.requestId}] Final VirusTotal lookup after analysis completion status: ${final.status}, statusText: ${final.statusText}`);
              const finalSimplified = simplifyVTResponse(final.data);
              logger.info(`[${req.requestId}] Final simplified VirusTotal analysis result for URL ${urlStr}: ${JSON.stringify(finalSimplified)}`);
              return { url: urlStr, vt_analysis: finalSimplified };
            } catch (e) {
              console.error('Final lookup failed after analysis completion, returning analysis data instead:', e.message);
              logger.error(`[${req.requestId}] Final lookup failed after analysis completion, returning analysis data instead: ${e.message}`);
              return { url: urlStr, vt_analysis: analysis.data };
            }
          }
        } catch (pollErr) {
          // ignore
        }
      }
      console.error('Polling timed out for VirusTotal analysis ID:', analysisId);
      return { url: urlStr, note: 'timed out polling virustotal' };
    }
  } catch (err) {
    console.error('Error during virustotalTool execution:', err.message);
    return { url: input.url, error: String(err) };
  }
}

// Fetch media from Meta Graph API given media_id -> save to temp file and return {filePath, mimeType}
async function fetchMetaMedia(mediaId) {
  logger.info(`[${req.requestId}] Fetching media from Meta Graph API for media_id: ${mediaId}`);
  if (!META_BSP_TOKEN) throw new Error('META_BSP_TOKEN not configured');

  const mediaMetaUrl = `https://graph.facebook.com/v15.0/${mediaId}?fields=url`;
  const metaRes = await axios.get(mediaMetaUrl, {
    headers: { Authorization: `Bearer ${META_BSP_TOKEN}` },
    timeout: 15000
  });

  const mediaUrl = metaRes.data && metaRes.data.url;
  logger.info(`[${req.requestId}] Media URL fetched from Meta Graph API: ${mediaUrl}`);
  if (!mediaUrl) throw new Error('media url not found');

  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, `mcp_media_${uuidv4()}`);
  const writer = fs.createWriteStream(filePath);
  logger.info(`[${req.requestId}] Downloading media from URL: ${mediaUrl} to temporary file: ${filePath}`);
  const response = await axios.get(mediaUrl, { responseType: 'stream', timeout: 20000 });
  logger.info(`[${req.requestId}] Media download response received with status: ${response.status} and content-type: ${response.headers['content-type']}`);
  const contentType = response.headers['content-type'] || 'application/octet-stream';
  response.data.pipe(writer);

  await new Promise((resolve, reject) => {
    writer.on('finish', resolve);
    writer.on('error', reject);
  });

  logger.info(`[${req.requestId}] Media downloaded successfully to: ${filePath} with content-type: ${contentType}`);
  return { filePath, mimeType: contentType };
}

async function ocrTool(req, input) {
  logger.info(`[${req.requestId}] Starting ocrTool with input: ${input}`);
  
  if (!input.media_id) return { error: 'media_id missing' };
  try {
    const media = await fetchMetaMedia(input.media_id);
    const filePath = media.filePath;
    const mimeType = media.mimeType;
    // If Google Vision API configured, use it
    if (GOOGLE_VISION_API_KEY) {
      const imageContent = fs.readFileSync(filePath, { encoding: 'base64' });
      const url = `https://vision.googleapis.com/v1/images:annotate?key=${GOOGLE_VISION_API_KEY}`;
      const body = {
        requests: [
          { image: { content: imageContent }, features: [{ type: 'TEXT_DETECTION', maxResults: 1 }] }
        ]
      };
      logger.info(`[${req.requestId}] Sending OCR request to Google Vision API for media_id: ${input.media_id}`);
      const r = await axios.post(url, body, { timeout: 20000 });
      const ann = r.data && r.data.responses && r.data.responses[0];
      const text = ann && (ann.fullTextAnnotation ? ann.fullTextAnnotation.text : (ann.textAnnotations && ann.textAnnotations[0] && ann.textAnnotations[0].description));
      safeUnlink(filePath);
      logger.info(`[${req.requestId}] OCR result for media_id ${input.media_id}: ${text ? 'Text extracted' : 'No text found'}`);
      return { ocr_text: text || '' , mimeType };
    } else {
      // Fallback: Tesseract not implemented here
      logger.warn(`[${req.requestId}] GOOGLE_VISION_API_KEY not configured, OCR not executed`);
      safeUnlink(filePath);
      return { note: 'No GOOGLE_VISION_API_KEY configured; OCR not executed', mimeType };
    }
  } catch (err) {
    logger.error(`[${req.requestId}] Error in ocrTool for media_id ${input.media_id}: ${err.message}`);
    return { error: String(err) };
  }
}

function safeUnlink(p) {
  try { fs.unlinkSync(p); } catch (e) {}
}

// Execute a tool by name with given input
async function executeTool(req, toolName, input) {
  logger.info(`[${req.requestId}] executeTool: ${toolName} with input: ${input}`);
  console.log(`executeTool: ${toolName} with input:`, input);
  switch (toolName) {
    case 'follow_redirects':
      return await followRedirectsTool(req, input);
    // case 'whois':
    //   return await whoisTool(input);
    case 'urlscan':
      return await urlscanTool(req, input);
    case 'virustotal':
      return await virustotalTool(req, input);
    case 'ocr':
      return await ocrTool(req, input);
    default:
      return { error: `unknown tool: ${toolName}` };
  }
}

/* --------------------
   HTTP endpoints
   -------------------- */

// GET /tools -> return tool manifest
app.get('/tools', (req, res) => {
  logger.info(`[${req.requestId}] Returning tool manifest with ${TOOL_MANIFEST.length} tools`);
  return res.json({ tools: TOOL_MANIFEST });
});

// POST /invoke -> execute a single tool synchronously
app.post('/invoke', requireAuth, async (req, res) => {
  logger.info(`[${req.requestId}] Received /invoke request with body: ${JSON.stringify(req.body)}`);
  try {
    const { tool, input } = req.body || {};
    logger.info(`[${req.requestId}] /invoke request for tool: ${tool} with input: ${JSON.stringify(input)}`);
    if (!tool) {
      logger.warn(`[${req.requestId}] /invoke request missing 'tool' in body`);
      return res.status(400).json({ error: 'tool missing' });
    }
    const result = await executeTool(req, tool, input || {});
    logger.info(`[${req.requestId}] /invoke result for tool ${tool}: ${JSON.stringify(result)}`);

    return res.json({ tool, input: input || {}, result });
  } catch (err) {
    logger.error(`[${req.requestId}] Error in /invoke: ${err.message}`);
    return res.status(500).json({ error: String(err) });
  }
});

// POST /scan -> legacy: accept tools array and run those async (keeps older behavior)
app.post('/scan', requireAuth, async (req, res) => {
  logger.info(`[${req.requestId}] Received /scan request with body: ${JSON.stringify(req.body)}`);

  try {
    const body = req.body || {};
    const scanId = uuidv4();
    const record = {
      scanId,
      receivedAt: new Date().toISOString(),
      body,
      status: 'queued',
      results: {}
    };
    scans.set(scanId, record);

    // Kick off background run
    runRequestedTools(req, scanId).catch(err => {
      //console.error('runRequestedTools err', err);
      logger.error(`[${req.requestId}] runRequestedTools err: ${err}`);

      const r = scans.get(scanId);
      if (r) { r.status = 'error'; r.error = String(err); notifyCallback(req, r).catch(console.error); }
    });

    return res.json({ scan_id: scanId, status: 'queued' });
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

// Background runner for /scan
async function runRequestedTools(req, scanId) {
  logger.info(`[${req.requestId}] Starting runRequestedTools for scanId: ${scanId}`);
  const record = scans.get(scanId);

  logger.info(`[${req.requestId}] Record for runRequestedTools: ${JSON.stringify(record)}`);

  if (!record){
    logger.error(`[${req.requestId}] Record not found for scanId: ${scanId}`);
    throw new Error('not found');
  } 

  const tools = Array.isArray(record.body.tools) ? record.body.tools : [];
  const urls = Array.isArray(record.body.urls) ? record.body.urls : [];
  logger.info(`[${req.requestId}] Tools to run: ${tools}, URLs: ${urls}`);

  const results = {};
  for (const t of tools) {
    //whois is not currently configured
    if (['follow_redirects','whois','urlscan','virustotal'].includes(t)) {
      results[t] = [];
      for (const u of urls) {
        try {
          if (t === 'whois') {
            const domain = new URL(u).hostname;
            results[t].push(await executeTool(req, t, { domain }));
          } else {
            logger.info(`[${req.requestId}] Executing tool ${t} for URL: ${u}`);
            const res = await executeTool(req, t, { url: u });

            logger.info(`[${req.requestId}] Result for tool ${t} and URL ${u}: ${JSON.stringify(res)}`);
            results[t].push(res);
          }
        } catch (err) {
          logger.error(`[${req.requestId}] Error executing tool ${t} for URL ${u}: ${err.message}`);
          results[t].push({ url: u, error: String(err) });
        }
      }
    } else if (t === 'ocr' && record.body.media_id) {
      logger.info(`[${req.requestId}] Executing OCR tool for media_id: ${record.body.media_id}`);
      results.ocr = await executeTool(req, 'ocr', { media_id: record.body.media_id });
    } else {
      logger.warn(`[${req.requestId}] Tool requested but no processing path matched or missing inputs for tool: ${t}`);
      results[t] = { note: 'tool requested but no processing path matched or missing inputs' };
    }
  }
  record.results = results;
  record.status = 'done';
  record.completedAt = new Date().toISOString();
  logger.info(`[${req.requestId}] Completed runRequestedTools for scanId: ${scanId} with results: ${JSON.stringify(results)}`);
  await notifyCallback(req, record);
}

// POST /agent -> start an asynchronous agent run using OpenAI function-calling approach
// Body expected:
// {
//   "messageId": "...",
//   "from": "+65...",
//   "text": "...user text...",
//   "urls": ["..."],
//   "media_id": "<meta_media_id>",
//   "callback": "https://<n8n>/webhook/mcp-callback",
//   "callback_secret": "sharedsecret",
//   "max_steps": 6
// }
app.post('/agent', requireAuth, async (req, res) => {
  logger.info(`[${req.requestId}] Received /agent request with body: ${req.body}`);

  const body = req.body || {};
  const scanId = uuidv4();
  const record = {
    scanId,
    receivedAt: new Date().toISOString(),
    body,
    status: 'queued',
    history: [],
    results: {}
  };
  scans.set(scanId, record);

  // Start async agent loop
  runAgent(req, scanId).catch(err => {
    console.error('runAgent err', err);
    logger.error(`[${req.requestId}] runAgent err: ${err}`);

    const r = scans.get(scanId);
    if (r) { 
      r.status = 'error'; 
      r.error = String(err); 
      notifyCallback(req, r).catch(
        //console.error
        logger.error(`[${req.requestId}] notifyCallback err: ${err}`)
      ); 
    }
  });

  return res.json({ scan_id: scanId, status: 'queued' });
});

// Agent loop implementation (uses OpenAI chat completions + function calling)
async function runAgent(req, scanId) {
  logger.info(`[${req.requestId}] Starting runAgent for scanId: ${scanId}`);
  const record = scans.get(scanId);
  if (!record) throw new Error('scan not found: ' + scanId);
  if (!OPENAI_API_KEY) {
    logger.error(`[${req.requestId}] OPENAI_API_KEY not configured for agent`);
    record.status = 'error';
    record.error = 'OPENAI_API_KEY not configured for agent';
    return notifyCallback(req, record);
  }

  const max_steps = record.body.max_steps || 6;
  // Build initial messages
  const messages = [
    { role: 'system', content: 'You are a malware and phishing analysis assistant. You may call provided tools to inspect URLs, follow redirects, lookup WHOIS, run urlscan and VirusTotal, or OCR images. Use as few tools as possible and explain why.' },
    { role: 'user', content: JSON.stringify({
      messageId: record.body.messageId,
      from: record.body.from,
      text: record.body.text,
      urls: record.body.urls || [],
      media_id: record.body.media_id || null
    }) }
  ];

  // Convert TOOL_MANIFEST to OpenAI function definitions
  const functions = TOOL_MANIFEST.map(t => {
    return {
      name: t.name,
      description: t.description,
      parameters: t.inputSchema
    };
  });

  const openaiUrl = 'https://api.openai.com/v1/chat/completions';

  let steps = 0;
  let lastAssistant = null;

  while (steps < max_steps) {
    steps++;
    // Call OpenAI ChatCompletion with function definitions
    const payload = {
      model: 'gpt-4o-mini', // change if desired
      messages,
      functions,
      function_call: 'auto',
      temperature: 0.0,
      max_tokens: 512
    };

    logger.info(`[${req.requestId}] OpenAI API call with payload: ${JSON.stringify(payload)}`);
    const r = await axios.post(openaiUrl, payload, {
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
      timeout: 30000
    });

    logger.info(`[${req.requestId}] OpenAI API response: ${JSON.stringify(r.data)}`);
    if (!r.data || !r.data.choices || r.data.choices.length === 0) {
      record.status = 'error';
      record.error = 'no response from openai';
      logger.error(`[${req.requestId}] No response from OpenAI API`);
      return notifyCallback(req, record);
    }

    const choice = r.data.choices[0];
    const message = choice.message;
    lastAssistant = message;
    logger.info(`[${req.requestId}] OpenAI message: ${JSON.stringify(message)}, choice: ${JSON.stringify(choice)}`);
    record.history.push({ step: steps, assistant: message });

    // If model requested a function (tool)
    if (message.function_call) {
      const fn = message.function_call;
      const toolName = fn.name;
      // Parse arguments (model may send as JSON string)
      let args = {};
      logger.info(`[${req.requestId}] Model requested tool: ${toolName} with arguments: ${fn.arguments}`);
      try {
        args = fn.arguments ? JSON.parse(fn.arguments) : {};
      } catch (e) {
        // attempt to fix single-quoted JSON or plain text
        try {
          args = JSON.parse(fn.arguments.replace(/([''])/g, '"'));
        } catch (ee) {
          args = { raw: fn.arguments || '' };
        }
      }

      // Validate tool existence
      logger.info(`[${req.requestId}] Validating requested tool: ${toolName}`);
      const toolDef = TOOL_MANIFEST.find(t => t.name === toolName);
      if (!toolDef) {
        // append function response with error and continue
        logger.warn(`[${req.requestId}] Requested unknown tool: ${toolName}`);
        messages.push({ role: 'assistant', content: `Requested unknown tool: ${toolName}` });
        continue;
      }

      // Execute the tool
      let result;
      try {
        logger.info(`[${req.requestId}] Executing tool: ${toolName} with arguments: ${JSON.stringify(args)}`);
        result = await executeTool(req, toolName, args);
      } catch (err) {
        result = { error: String(err) };
      }

      // Append the function result as a 'function' message (what the tool returned)
      logger.info(`[${req.requestId}] Tool execution result for ${toolName}: ${JSON.stringify(result)}`);
      messages.push({
        role: 'function',
        name: toolName,
        content: JSON.stringify(result)
      });

      // store intermediate results
      logger.info(`[${req.requestId}] Storing result for tool ${toolName}`);
      record.results[toolName] = record.results[toolName] || [];
      record.results[toolName].push({ input: args, output: result, ts: new Date().toISOString() });

      // continue the loop so the model can decide next step
      logger.info(`[${req.requestId}] Continuing agent loop after tool execution...`);
      continue;
    } else {
      // No function called -> model produced a final answer (assistant content)
      logger.info(`[${req.requestId}] Model produced final response: ${message.content}`);
      record.final_response = message.content;
      record.status = 'done';
      record.completedAt = new Date().toISOString();
      // include history, results, final message
      await notifyCallback(req, record);
      return;
    }
  }

  // Max steps reached without final answer
  logger.warn(`[${req.requestId}] Max steps reached without final answer`);
  record.status = 'done';
  record.completedAt = new Date().toISOString();
  record.final_response = lastAssistant && (lastAssistant.content || null);
  logger.info(`[${req.requestId}] Final record before callback: ${JSON.stringify(record)}`);
  await notifyCallback(req, record);
}

// Notify n8n callback (header X-Callback-Secret)
async function notifyCallback(req, record) {
  logger.info(`[${req.requestId}] Notifying callback with record: ${JSON.stringify(record)}`);
  const cb = (record.body && record.body.callback) || record.body.callback;
  const secret = (record.body && record.body.callback_secret) || record.body.callback_secret || CALLBACK_DEFAULT_SECRET;
  if (!cb) {
    logger.warn(`[${req.requestId}] No callback URL configured for record ${record.scanId}`);
    console.warn('no callback configured for record', record.scanId);
    return;
  }

  const payload = {
    scan_id: record.scanId,
    messageId: record.body.messageId,
    from: record.body.from,
    text: record.body.text,
    urls: record.body.urls,
    media_id: record.body.media_id,
    results: record.results,
    final_response: record.final_response || null,
    history: record.history || null,
    status: record.status,
    receivedAt: record.receivedAt,
    completedAt: record.completedAt || null
  };

  try {
    logger.info(`[${req.requestId}] Sending POST request to callback URL: ${cb} with payload: ${JSON.stringify(payload)}`);
    const cbresult = await axios.post(cb, payload, {
      headers: {
        'Content-Type': 'application/json',
        'X-Callback-Secret': secret
      },
      timeout: 20000
    });
    logger.info(`[${req.requestId}] Callback notification sent successfully to ${cb} HTTP status: ${cbresult.status}`);
  } catch (err) {
    logger.error(`[${req.requestId}] notifyCallback failed: ${err && err.response ? err.response.data : err.message}`);
    throw err;
  }
}

// Debug endpoint: get scan status
app.get('/scan/:id', (req, res) => {
  logger.info(`[${req.requestId}] Fetching scan status for ID: ${req.params.id}`);
  const id = req.params.id;
  const r = scans.get(id);
  if (!r) {
    logger.error(`[${req.requestId}] Scan not found for ID: ${id}`);
    return res.status(404).json({ error: 'not found' });
  }
  logger.info(`[${req.requestId}] Scan found for ID: ${id}`);
  return res.json(r);
});

// Health
app.get('/health', (req, res) => {
  logger.info(`[${req.requestId}] Health check OK`);
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`MCP Agent microservice listening on port ${PORT}`);
  console.log('ENV: OPENAI_API_KEY set?', !!OPENAI_API_KEY);
  console.log('ENV: VT_API_KEY set?', !!VT_API_KEY);
  console.log('ENV: URLSCAN_API_KEY set?', !!URLSCAN_API_KEY);
  console.log('ENV: WHOIS_API_KEY set?', !!WHOIS_API_KEY);
  console.log('ENV: META_BSP_TOKEN set?', !!META_BSP_TOKEN);

  logger.info(`MCP Agent microservice listening on port ${PORT}`);
  logger.info(`ENV: OPENAI_API_KEY set? ${!!OPENAI_API_KEY}`);
  logger.info(`ENV: VT_API_KEY set? ${!!VT_API_KEY}`);
  logger.info(`ENV: URLSCAN_API_KEY set? ${!!URLSCAN_API_KEY}`);
  logger.info(`ENV: WHOIS_API_KEY set? ${!!WHOIS_API_KEY}`);
  logger.info(`ENV: META_BSP_TOKEN set? ${!!META_BSP_TOKEN}`);
});
