
# MCP Agent

Quick start (Node >= 18.0.0)

1. Install dependencies
   npm install

2. Configure environment variables (see .env.example). At minimum for basic endpoints:
   - (optional) MCP_API_KEY — if set, requests must include Bearer token
   - OPENAI_API_KEY — required if you want to use /agent
   - other API keys as needed for the tools

3. Start the server
   npm start
   or for development with auto-restart:
   npm run dev

4. Health check
   GET http://localhost:3000/health

5. Tools manifest
   GET http://localhost:3000/tools

6. Invoke a tool (example)
   POST /invoke
   Headers: Authorization: Bearer <MCP_API_KEY> (if configured), Content-Type: application/json
   Body:
   { "tool": "follow_redirects", "input": { "url": "https://example.com" } }
