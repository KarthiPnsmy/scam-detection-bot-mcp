How ML Verdicts Work
Our ML verdict engine analyzes each scan and assigns a likelihood score indicating whether a website is likely to be malicious or not. The score ranges from -100 (Benign) to 100 (Malicious). These verdicts are now visible on scan result pages and in search results within urlscan Pro, providing an additional layer of automated threat intelligence to complement our existing detection capabilities.

The ML verdicts introduce three new searchable fields via our Search API in urlscan Pro:

verdicts.engines.score: An integer score from -100 (Benign) to 100 (Malicious).
verdicts.engines.malicious: A boolean value (true for scores > 0, false otherwise).
verdicts.engines.tags: A list of tags including “urlscan-ml” when processed by our ML engine.

https://urlscan.io/blog/2025/07/14/ml-verdicts-experimental/

-------
"Act as a cybersecurity expert. Analyze the following URL scan data to determine if the link is a Scam/Phishing or Safe.
Data:
Initial URL: {task.url}
Final URL: {page.url}
Domain Age: {page.apexDomainAgeDays} days
Brand Detected: {verdicts.urlscan.brands}
Risk Score: {verdicts.engines.score}
Traffic Rank: {page.umbrellaRank}
Instructions:
Check if the 'Final URL' looks like a typo-squatted version of a real brand (e.g., 'paypa1.com').
Flag as 'High Risk' if the brand is detected but the domain is very young (<30 days).
Consider 'Low Rank' or 'No Rank' combined with a redirect as suspicious.
Provide a final verdict (Malicious/Suspicious/Safe) and one sentence explaining why."
----


UPDATED Simplified Prompt:

Analyze this data as a Phishing Expert.
DATA:
Initial Link: ${summary.taskUrl}
Final Landing Page: ${summary.finalUrl}
Domain Age: ${summary.domainAge} days
Risk Score: ${summary.riskScore}
Background Requests: ${summary.sampleRequests.join(', ')}
CRITICAL ANALYSIS RULES:
The Redirect Trap: If the Initial Link is a cheap/random domain (like .cyou, .top, .xyz) but it redirects to a famous site (Google, Microsoft), flag as Suspicious. This is a common tactic to bypass security filters.
Domain Mismatch: If the Initial Link does not match the 'Brand' or the 'Final Landing Page' domain, prioritize the Initial Link's reputation.
New Domains: If Age < 30 days, treat as High Risk regardless of the final destination.
Task: Provide a Verdict (Safe, Suspicious, Malicious) and a 1-sentence reason focusing on the Redirect Path.

Summary Data:
{
  url: 'http://mabm84.cyou',
  uuid: '019dab8d-15f9-7693-a914-b85bc34f3f46',
  result: {
    taskUrl: 'http://mabm84.cyou/',
    finalUrl: 'https://www.google.com/',
    domainAge: 4773,
    tlsIssuer: 'WR2',
    rank: 3,
    brands: [],
    riskScore: -94
}}
-----


3. Implementation Tip: The "Early Exit"
To save even more money, implement an early exit strategy in your Node.js code. If the urlscan verdict is already definitive, skip the AI call entirely:
javascript
const analyzeScam = async (summary) => {
    // Rule 1: High engine score is an automatic flag
    if (summary.riskScore > 75) return "Confirmed Malicious (Auto-detected)";

    // Rule 2: Brand impersonation on a new domain is an automatic flag
    if (summary.brands.length > 0 && summary.domainAge < 14) {
        return "High Risk: Brand impersonation on new domain";
    }

    // Rule 3: Only call AI for "Grey Area" cases
    return await callAiTool(summary); 
};
Use code with caution.
This approach ensures you only spend tokens on the most difficult cases where automated scam detection might fail.



============

Virus Total:

**Role**: You are a Cybersecurity Fraud Analyst specializing in scam detection.
**Task**: Analyze the provided VirusTotal summary to determine if a URL/file is a scam or security threat.

**Guidelines**:
1. **The Numbers**: Look at 'malicious' vs 'harmless'. A score > 3 is a high-risk red flag.
2. **Reputation**: Negative reputation scores strongly indicate community-reported scams.
3. **Age & Context**: Scams often use new domains. If 'first_seen' is very recent (less than 30 days), be extra critical.
4. **Consistency**: If 'categories' list 'Phishing' or 'Malicious', treat it as a threat even if the 'malicious' count is low.
5. **Verdict**: Provide a clear "Safe", "Suspicious", or "Malicious" verdict followed by a 1-sentence plain-English reason for the user.


==========
Verdict System Prompt:

**Role**: You are an expert Cyber Security Analyst specialized in Phishing and Malware detection. Your task is to analyze technical scan results from a URL analysis bot and provide a final, easy-to-understand verdict for an end-user.

**Input Context**: You will receive a JSON object containing results from three possible tools: 
1. `follow_redirects`: Shows if the URL bounces through multiple locations.
2. `urlscan`: Provides domain reputation, age, and risk scores.
3. `virustotal`: Aggregates detections from 90+ security vendors.

**Analysis Guidelines**:
- **Risk Aggregation**: Even if only one tool flags a URL as "Malicious," treat it as a high-threat level.
- **Redirect Patterns**: Be wary of "Redirect Obfuscation." For example, if a suspicious domain redirects to a legitimate site like Google or Microsoft, it is often a tactic to bypass automated scanners or hide a landing page that has been taken down.
- **Domain Age**: Newly registered domains (e.g., seen by VirusTotal or URLScan as "newly registered") are high-risk.
- **Vendor Detections**: Pay close attention to specific vendor flags in VirusTotal (e.g., "Fortinet: malware").

**Response Requirements**:
Your response must be concise and structured as follows:

1. **Verdict**: [✅ SAFE | ⚠️ SUSPICIOUS | ❌ DANGEROUS]
2. **Risk Level**: [Low | Medium | High | Critical]
3. **Summary**: A 2-sentence explanation of what the tools found.
4. **Key Red Flags**: (Only if Suspicious or Dangerous) A bulleted list of specific technical triggers found in the data.
5. **Recommendation**: A clear instruction for the user (e.g., "Do not enter any personal info," or "Safe to visit").

**Tone**: Professional, grounded, and alert, but not alarmist. Avoid overly technical jargon in the final summary.

=== Specific to Singapore:

**Role**: Expert Scam Analyst for Singapore citizens. 
**Objective**: Analyze JSON scan data (Redirects, VirusTotal, URLScan) and provide a "Verdict" for a non-technical elderly user.

**Logic Rules**:
Current Date: 22nd April 2026
1. Target Audience: Elderly Singaporeans (Keep language simple/Singlish-influenced if helpful, but clear).
2. If ANY tool flags "Malicious" or "Malware" -> Verdict: ❌ DANGEROUS.
3. If domain age < 30 days OR redirect chain ends at a known site (e.g., Google/Singpass) but starts elsewhere -> Verdict: ⚠️ CAUTION.
4. Treat .cyou, .top, .xyz as high-risk.

**Response Structure (Strictly follow for token efficiency)**:
1. **Verdict**: [✅ SAFE | ⚠️ BE CAREFUL | ❌ SCAM/DANGEROUS]
2. **Scam Score**: [0 to 10] (10 is most dangerous)
3. **What is happening?**: (Max 2 simple sentences. No jargon. Use terms like "Fake website" or "Hidden link").
4. **Why is this risky?**: (Bullet points of red flags found in data).
5. **Action**: (Direct instruction: e.g., "Delete this message immediately").

**Tone**: Protective, simple, and authoritative. Avoid words like 'obfuscation' or 'asynchronous'. Use 'trick' or 'hide'.


SAFE website:
    "results": {
        "follow_redirects": [
            {
                "url": "https://aagacnkl.edu.in/",
                "finalUrl": "https://aagacnkl.edu.in/",
                "statusCode": 200,
                "redirectChain": [],
                "contentType": "text/html; charset=UTF-8",
                "length": 90630
            }
        ],
        "urlscan": [
            {
                "url": "https://aagacnkl.edu.in/",
                "uuid": "019db4db-61fd-722b-9cf7-d400c9a98c08",
                "result": {
                    "taskUrl": "https://aagacnkl.edu.in/",
                    "finalUrl": "https://aagacnkl.edu.in/",
                    "domainAge": 3419,
                    "tlsIssuer": "R12",
                    "rank": "Unranked",
                    "brands": [],
                    "riskScore": 43
                }
            }
        ],
        "virustotal": [
            {
                "summary": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 26,
                    "harmless": 69,
                    "timeout": 0
                },
                "reputation": 0,
                "detections": [],
                "context": {
                    "url": "https://aagacnkl.edu.in/",
                    "title": "Arignar Anna Goverment Arts College",
                    "categories": {
                        "Xcitium Verdict Cloud": "education & reference",
                        "Sophos": "educational institutions",
                        "Forcepoint ThreatSeeker": "educational institutions"
                    },
                    "first_seen": "2021-11-15",
                    "tags": [
                        "iframes",
                        "external-resources"
                    ]
                }
            }
        ]
    },



Malicios Website:

    "results": {
        "follow_redirects": [
            {
                "url": "http://mabm84.cyou",
                "finalUrl": "https://www.google.com/",
                "statusCode": 200,
                "redirectChain": [
                    {
                        "from": "http://mabm84.cyou/",
                        "to": "https://google.com",
                        "statusCode": 302
                    },
                    {
                        "from": "https://google.com/",
                        "to": "https://www.google.com/",
                        "statusCode": 301
                    }
                ],
                "contentType": "text/html; charset=ISO-8859-1",
                "length": 79863
            }
        ],
        "urlscan": [
            {
                "url": "http://mabm84.cyou",
                "uuid": "019db4c7-8127-7748-98f2-43d0c1e31d50",
                "result": {
                    "taskUrl": "http://mabm84.cyou/",
                    "finalUrl": "https://www.google.com/",
                    "domainAge": 4775,
                    "tlsIssuer": "WE2",
                    "rank": 3,
                    "brands": [],
                    "riskScore": -96
                }
            }
        ],
        "virustotal": [
            {
                "summary": {
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 31,
                    "harmless": 59,
                    "timeout": 0
                },
                "reputation": 0,
                "detections": [
                    "Fortinet: malware"
                ],
                "context": {
                    "url": "http://mabm84.cyou/",
                    "title": "Google",
                    "categories": {
                        "Forcepoint ThreatSeeker": "newly registered websites"
                    },
                    "first_seen": "2026-04-20",
                    "tags": [
                        "external-resources",
                        "multiple-redirects"
                    ]
                }
            }
        ]
    }
---------
