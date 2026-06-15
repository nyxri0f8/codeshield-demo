export const MOCK_SCAN = {
  findings: [
    {
      title: "Hardcoded Stripe Credentials",
      description: "A hardcoded Stripe secret API key was found in the orders router config. Hardcoding keys allows anyone with read access to the code to steal account funds or customer transaction records.",
      severity: "Critical",
      cvss_score: 9.3,
      owasp_category: "A02:2021-Cryptographic Failures",
      cwe_id: "CWE-798",
      vulnerable_snippet: "const stripe  = require('stripe')('sk_live_abc123hardcodedkey');",
      secure_fix: "const stripe  = require('stripe')(process.env.STRIPE_SECRET_KEY);",
      fix_recommendation: "Move Stripe API key to environment variables and inject it into backend runtime configurations.",
      impact_analysis: "An attacker could extract the Stripe API key, authorize refunds, issue payouts to foreign accounts, or access private PCI records.",
      attack_narrative: "I accessed the public GitHub repository page, copied the hardcoded Stripe key from orders.js, and authenticated against the Stripe billing endpoint to extract all customer credit card statements.",
      file_path: "checkout-api/src/routes/orders.js",
      line_number: 5,
      is_ai_smell: false
    },
    {
      title: "SQL Injection via Concatenation",
      description: "User credentials are concatenated directly into the SQL query string in the user login endpoint. Attackers can bypass passwords or fetch records from arbitrary tables.",
      severity: "Critical",
      cvss_score: 9.8,
      owasp_category: "A03:2021-Injection",
      cwe_id: "CWE-89",
      vulnerable_snippet: "const query = \"SELECT * FROM users WHERE username = '\" + username + \"' AND password = '\" + password + \"'\";",
      secure_fix: "const query = 'SELECT * FROM users WHERE username = $1 AND password = $2';\nconst user = await db.query(query, [username, password]);",
      fix_recommendation: "Replace dynamic SQL strings with parameterized queries using positional parameters.",
      impact_analysis: "Enables authentication bypasses, letting any attacker sign in as administrator and extract all registered database records.",
      attack_narrative: "I sent a username parameter with a single quote followed by an OR condition: admin' --. The database parsed it, ignored the password check entirely, and logged me in as administrator.",
      file_path: "checkout-api/src/routes/orders.js",
      line_number: 11,
      is_ai_smell: false
    },
    {
      title: "IDOR on Orders Fetch Endpoint",
      description: "The order routing parameter is parsed and queried directly from database without checking if the active user session owns the order reference.",
      severity: "High",
      cvss_score: 8.5,
      owasp_category: "A01:2021-Broken Access Control",
      cwe_id: "CWE-22",
      vulnerable_snippet: "const order = await db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);",
      secure_fix: "const order = await db.query('SELECT * FROM orders WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);",
      fix_recommendation: "Verify order ownership by enforcing access controls in the database query parameters.",
      impact_analysis: "Enables unauthenticated users to view arbitrary customer billing information and tracking details by cycling order IDs.",
      attack_narrative: "I logged in to my account, opened my order page, and cycled the order ID number in the browser URL bar from 100 to 101. The server returned billing data of another user.",
      file_path: "checkout-api/src/routes/orders.js",
      line_number: 18,
      is_ai_smell: false
    },
    {
      title: "AI Smell - Unimplemented Auth TODO",
      description: "A TODO comment indicates security validations were planned but never implemented, leaving the endpoint open to exploitation.",
      severity: "Medium",
      cvss_score: 5.3,
      owasp_category: "A04:2021-Insecure Design",
      cwe_id: "CWE-276",
      vulnerable_snippet: "// TODO: check if user owns this order",
      secure_fix: "// Enforce ownership checks via middleware\nrouter.get('/orders/:id', checkOrderOwnership, async (req, res) => { ... });",
      fix_recommendation: "Ensure TODO comments regarding authorization filters are completed before deploying components to production.",
      impact_analysis: "Unimplemented validation filters lead to systemic authorization bypass flaws like IDOR.",
      is_ai_smell: true,
      file_path: "checkout-api/src/routes/orders.js",
      line_number: 17
    }
  ],
  idor_endpoints: [
    {
      endpoint: "/orders/:id",
      method: "GET",
      risk_level: "High",
      has_auth_check: false,
      has_ownership_check: false,
      reasoning: "Fetches orders using route parameters without checking matching session owners.",
      line_number: 18
    },
    {
      endpoint: "/users/:userId/profile",
      method: "GET",
      risk_level: "High",
      has_auth_check: false,
      has_ownership_check: false,
      reasoning: "Allows reading profile settings of arbitrary user IDs.",
      line_number: 23
    },
    {
      endpoint: "/files/:fileId",
      method: "DELETE",
      risk_level: "High",
      has_auth_check: false,
      has_ownership_check: false,
      reasoning: "Deletes document attachments using parameters without verifying session ownership.",
      line_number: 28
    }
  ],
  compliance_flags: [
    {
      framework: "GDPR",
      risk_level: "High",
      reason: "Exposes private profiles and records via IDOR endpoints, violating personal data safety requirements."
    },
    {
      framework: "PCI-DSS",
      risk_level: "Critical",
      reason: "Hardcodes Stripe private keys in configuration files, violating encryption key safety guidelines."
    },
    {
      framework: "SOC2",
      risk_level: "High",
      reason: "Concat database parameters without sanitization exposes private infrastructure records to modification."
    }
  ]
};
