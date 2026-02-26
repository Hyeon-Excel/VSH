const TOKEN = "ghp_1234567890abcdef1234567890abcd";
// VSH Alert [HIGH] vsh.common.secret.hardcoded
// CWE: CWE-798
// KISA: SECRETS_MANAGEMENT_1
// Reachability: UNKNOWN
// Impact: Embedded credentials may be leaked through source control.
// Recommendation: Move secrets to environment variables or a secret manager.

function renderUserInput(input) {
  const target = document.getElementById("target");
  target.innerHTML = `<b>${input}</b>`;
// VSH Alert [HIGH] vsh.js.xss.innerhtml
// CWE: CWE-79
// KISA: OUTPUT_ENCODING_1
// Reachability: YES
// Impact: Untrusted input may execute script in the browser.
// Recommendation: Use safe text rendering APIs or sanitize trusted HTML.
}

module.exports = { renderUserInput };
