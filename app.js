const DATA_URL = "./certificates.json";
const KEY_URL = "./public-key.jwk";

const form = document.querySelector("#verify-form");
const input = document.querySelector("#certificate-id");
const result = document.querySelector("#result");
const fingerprintElement = document.querySelector("#key-fingerprint");

let certificateRecords = [];
let publicKeyBundle;

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function displayDate(isoDate) {
  const date = new Date(`${isoDate}T00:00:00Z`);
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" }).format(date);
}

async function loadRegistry() {
  const [recordsResponse, keyResponse] = await Promise.all([
    fetch(DATA_URL, { cache: "no-store" }),
    fetch(KEY_URL, { cache: "no-store" }),
  ]);
  if (!recordsResponse.ok || !keyResponse.ok) throw new Error("The certificate register could not be loaded.");
  certificateRecords = await recordsResponse.json();
  publicKeyBundle = await keyResponse.json();
  const keyDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(publicKeyBundle.publicKeyJwk)));
  fingerprintElement.textContent = `Verification key ${publicKeyBundle.keyId}: ${bytesToHex(keyDigest).match(/.{1,4}/g).join(" ")}`;
}

async function verifySignature(record) {
  if (record.keyId !== publicKeyBundle.keyId) return false;
  const { signature, ...unsignedRecord } = record;
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicKeyBundle.publicKeyJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    base64UrlToBytes(signature),
    new TextEncoder().encode(canonicalize(unsignedRecord)),
  );
}

function showMessage(type, title, message, symbol) {
  result.className = `result ${type}`;
  result.innerHTML = `<div class="result-heading"><span class="status-mark" aria-hidden="true">${symbol}</span><h2>${escapeHtml(title)}</h2></div><p>${escapeHtml(message)}</p>`;
  result.hidden = false;
}

function showRecord(record, isValidSignature) {
  if (!isValidSignature) {
    showMessage("invalid", "Verification failed", "The certificate record exists, but its digital signature is invalid. Do not accept this certificate.", "!");
    return;
  }
  if (record.status === "revoked") {
    showMessage("revoked", "Certificate revoked", "This certificate was issued previously but is no longer valid.", "×");
    return;
  }
  if (record.status !== "valid") {
    showMessage("invalid", "Unknown certificate status", "The record contains a status that cannot be verified.", "!");
    return;
  }

  const hiddenResults = new Set(["INVITATION AWARD", "RECOGNITION"]);
  const resultRow = record.result && !hiddenResults.has(record.result)
    ? `<dt>Result</dt><dd>${escapeHtml(record.result)}</dd>`
    : "";
  const pdfUrl = `./pdfs/2026/${encodeURIComponent(record.certificateId)}.pdf`;
  const digitalCopySection = record.documentHash
    ? `<div class="digital-copy">
        <a class="download-link" href="${pdfUrl}" download>Download official PDF</a>
        <div class="file-check">
          <label for="certificate-file">Verify official PDF</label>
          <input id="certificate-file" type="file" accept="application/pdf" />
          <p id="file-check-result">Select the issued PDF to confirm that it is authentic and unchanged.</p>
          <p class="privacy-note">The file is checked securely in your browser and is not uploaded.</p>
        </div>
      </div>`
    : "";
  result.className = "result valid";
  result.innerHTML = `
    <div class="result-heading"><span class="status-mark" aria-hidden="true">✓</span><h2>Certificate verified</h2></div>
    <dl class="record-details">
      <dt>Certificate number</dt><dd>${escapeHtml(record.certificateId)}</dd>
      <dt>Recipient or company</dt><dd>${escapeHtml(record.recipient)}</dd>
      <dt>Award category</dt><dd>${escapeHtml(record.awardCategory)}</dd>
      ${resultRow}
      <dt>Issue date</dt><dd>${escapeHtml(displayDate(record.issueDate))}</dd>
      <dt>Issuer</dt><dd>${escapeHtml(record.issuer)}</dd>
    </dl>
    ${digitalCopySection}`;
  result.hidden = false;

  if (record.documentHash) {
    const fileInput = result.querySelector("#certificate-file");
    const fileResult = result.querySelector("#file-check-result");
    fileInput.addEventListener("change", async () => {
      const [file] = fileInput.files;
      if (!file) return;
      fileResult.textContent = "Checking PDF…";
      const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
      const matches = bytesToHex(digest) === record.documentHash.toLowerCase();
      fileResult.textContent = matches ? "The PDF matches the issued certificate." : "The PDF does not match the issued certificate.";
      fileResult.style.color = matches ? "var(--success)" : "var(--danger)";
      fileResult.style.fontWeight = "700";
    });
  }
}

async function verifyCertificate(rawId) {
  const certificateId = rawId.trim().toUpperCase();
  if (!certificateId) {
    showMessage("not-found", "Enter a certificate number", "A certificate number is required before verification can begin.", "?");
    input.focus();
    return;
  }

  showMessage("loading", "Checking certificate", "The signed certificate register is being checked.", "…");
  try {
    if (!publicKeyBundle) await loadRegistry();
    const record = certificateRecords.find((item) => item.certificateId.toUpperCase() === certificateId);
    if (!record) {
      showMessage("not-found", "Certificate not found", "No certificate with this number appears in the published register.", "?");
      return;
    }
    showRecord(record, await verifySignature(record));
    const url = new URL(window.location.href);
    url.searchParams.set("id", record.certificateId);
    history.replaceState({}, "", url);
  } catch (error) {
    showMessage("invalid", "Verification unavailable", error.message || "The certificate register could not be checked.", "!");
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  verifyCertificate(input.value);
});

try {
  await loadRegistry();
  const requestedId = new URLSearchParams(window.location.search).get("id");
  if (requestedId) {
    input.value = requestedId;
    await verifyCertificate(requestedId);
  }
} catch (error) {
  fingerprintElement.textContent = "Verification key unavailable";
}
