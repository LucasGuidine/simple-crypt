const inputText = document.querySelector("#input-text");
const outputText = document.querySelector("#output-text");
const password = document.querySelector("#password");
const status = document.querySelector("#status");
const copyButton = document.querySelector("#copy");
const togglePassword = document.querySelector("#toggle-password");
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function showStatus(message, isError = false) {
  status.textContent = message;
  status.classList.toggle("error", isError);
}

function toBase64(bytes) {
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function deriveKey(secret, salt) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(secret), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function validateFields() {
  if (!password.value) throw new Error("Digite uma senha.");
  if (!inputText.value) throw new Error("Digite um texto.");
}

async function encrypt() {
  validateFields();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password.value, salt);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(inputText.value));
  outputText.value = `v1.${toBase64(salt)}.${toBase64(iv)}.${toBase64(new Uint8Array(encrypted))}`;
  showStatus("Texto criptografado com sucesso.");
}

async function decrypt() {
  validateFields();
  const parts = inputText.value.trim().split(".");
  if (parts.length !== 4 || parts[0] !== "v1") {
    throw new Error("Formato inválido. Cole um texto criptografado por esta ferramenta.");
  }
  try {
    const salt = fromBase64(parts[1]);
    const iv = fromBase64(parts[2]);
    const encrypted = fromBase64(parts[3]);
    const key = await deriveKey(password.value, salt);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
    outputText.value = decoder.decode(decrypted);
    showStatus("Texto descriptografado com sucesso.");
  } catch {
    throw new Error("Não foi possível descriptografar. Verifique a senha e o conteúdo.");
  }
}

async function run(operation) {
  showStatus("");
  try {
    await operation();
  } catch (error) {
    outputText.value = "";
    showStatus(error.message, true);
  }
}

document.querySelector("#encrypt").addEventListener("click", () => run(encrypt));
document.querySelector("#decrypt").addEventListener("click", () => run(decrypt));
togglePassword.addEventListener("click", () => {
  const isPassword = password.type === "password";
  password.type = isPassword ? "text" : "password";
  togglePassword.textContent = isPassword ? "Ocultar" : "Mostrar";
  togglePassword.setAttribute("aria-label", isPassword ? "Ocultar senha" : "Mostrar senha");
});
copyButton.addEventListener("click", async () => {
  if (!outputText.value) {
    showStatus("Não há resultado para copiar.", true);
    return;
  }
  try {
    await navigator.clipboard.writeText(outputText.value);
    showStatus("Resultado copiado.");
  } catch {
    showStatus("Não foi possível acessar a área de transferência.", true);
  }
});
