const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const A = P - 3n;
const G = {
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n
};
const BYTE_LENGTH = 32;
let demonstrationPrivateKey;

function mod(value, modulus) {
  const remainder = value % modulus;
  return remainder < 0n ? remainder + modulus : remainder;
}

function inverse(value, modulus) {
  let oldR = mod(value, modulus);
  let r = modulus;
  let oldS = 1n;
  let s = 0n;

  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }

  if (oldR !== 1n) {
    throw new Error("L'inverse modulaire demandé n'existe pas.");
  }
  return mod(oldS, modulus);
}

function pointAdd(left, right) {
  if (left === null) return right;
  if (right === null) return left;

  if (left.x === right.x && mod(left.y + right.y, P) === 0n) {
    return null;
  }

  const slope = left.x === right.x && left.y === right.y
    ? mod((3n * left.x * left.x + A) * inverse(2n * left.y, P), P)
    : mod((right.y - left.y) * inverse(right.x - left.x, P), P);
  const x = mod(slope * slope - left.x - right.x, P);
  const y = mod(slope * (left.x - x) - left.y, P);
  return { x, y };
}

function pointMultiply(scalar, point = G) {
  let result = null;
  let addend = point;
  let remaining = scalar;

  while (remaining > 0n) {
    if (remaining & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    remaining >>= 1n;
  }
  return result;
}

function toBytes(value, length = BYTE_LENGTH) {
  const bytes = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error("Valeur trop grande pour l'encodage demandé.");
  return bytes;
}

function fromBytes(bytes) {
  return bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

function concatBytes(...arrays) {
  const result = new Uint8Array(arrays.reduce((length, array) => length + array.length, 0));
  let offset = 0;
  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }
  return result;
}

function toHex(value) {
  return value.toString(16).padStart(BYTE_LENGTH * 2, "0");
}

function shortHex(value) {
  const hex = toHex(value);
  return `${hex.slice(0, 18)}…${hex.slice(-14)}`;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function randomScalar() {
  while (true) {
    const bytes = crypto.getRandomValues(new Uint8Array(BYTE_LENGTH));
    const value = fromBytes(bytes);
    if (value > 0n && value < N) return value;
  }
}

function getDemonstrationPrivateKey() {
  if (demonstrationPrivateKey === undefined) {
    demonstrationPrivateKey = randomScalar();
  }
  return demonstrationPrivateKey;
}

async function sha256(message) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(message));
  return new Uint8Array(digest);
}

async function hmacSha256(keyBytes, messageBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, messageBytes));
}

function hashToScalar(hashBytes) {
  return fromBytes(hashBytes) % N;
}

async function rfc6979(privateKey, hashBytes) {
  let key = new Uint8Array(BYTE_LENGTH);
  let value = new Uint8Array(BYTE_LENGTH).fill(1);
  const privateOctets = toBytes(privateKey);
  const hashOctets = toBytes(hashToScalar(hashBytes));

  key = await hmacSha256(key, concatBytes(value, Uint8Array.of(0), privateOctets, hashOctets));
  value = await hmacSha256(key, value);
  key = await hmacSha256(key, concatBytes(value, Uint8Array.of(1), privateOctets, hashOctets));
  value = await hmacSha256(key, value);

  while (true) {
    value = await hmacSha256(key, value);
    const candidate = fromBytes(value);
    if (candidate > 0n && candidate < N) return candidate;
    key = await hmacSha256(key, concatBytes(value, Uint8Array.of(0)));
    value = await hmacSha256(key, value);
  }
}

function sign(hashBytes, privateKey, nonce) {
  const point = pointMultiply(nonce);
  const r = point.x % N;
  const s = mod(inverse(nonce, N) * (hashToScalar(hashBytes) + r * privateKey), N);
  assert(r !== 0n && s !== 0n, "La signature ECDSA obtenue est dégénérée; relancez la démonstration.");
  return { r, s };
}

function verify(hashBytes, signature, publicKey) {
  if (signature.r <= 0n || signature.r >= N || signature.s <= 0n || signature.s >= N) return false;
  const z = hashToScalar(hashBytes);
  const w = inverse(signature.s, N);
  const point = pointAdd(
    pointMultiply(mod(z * w, N)),
    pointMultiply(mod(signature.r * w, N), publicKey)
  );
  return point !== null && point.x % N === signature.r;
}

function recoverKey(hashOne, hashTwo, first, second) {
  assert(first.r === second.r, "Les signatures ne partagent pas le même r.");
  const zOne = hashToScalar(hashOne);
  const zTwo = hashToScalar(hashTwo);
  const nonce = mod((zOne - zTwo) * inverse(first.s - second.s, N), N);
  const privateKey = mod((first.s * nonce - zOne) * inverse(first.r, N), N);
  assert(nonce > 0n && privateKey > 0n, "La récupération a produit une valeur invalide.");
  return { nonce, privateKey };
}

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function resetOutputs() {
  for (const id of [
    "vuln-sig-one", "vuln-sig-two", "vuln-r-match", "recovered-key", "key-match",
    "forgery-valid", "patched-valid-one", "patched-valid-two", "patched-k-diff",
    "patched-r-match", "patched-repeat"
  ]) {
    setText(id, "—");
  }
}

function readMessages() {
  const first = document.getElementById("message-one").value;
  const second = document.getElementById("message-two").value;
  assert(first.length > 0 && second.length > 0, "Saisissez deux messages non vides.");
  assert(first !== second, "Utilisez deux messages différents pour comparer les signatures.");
  return [first, second];
}

async function runVulnerableDemo() {
  const [messageOne, messageTwo] = readMessages();
  const privateKey = getDemonstrationPrivateKey();
  const publicKey = pointMultiply(privateKey);
  const nonce = randomScalar();
  const hashOne = await sha256(messageOne);
  const hashTwo = await sha256(messageTwo);
  const signatureOne = sign(hashOne, privateKey, nonce);
  const signatureTwo = sign(hashTwo, privateKey, nonce);
  const recovered = recoverKey(hashOne, hashTwo, signatureOne, signatureTwo);
  const recoveredPublicKey = pointMultiply(recovered.privateKey);
  const forgedHash = await sha256("Message forgé pour cette démonstration locale");
  const forgedSignature = sign(forgedHash, recovered.privateKey, randomScalar());

  assert(verify(hashOne, signatureOne, publicKey), "Échec de vérification de la première signature.");
  assert(verify(hashTwo, signatureTwo, publicKey), "Échec de vérification de la seconde signature.");

  setText("vuln-sig-one", `r=${shortHex(signatureOne.r)} · s=${shortHex(signatureOne.s)}`);
  setText("vuln-sig-two", `r=${shortHex(signatureTwo.r)} · s=${shortHex(signatureTwo.s)}`);
  setText("vuln-r-match", signatureOne.r === signatureTwo.r ? "Oui" : "Non");
  setText("recovered-key", `0x${toHex(recovered.privateKey)}`);
  setText("key-match", recoveredPublicKey.x === publicKey.x && recoveredPublicKey.y === publicKey.y ? "Oui" : "Non");
  setText("forgery-valid", verify(forgedHash, forgedSignature, publicKey) ? "Oui" : "Non");
}

async function runPatchedDemo() {
  const [messageOne, messageTwo] = readMessages();
  const privateKey = getDemonstrationPrivateKey();
  const publicKey = pointMultiply(privateKey);
  const hashOne = await sha256(messageOne);
  const hashTwo = await sha256(messageTwo);
  const nonceOne = await rfc6979(privateKey, hashOne);
  const nonceTwo = await rfc6979(privateKey, hashTwo);
  const signatureOne = sign(hashOne, privateKey, nonceOne);
  const signatureTwo = sign(hashTwo, privateKey, nonceTwo);
  const repeatedNonce = await rfc6979(privateKey, hashOne);
  const repeatedSignature = sign(hashOne, privateKey, repeatedNonce);

  setText("patched-valid-one", verify(hashOne, signatureOne, publicKey) ? "Oui" : "Non");
  setText("patched-valid-two", verify(hashTwo, signatureTwo, publicKey) ? "Oui" : "Non");
  setText("patched-k-diff", nonceOne !== nonceTwo ? "Oui" : "Non");
  setText("patched-r-match", signatureOne.r === signatureTwo.r ? "Oui" : "Non");
  setText(
    "patched-repeat",
    nonceOne === repeatedNonce && signatureOne.r === repeatedSignature.r && signatureOne.s === repeatedSignature.s
      ? "Oui, comme prévu"
      : "Non"
  );
}

const status = document.getElementById("lab-status");
const buttons = [
  document.getElementById("run-vulnerable"),
  document.getElementById("run-patched"),
  document.getElementById("new-key")
];

async function runDemo(action, successMessage) {
  buttons.forEach((button) => { button.disabled = true; });
  status.classList.remove("error");
  status.textContent = "Calcul des signatures et vérification…";
  resetOutputs();

  try {
    await action();
    status.textContent = successMessage;
  } catch (error) {
    status.classList.add("error");
    status.textContent = error instanceof Error ? error.message : "La démonstration a échoué.";
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
}

document.getElementById("run-vulnerable").addEventListener("click", () => {
  void runDemo(runVulnerableDemo, "Démonstration terminée. La clé affichée est temporaire et a été récupérée à partir des deux signatures.");
});

document.getElementById("run-patched").addEventListener("click", () => {
  void runDemo(runPatchedDemo, "Comparaison terminée. Les signatures et le comportement déterministe ont été vérifiés.");
});

document.getElementById("new-key").addEventListener("click", () => {
  demonstrationPrivateKey = randomScalar();
  resetOutputs();
  status.classList.remove("error");
  status.textContent = "Nouvelle clé temporaire créée. Les deux démonstrations utiliseront cette même clé.";
});

if (!globalThis.crypto?.subtle || typeof BigInt !== "function") {
  buttons.forEach((button) => { button.disabled = true; });
  status.classList.add("error");
  status.textContent = "Ce navigateur ne prend pas en charge les primitives cryptographiques requises. Ouvrez le laboratoire dans un navigateur moderne via localhost.";
}
