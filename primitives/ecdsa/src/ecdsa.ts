import { createHash } from "crypto";
import { ec as EC } from "elliptic";
import keccak from "keccak";

type HashAlgorithm = "none" | "sha256" | "keccak256";

const ec = new EC("secp256k1");

export function generateKeyPair(curveName: string = "secp256k1") {
  const keyPair = ec.genKeyPair();
  const privateKey = keyPair.getPrivate("hex");
  const publicKey = keyPair.getPublic("hex");
  return { privateKey, publicKey };
}

export function signMessage(
  privateKey: string,
  message: string,
  hashAlgorithm: HashAlgorithm = "none"
): string {
  const key = ec.keyFromPrivate(privateKey, "hex");

  const msgToSign = hashMessage(message, hashAlgorithm);

  const signature = key.sign(msgToSign, "hex");
  const derSign = signature.toDER("hex");
  console.log("✍️ Signature (DER-encoded):", derSign);

  return derSign;
}

export function verifySignature(
  message: string,
  signature: string,
  publicKey: string,
  hashAlgorithm: HashAlgorithm = "none"
): boolean {
  const key = ec.keyFromPublic(publicKey, "hex");
  console.log("🔓 Public key loaded:", publicKey);

  const msgToVerify = hashMessage(message, hashAlgorithm);

  const isValid = key.verify(msgToVerify, signature);
  console.log("✅ Signature is valid?", isValid);

  return isValid;
}

function hashMessage(message: string, hashAlgorithm: HashAlgorithm): string {
  if (hashAlgorithm === "sha256") {
    return createHash("sha256").update(message).digest("hex");
  } else if (hashAlgorithm === "keccak256") {
    return keccak("keccak256").update(message).digest("hex");
  } else {
    return message;
  }
}
