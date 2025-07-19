import { createHash } from "crypto";

export function proofOfWork(data: string, difficulty: number): number {
  const hexPrefixLength = Math.floor(difficulty / 4);
  const expectedPrefix = "0".repeat(hexPrefixLength);
  // console.log("Expected prefix:", expectedPrefix);

  let nonce = 0;

  while (true) {
    const hash = createHash("sha256")
      .update(data + nonce)
      .digest("hex");

    // console.log("nonce:", nonce, "→ hash:", hash);

    if (hash.startsWith(expectedPrefix)) {
      // console.log("✅ Found valid nonce:", nonce);
      return nonce;
    }

    nonce++;
  }
}
