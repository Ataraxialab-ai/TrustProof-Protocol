import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, it } from "vitest";

import {
  canonicalJson,
  computeCanonicalEventMaterial,
  computeEntryHash,
  sha256Hex
} from "../src";

type VectorFile = {
  id: string;
  input: {
    subject: unknown;
    action: unknown;
    resource: unknown;
    policy: unknown;
    timestamp: unknown;
    jti: unknown;
  };
  output: unknown;
  canonical_input: string;
  canonical_output: string;
  expected: {
    input_hash_hex: string;
    output_hash_hex: string;
    prev_hash_hex: string;
    canonical_event_material: string;
    entry_hash_hex: string;
  };
};

const vectorsDirPath = fileURLToPath(new URL("../../../spec/vectors", import.meta.url));
const vectorFiles = readdirSync(vectorsDirPath)
  .filter((name) => name.endsWith(".json"))
  .sort();

function loadVector(fileName: string): VectorFile {
  const filePath = new URL(`../../../spec/vectors/${fileName}`, import.meta.url);
  return JSON.parse(readFileSync(filePath, "utf8")) as VectorFile;
}

describe("golden vectors", () => {
  for (const fileName of vectorFiles) {
    it(`validates ${fileName}`, () => {
      const vector = loadVector(fileName);

      const canonicalInput = canonicalJson(vector.input);
      if (canonicalInput !== vector.canonical_input) {
        throw new Error(`${vector.id}: canonical_input mismatch`);
      }

      const canonicalOutput = canonicalJson(vector.output);
      if (canonicalOutput !== vector.canonical_output) {
        throw new Error(`${vector.id}: canonical_output mismatch`);
      }

      const inputHashHex = sha256Hex(canonicalInput);
      if (inputHashHex !== vector.expected.input_hash_hex) {
        throw new Error(`${vector.id}: input_hash_hex mismatch`);
      }

      const outputHashHex = sha256Hex(canonicalOutput);
      if (outputHashHex !== vector.expected.output_hash_hex) {
        throw new Error(`${vector.id}: output_hash_hex mismatch`);
      }

      const claimsForChain = {
        subject: vector.input.subject,
        action: vector.input.action,
        resource: vector.input.resource,
        policy: vector.input.policy,
        result: vector.output,
        hashes: {
          input_hash: inputHashHex,
          output_hash: outputHashHex
        },
        timestamp: vector.input.timestamp,
        jti: vector.input.jti
      };

      const canonicalEventMaterial = computeCanonicalEventMaterial(claimsForChain);
      if (canonicalEventMaterial !== vector.expected.canonical_event_material) {
        throw new Error(`${vector.id}: canonical_event_material mismatch`);
      }

      const entryHashHex = computeEntryHash(
        vector.expected.prev_hash_hex,
        canonicalEventMaterial
      );
      if (entryHashHex !== vector.expected.entry_hash_hex) {
        throw new Error(`${vector.id}: entry_hash_hex mismatch`);
      }
    });
  }
});
