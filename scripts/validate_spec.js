#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const Ajv = require("ajv");

const ROOT_DIR = path.resolve(__dirname, "..");
const SPEC_DIR = path.join(ROOT_DIR, "spec");
const EXAMPLES_DIR = path.join(SPEC_DIR, "examples");
const VECTORS_DIR = path.join(SPEC_DIR, "vectors");

function sortRecursively(value) {
  if (Array.isArray(value)) {
    return value.map(sortRecursively);
  }

  if (value && typeof value === "object") {
    const sortedKeys = Object.keys(value).sort();
    const out = {};
    for (const key of sortedKeys) {
      out[key] = sortRecursively(value[key]);
    }
    return out;
  }

  return value;
}

function canonicalJson(value) {
  return JSON.stringify(sortRecursively(value));
}

function sha256Hex(utf8Input) {
  return crypto.createHash("sha256").update(utf8Input, "utf8").digest("hex");
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function collectJsonFiles(dirPath) {
  return fs
    .readdirSync(dirPath)
    .filter((name) => name.endsWith(".json"))
    .map((name) => path.join(dirPath, name))
    .sort();
}

function buildCanonicalEventMaterial(vector, inputHashHex, outputHashHex) {
  const eventMaterial = {
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

  return canonicalJson(eventMaterial);
}

function validateExamples(schema) {
  const ajv = new Ajv({ allErrors: true, strict: false });
  const validate = ajv.compile(schema);

  const exampleFiles = [
    path.join(EXAMPLES_DIR, "allow.json"),
    path.join(EXAMPLES_DIR, "deny.json"),
    path.join(EXAMPLES_DIR, "step_up.json")
  ];

  const failures = [];

  for (const filePath of exampleFiles) {
    const data = readJson(filePath);
    const ok = validate(data);

    if (!ok) {
      failures.push({
        filePath,
        errors: validate.errors || []
      });
      continue;
    }

    console.log(`PASS schema: ${path.relative(ROOT_DIR, filePath)}`);
  }

  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`FAIL schema: ${path.relative(ROOT_DIR, failure.filePath)}`);
      for (const err of failure.errors) {
        const where = err.instancePath || "(root)";
        console.error(`  - ${where}: ${err.message}`);
      }
    }
    throw new Error("Schema validation failed for one or more examples.");
  }
}

function validateVectors() {
  const vectorFiles = collectJsonFiles(VECTORS_DIR);
  const failures = [];

  for (const filePath of vectorFiles) {
    const vector = readJson(filePath);

    try {
      const canonicalInput = canonicalJson(vector.input);
      const canonicalOutput = canonicalJson(vector.output);
      const inputHashHex = sha256Hex(canonicalInput);
      const outputHashHex = sha256Hex(canonicalOutput);
      const canonicalEventMaterial = buildCanonicalEventMaterial(
        vector,
        inputHashHex,
        outputHashHex
      );
      const entryHashHex = sha256Hex(
        `${vector.expected.prev_hash_hex}${canonicalEventMaterial}`
      );

      const checks = [
        ["canonical_input", canonicalInput, vector.canonical_input],
        ["canonical_output", canonicalOutput, vector.canonical_output],
        ["expected.input_hash_hex", inputHashHex, vector.expected.input_hash_hex],
        ["expected.output_hash_hex", outputHashHex, vector.expected.output_hash_hex],
        [
          "expected.canonical_event_material",
          canonicalEventMaterial,
          vector.expected.canonical_event_material
        ],
        ["expected.entry_hash_hex", entryHashHex, vector.expected.entry_hash_hex]
      ];

      let vectorOk = true;

      for (const [label, got, want] of checks) {
        if (got !== want) {
          vectorOk = false;
          failures.push({
            filePath,
            label,
            got,
            want
          });
        }
      }

      if (vectorOk) {
        console.log(`PASS vector: ${path.relative(ROOT_DIR, filePath)} (${vector.id})`);
      }
    } catch (err) {
      failures.push({
        filePath,
        label: "runtime",
        got: String(err),
        want: "no error"
      });
    }
  }

  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`FAIL vector: ${path.relative(ROOT_DIR, failure.filePath)}`);
      console.error(`  - ${failure.label}`);
      console.error(`    got : ${failure.got}`);
      console.error(`    want: ${failure.want}`);
    }
    throw new Error("Vector validation failed.");
  }
}

function main() {
  const schemaPath = path.join(SPEC_DIR, "trustproof.schema.json");
  const schema = readJson(schemaPath);

  validateExamples(schema);
  validateVectors();

  console.log("All spec validations passed.");
}

main();
