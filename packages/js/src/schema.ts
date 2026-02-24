import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import Ajv, { type ErrorObject, type ValidateFunction } from "ajv";

let validator: ValidateFunction | null = null;

function resolveModuleUrl(): string {
  const importMetaUrl = new Function(
    "try { return import.meta.url; } catch { return undefined; }"
  )() as string | undefined;

  if (importMetaUrl) {
    return importMetaUrl;
  }

  if (typeof __filename === "string" && __filename.length > 0) {
    return pathToFileURL(__filename).href;
  }

  throw new Error("Unable to determine module URL for schema resolution.");
}

function resolveSchemaUrl(): URL {
  const moduleUrl = resolveModuleUrl();

  const directUrl = new URL("../../../spec/trustproof.schema.json", moduleUrl);
  if (existsSync(fileURLToPath(directUrl))) {
    return directUrl;
  }

  const distUrl = new URL("../../../../spec/trustproof.schema.json", moduleUrl);
  if (existsSync(fileURLToPath(distUrl))) {
    return distUrl;
  }

  let currentDir = dirname(fileURLToPath(moduleUrl));

  for (let depth = 0; depth < 8; depth += 1) {
    const candidatePath = join(currentDir, "spec", "trustproof.schema.json");
    if (existsSync(candidatePath)) {
      return pathToFileURL(candidatePath);
    }

    const parentDir = dirname(currentDir);
    if (parentDir === currentDir) {
      break;
    }

    currentDir = parentDir;
  }

  throw new Error("Unable to locate spec/trustproof.schema.json from module path.");
}

function cloneAjvErrors(errors: ErrorObject[] | null | undefined): ErrorObject[] {
  return (errors ?? []).map((error) => ({
    ...error,
    params: { ...error.params }
  }));
}

function loadSchema(): Record<string, unknown> {
  const schemaUrl = resolveSchemaUrl();
  return JSON.parse(readFileSync(schemaUrl, "utf8")) as Record<string, unknown>;
}

function getValidator(): ValidateFunction {
  if (validator) {
    return validator;
  }

  const ajv = new Ajv({
    allErrors: true,
    strict: false,
    validateSchema: false
  });

  validator = ajv.compile(loadSchema());
  return validator;
}

export function validateEnvelopeSchema(value: unknown): {
  valid: boolean;
  errors: ErrorObject[];
} {
  const validate = getValidator();
  const valid = validate(value);

  if (valid) {
    return { valid: true, errors: [] };
  }

  return {
    valid: false,
    errors: cloneAjvErrors(validate.errors)
  };
}

export function formatAjvErrors(errors: ErrorObject[]): string {
  if (errors.length === 0) {
    return "unknown schema validation error";
  }

  return errors
    .map((error) => {
      const location = error.instancePath || "(root)";
      return `${location} ${error.message ?? "invalid"}`;
    })
    .join("; ");
}
