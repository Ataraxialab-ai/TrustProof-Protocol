function sortRecursively(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortRecursively);
  }

  if (value && typeof value === "object") {
    const sortedKeys = Object.keys(value).sort();
    const out: Record<string, unknown> = {};

    for (const key of sortedKeys) {
      out[key] = sortRecursively((value as Record<string, unknown>)[key]);
    }

    return out;
  }

  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortRecursively(value));
}
