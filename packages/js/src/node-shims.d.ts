declare const __filename: string;

declare module "node:crypto" {
  export function createHash(algorithm: string): {
    update(data: string, encoding?: "utf8"): {
      digest(encoding: "hex"): string;
    };
    digest(encoding: "hex"): string;
  };
}

declare module "node:fs" {
  export function existsSync(path: string): boolean;
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
}

declare module "node:path" {
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
}

declare module "node:url" {
  export function fileURLToPath(url: string | URL): string;
  export function pathToFileURL(path: string): URL;
}
