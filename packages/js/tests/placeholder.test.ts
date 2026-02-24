import { describe, expect, it } from "vitest";

import { noop } from "../src";

describe("sdk placeholder", () => {
  it("noop returns undefined", () => {
    expect(noop()).toBeUndefined();
  });
});
