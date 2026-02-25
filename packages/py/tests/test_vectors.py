from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustproof.chain import (  # noqa: E402
    canonical_json,
    compute_canonical_event_material,
    compute_entry_hash,
    sha256_hex,
)


def _vector_files() -> list[Path]:
    repo_root = Path(__file__).resolve().parents[3]
    vectors_dir = repo_root / "spec" / "vectors"
    return sorted(vectors_dir.glob("*.json"))


def test_golden_vectors_cross_language_parity() -> None:
    vector_paths = _vector_files()
    assert vector_paths, "No vector JSON files found in spec/vectors."

    for vector_path in vector_paths:
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        vector_id = vector.get("id", vector_path.stem)

        canonical_input = canonical_json(vector["input"])
        assert canonical_input == vector["canonical_input"], (
            f"{vector_id}: canonical_input mismatch"
        )

        canonical_output = canonical_json(vector["output"])
        assert canonical_output == vector["canonical_output"], (
            f"{vector_id}: canonical_output mismatch"
        )

        input_hash_hex = sha256_hex(canonical_input)
        output_hash_hex = sha256_hex(canonical_output)
        assert input_hash_hex == vector["expected"]["input_hash_hex"], (
            f"{vector_id}: input_hash_hex mismatch"
        )
        assert output_hash_hex == vector["expected"]["output_hash_hex"], (
            f"{vector_id}: output_hash_hex mismatch"
        )

        claims_for_chain = {
            "subject": vector["input"]["subject"],
            "action": vector["input"]["action"],
            "resource": vector["input"]["resource"],
            "policy": vector["input"]["policy"],
            "result": vector["output"],
            "hashes": {
                "input_hash": input_hash_hex,
                "output_hash": output_hash_hex,
            },
            "timestamp": vector["input"]["timestamp"],
            "jti": vector["input"]["jti"],
        }

        canonical_event_material = compute_canonical_event_material(claims_for_chain)
        assert canonical_event_material == vector["expected"]["canonical_event_material"], (
            f"{vector_id}: canonical_event_material mismatch"
        )

        entry_hash_hex = compute_entry_hash(
            vector["expected"]["prev_hash_hex"], canonical_event_material
        )
        assert entry_hash_hex == vector["expected"]["entry_hash_hex"], (
            f"{vector_id}: entry_hash_hex mismatch"
        )
