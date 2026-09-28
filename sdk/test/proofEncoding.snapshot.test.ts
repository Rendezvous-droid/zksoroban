// Snapshot tests for the SDK's proof/hash encoding output (zksoroban#90).
//
// Unlike encodingVectors.test.ts's hand-written assert.equal checks against
// hardcoded hex literals, these capture their expected output automatically
// into test/__snapshots__/*.snapshot the first time they run (or whenever
// intentionally refreshed) -- see sdk/README.md for how to update them. The
// point is the same either way: catch an encoding change in CI, before it
// ever reaches a contract on a real network.
import test from "node:test";

import { formatProof } from "../src/proof";
import { poseidon } from "../src/poseidon";
import { VALID_PUBLIC_SIGNALS, VALID_SNARKJS_PROOF } from "./fixtures";

test("formatProof output for the known poseidon_preimage fixture proof", (t) => {
  const calldata = formatProof(VALID_SNARKJS_PROOF, VALID_PUBLIC_SIGNALS);

  t.assert.snapshot({
    proofA: calldata.proofA.toString("hex"),
    proofB: calldata.proofB.toString("hex"),
    proofC: calldata.proofC.toString("hex"),
    publicInputs: calldata.publicInputs.map((input) => input.toString("hex"))
  });
});

test("poseidon output for known inputs", (t) => {
  const hash = poseidon([1n, 2n]);

  t.assert.snapshot({
    inputs: ["1", "2"],
    decimal: hash.toString(),
    hex: hash.toString(16)
  });
});

test("full wire-format hex blob: proofA + proofB + proofC + publicInputs concatenated", (t) => {
  const calldata = formatProof(VALID_SNARKJS_PROOF, VALID_PUBLIC_SIGNALS);
  const blob = Buffer.concat([
    calldata.proofA,
    calldata.proofB,
    calldata.proofC,
    ...calldata.publicInputs
  ]);

  t.assert.snapshot(blob.toString("hex"));
});
