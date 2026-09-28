// Preloaded via `--require` before the test suite runs (see package.json's
// "test" script). Configures node:test's built-in snapshot testing
// (https://nodejs.org/api/test.html#snapshot-testing) so snapshot files land
// in test/__snapshots__/ next to the test that owns them, instead of node's
// default of a flat `<test-file>.snapshot` sitting directly in test/.
//
// `--require` loads this as CommonJS, so this file uses require()/module
// syntax rather than import/export -- an ESM-style version here fails to
// load (silently, as a warning) and cancels the rest of the suite.
const { snapshot } = require("node:test");
const path = require("node:path");

snapshot.setResolveSnapshotPath((testFilePath: string) => {
  const dir = path.join(path.dirname(testFilePath), "__snapshots__");
  return path.join(dir, `${path.basename(testFilePath)}.snapshot`);
});
