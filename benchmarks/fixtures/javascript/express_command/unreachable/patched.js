// Patched equivalent of an unreachable prototype.
const { execFile } = require("node:child_process");

function abandonedPrototype() {
  execFile("/usr/bin/true", []);
}
