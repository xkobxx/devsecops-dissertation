// Vulnerable pattern in unreachable benchmark code: never imported or called.
const { exec } = require("node:child_process");

function abandonedPrototype(input) {
  exec(input);
}
