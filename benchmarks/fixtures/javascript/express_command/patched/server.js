// Patched benchmark equivalent. It is still not a deployable application.
const express = require("express");
const { execFile } = require("node:child_process");
const app = express();

app.get("/diagnostics", (request, response) => {
  const targets = { dns: ["example.test"], loopback: ["127.0.0.1"] };
  const args = targets[request.query.target];
  if (!args) return response.status(400).send("unsupported target");
  execFile("/usr/bin/dig", args, (error, stdout) => response.send(stdout));
});
