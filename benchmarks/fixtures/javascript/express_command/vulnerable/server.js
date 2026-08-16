// Deliberately vulnerable benchmark fixture. Do not deploy.
const express = require("express");
const { exec } = require("node:child_process");
const app = express();

app.get("/diagnostics", (request, response) => {
  exec(request.query.command, (error, stdout) => response.send(stdout));
});
