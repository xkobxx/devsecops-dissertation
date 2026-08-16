// Deliberately vulnerable benchmark fixture. Do not deploy.
import Fastify from "fastify";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const app = Fastify();
app.get("/files", async (request) => {
  const name = (request.query as { name: string }).name;
  return readFile(join("/srv/files", name), "utf8");
});
