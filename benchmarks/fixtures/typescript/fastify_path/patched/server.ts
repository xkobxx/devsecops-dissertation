// Patched benchmark equivalent with a root-confinement check.
import Fastify from "fastify";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

const app = Fastify();
const root = resolve("/srv/files");
app.get("/files", async (request, reply) => {
  const name = (request.query as { name: string }).name;
  const candidate = resolve(root, name);
  if (!candidate.startsWith(root + sep)) return reply.code(400).send("invalid path");
  return readFile(candidate, "utf8");
});
