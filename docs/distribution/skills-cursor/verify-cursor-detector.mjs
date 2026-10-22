// Offline replay of the pinned Cursor Directory detector; does not submit.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { stripTypeScriptTypes } from "node:module";

const upstreamSha = "e81660652954a089f443d0032afd7de3bea73217";
const hashes = {
  "parse.ts": "a9c6d9d18c9813e56a8c39e3d67934d025a66e1914ec20d2cc7cc8dfc103d788",
  "slug.ts": "fea2e12d8af3c8b5332662643288be14c116c6b8627200e4dc9ea3a38ccfa02a",
};
const repoDir = fs.realpathSync(process.argv[2]);
const sourceDir = fs.realpathSync(process.argv[3]);
const sha256 = (v) => crypto.createHash("sha256").update(v).digest("hex");
const readSource = (name) => {
  const bytes = fs.readFileSync(path.join(sourceDir, name));
  assert.equal(sha256(bytes), hashes[name], "Unexpected upstream source");
  return bytes.toString("utf8");
};
const readLocal = (relativePath) => {
  const file = path.resolve(repoDir, relativePath);
  if (!file.startsWith(repoDir + path.sep) || !fs.existsSync(file)) return null;
  const real = fs.realpathSync(file);
  if (!real.startsWith(repoDir + path.sep) || !fs.statSync(real).isFile()) return null;
  return fs.readFileSync(real, "utf8");
};
const body = (s) => {
  const match = s.match(/^---\n[\s\S]*?\n---\n([\s\S]*)$/);
  assert(match, "Expected LF frontmatter");
  return match[1].trim();
};
let source = readSource("parse.ts");
assert(source.includes('import { slugify } from "@/lib/slug";'));
source = source.replace('import { slugify } from "@/lib/slug";',
  readSource("slug.ts").replace(/export const/g, "const").replace(/export function/g, "function"));
const js = stripTypeScriptTypes(source, { mode: "transform" });
const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { cwd: repoDir, encoding: "utf8" }).split("\0").filter(Boolean);
const requests = [];
globalThis.fetch = async (input) => {
  const url = String(input);
  requests.push(url);
  if (url === "https://api.github.com/repos/toby-bridges/api-relay-audit/git/trees/HEAD?recursive=1") {
    return Response.json({ tree: [...new Set(files)].map((p) => ({ path: p, type: "blob" })) });
  }
  const prefix = "https://raw.githubusercontent.com/toby-bridges/api-relay-audit/HEAD/";
  if (!url.startsWith(prefix)) throw new Error("Unexpected fetch blocked");
  const text = readLocal(url.slice(prefix.length));
  return text === null ? new Response("", { status: 404 }) : new Response(text);
};
const detector = await import("data:text/javascript;base64," + Buffer.from(js).toString("base64"));
const result = await detector.parseGitHubPlugin("https://github.com/toby-bridges/api-relay-audit", {
  repoMeta: { id: 1, stars: 0, fork: false, archived: false, default_branch: "master", license_spdx: "AGPL-3.0-only" },
});
const nested = readLocal("skills/api-relay-audit/SKILL.md");
assert.equal(body(readLocal("SKILL.md")), body(nested));
assert.equal(result.components.length, 1);
const component = result.components[0];
assert.equal(component.type, "skill");
assert.equal(component.name, "api-relay-audit");
assert.equal(component.slug, "api-relay-audit");
assert(component.description);
assert.equal(component.content, body(nested));
assert(!component.content.startsWith("---"));
assert.deepEqual(component.metadata, {});
assert(requests.some((u) => u.endsWith("/HEAD/skills/api-relay-audit/SKILL.md")));
assert(!requests.some((u) => u.endsWith("/HEAD/SKILL.md")));
console.log(JSON.stringify({
  upstream_sha: upstreamSha, source_sha256: hashes, actual_network_requests: 0,
  mocked_requests: requests.length, root_and_nested_bodies_equal: true,
  component: { type: component.type, name: component.name, slug: component.slug,
    description: component.description, content_sha256: sha256(component.content),
    content_bytes: Buffer.byteLength(component.content), copied_frontmatter: false },
}, null, 2));
