// Live run on Studionet against the real GitHub Advisory Database.
// Opens a fastify bounty, then lets validators evaluate real advisories:
// one in scope, one out of scope (DoS), one with a non-finder credit, one for the
// wrong package. Then shows identity binding rejecting a login we do not control,
// and a claim from an unregistered address being refused.
//   node scripts/live_demo.mjs <contractAddress>
import { createClient, createAccount, generatePrivateKey } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import { TransactionStatus } from "genlayer-js/types";
import fs from "node:fs";

const address = process.argv[2];
const GEN = 10n ** 18n;
const SCOPE =
  "Remote code execution or authentication/authorization bypass reachable through " +
  "fastify's request routing or parsing. Denial of service and crashes are excluded.";

function loadKey(name) {
  const env = fs.existsSync(".env") ? fs.readFileSync(".env", "utf8") : "";
  const m = env.match(new RegExp(`^${name}=(0x[0-9a-f]+)`, "m"));
  if (m) return m[1];
  const pk = generatePrivateKey();
  fs.appendFileSync(".env", `${name}=${pk}\n`);
  return pk;
}

async function fund(addr) {
  await fetch(studionet.rpcUrls.default.http[0], {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "sim_fundAccount", params: [addr, Number(1000n * GEN)] }),
  });
}

const plain = (x) =>
  JSON.parse(JSON.stringify(x ?? null, (_, v) => (typeof v === "bigint" ? v.toString() : v instanceof Map ? Object.fromEntries(v) : v)));

const sponsor = createAccount(loadKey("DEMO_SPONSOR_PK"));
const researcher = createAccount(loadKey("DEMO_RESEARCHER_PK"));
const client = createClient({ chain: studionet });
await fund(sponsor.address);
await fund(researcher.address);

async function write(account, functionName, args, value = 0n) {
  const hash = await client.writeContract({ account, address, functionName, args, value });
  const receipt = await client.waitForTransactionReceipt({ hash, status: TransactionStatus.ACCEPTED, retries: 120, interval: 5000 });
  const lr = receipt?.consensus_data?.leader_receipt?.[0] ?? {};
  const out = {
    fn: functionName,
    args,
    tx: hash,
    status: receipt?.status_name,
    execution: lr.execution_result,
    votes: receipt?.consensus_data?.validator_votes_name,
    result: plain(lr.result),
    stderr: lr.genvm_result?.stderr ? String(lr.genvm_result.stderr).slice(-400) : undefined,
  };
  console.log(JSON.stringify(out));
  return out;
}
const read = async (functionName, args) => plain(await client.readContract({ address, functionName, args }));

const now = Math.floor(Date.now() / 1000);
const eligibleFrom = Math.floor(Date.UTC(2026, 8, 1) / 1000); // 2026-09-01: retroactive bounty
const deadline = now + 30 * 86400;

const steps = [];
const bountyId = Number(await read("get_count", []));
steps.push(await write(sponsor, "open_bounty", ["npm", "fastify", SCOPE, "medium", eligibleFrom, deadline], 10n * GEN));

const previews = [
  ["GHSA-p68q-wchp-6fh7", "vvvvvvvvvvitel"], // auth bypass, reporter -> expect accepted
  ["GHSA-4mh8-r7rc-xpvc", "zerovulnlabs"],   // DoS, reporter -> expect out of scope
  ["GHSA-p68q-wchp-6fh7", "mcollina"],       // credited as remediation_developer -> not credited
  ["GHSA-hxh3-vqpv-xpqv", "ggmolly"],        // hono advisory -> wrong package
];
const verdicts = [];
for (const [ghsa, login] of previews) {
  const s = await write(researcher, "preview_claim", [bountyId, ghsa, login]);
  steps.push(s);
  verdicts.push({ ghsa, login, tx: s.tx, votes: s.votes, verdict: await read("get_verdict", [bountyId, ghsa, login]) });
}

// identity: we do not control this GitHub account, so binding it must fail
steps.push(await write(researcher, "register_researcher", ["vvvvvvvvvvitel"]));
// an unregistered address cannot claim even an eligible advisory
steps.push(await write(researcher, "claim", [bountyId, "GHSA-p68q-wchp-6fh7"]));

const out = {
  contract: address,
  network: "studionet",
  run_at: new Date().toISOString(),
  sponsor: sponsor.address,
  researcher: researcher.address,
  bounty_id: bountyId,
  bounty: await read("get_bounty", [bountyId]),
  researcher_binding: await read("get_researcher", ["vvvvvvvvvvitel"]),
  verdicts,
  steps,
};
fs.writeFileSync("demo_result.json", JSON.stringify(out, null, 2));
console.log(JSON.stringify({ bounty: out.bounty, verdicts }, null, 2));
