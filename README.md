# AdvisoryBounty

Security bug bounty escrow on GenLayer. Payouts are decided from the public GitHub Security Advisory record, not by the sponsor who pays them.

## The trust problem

In a normal bug bounty the party that pays also decides whether to pay. Researchers report a real vulnerability and then hear "out of scope", "duplicate" or "lower severity than you think", and there is nobody neutral to appeal to. Sponsors face the opposite risk: someone claims credit for a bug they did not find.

Most of the facts already exist in a public, authoritative record. When a maintainer publishes a GitHub Security Advisory, GitHub reviews it and lists the affected package, the severity, the weakness class (CWE), the publication time, whether it was withdrawn, and who is credited as finder or reporter. Code can check all of that. What is left is one judgment: does this vulnerability fall inside the scope the sponsor wrote?

AdvisoryBounty gives the facts to code and the judgment to GenLayer validators. The sponsor locks the reward up front and never decides the payout.

## How it works

1. **The sponsor opens a bounty.** It names an ecosystem and package (for example `npm` / `fastify`), a scope in plain language, a minimum severity, an eligibility window (`eligible_from` to `deadline`) and locks the reward as `msg.value`.
2. **The researcher proves who they are.** `register_researcher(login)` makes validators fetch `https://raw.githubusercontent.com/<login>/<login>/HEAD/README.md`, the account's public profile README. Only the owner of a GitHub account can write to that repository. The README must contain the caller's address. Validators agree on one boolean ("is the address there"), so this step needs no LLM.
3. **The researcher claims** with `claim(bounty_id, ghsa_id)`. The leader fetches `https://api.github.com/advisories/<GHSA>` and runs these checks in code:

   | Check | Rule |
   |---|---|
   | `reviewed` | `type == "reviewed"`. GitHub-reviewed advisories only, no unreviewed or malware entries |
   | `not_withdrawn` | `withdrawn_at` is null |
   | `published_in_window` | `eligible_from <= published_at <= deadline` |
   | `package_match` | some `vulnerabilities[].package` equals the bounty's ecosystem and name (case-insensitive) |
   | `severity_ok` | `severity` is at least `min_severity` (low < medium < high < critical) |
   | `credited` | the caller's verified login is in `credits` with type `finder` or `reporter` |

   Only if all six pass, the LLM is asked whether the advisory's summary, CWEs and description fall within the sponsor's scope. It answers `{"in_scope": bool, "reason": str}`.
4. **Validators verify independently.** Each one re-fetches the advisory and re-runs the whole evaluation. It accepts the leader's result only if the six checks are identical and the `in_scope` boolean is the same. The free-text reason is not compared. A leader that reports passing checks the advisory does not support, or a different scope decision, is rejected. Errors are tagged (`[EXPECTED]`, `[EXTERNAL]`, `[TRANSIENT]`, `[LLM_ERROR]`), and a validator accepts a leader error only if it hits the same one.
5. **Settlement.** The contract decides "accepted" from the agreed checks and `in_scope`, not from anything the leader asserts. If accepted, the reward goes to the researcher's verified address, the bounty becomes `paid`, and that GHSA can never be paid again by any bounty. Every evaluation, accepted or not, is stored with its reason (`get_verdict`).
6. **Reclaim.** If nobody qualified, the sponsor can `reclaim` the reward 7 days after the deadline. The grace period means a researcher whose advisory was published just before the deadline still has time to claim. The sponsor cannot pull the money while a claim could still be valid.

`preview_claim(bounty_id, ghsa_id, github_login)` runs the same consensus evaluation for any login and stores the verdict without paying. A researcher can check eligibility before publishing a profile README and claiming. A sponsor can check how validators read their scope against real advisories.

### Prompt injection

Advisory text is written by third parties and could include text aimed at the model. It is passed inside `<advisory>` tags, any `<advisory>` or `</advisory>` tags inside the text are stripped so it cannot close the block, the model is told to treat it as data, and unclear cases default to `false`. The test suite checks this: when the stripping is removed, the test fails. The LLM also only runs after the code checks pass, so injected text cannot change package, severity, credit or timing.

## Live run on real data (Studionet, 2026-10-01)

Contract: `0x5e1DEFa174bDD1e5d74984449dCbb2aB308420e9` (deploy tx `0xd3359441…8734`)

Bounty 0 locks 10 GEN for `npm` / `fastify`, minimum severity `medium`, eligible from 2026-09-01. Scope: *"Remote code execution or authentication/authorization bypass reachable through fastify's request routing or parsing. Denial of service and crashes are excluded."* Validators then evaluated four real advisories that fastify and hono published on 2026-09-30, fetched live from the GitHub API:

| Advisory | Login | Code checks | Scope (LLM) | Verdict | Tx |
|---|---|---|---|---|---|
| GHSA-p68q-wchp-6fh7, fastify auth bypass via malformed URLs (high, CWE-288) | vvvvvvvvvvitel (reporter) | all pass | in scope: "enables authentication bypass via Fastify's request routing/parsing" | **accepted** | `0xb727b217…0bdf` |
| GHSA-4mh8-r7rc-xpvc, fastify DoS on HTTP/2 trailers (medium, CWE-248) | zerovulnlabs (reporter) | all pass | out of scope: "denial of service and process crash … excluded" | **rejected** | `0x127f86e8…275d` |
| GHSA-p68q-wchp-6fh7, same auth bypass | mcollina (credited as remediation_developer) | `credited` fails | not asked | **rejected** | `0x7d986324…830c` |
| GHSA-hxh3-vqpv-xpqv, hono XSS | ggmolly (reporter) | `package_match` fails | not asked | **rejected** | `0x6c0560c5…b1ce` |

These were `preview_claim` calls, so nothing was paid. The bounty is still `open` with 10 GEN locked.

The identity and payout steps were also run live, and they failed as they should:
- `register_researcher("vvvvvvvvvvitel")` from the demo address was rolled back with `[EXPECTED] vvvvvvvvvvitel has no public profile README` (tx `0x8391b74f…40c3`). We do not control that account, so we could not bind it.
- `claim(0, "GHSA-p68q-wchp-6fh7")` from the same unregistered address was rolled back with `[EXPECTED] register your GitHub login first` (tx `0x12ecad98…b9b9f`). The advisory is eligible, but the reward cannot go to someone who has not proved they are the credited reporter.

The one step we could not show live is a real payout: it needs control of a GitHub account that is credited on an advisory. The direct-mode tests cover the payout with the real advisory as fixture. Full output is in `demo_result.json`. To reproduce, run `node scripts/live_demo.mjs <contract address>`.

## Contract API

| Method | Kind | Description |
|---|---|---|
| `open_bounty(ecosystem, package, scope, min_severity, eligible_from, deadline)` | payable write | `msg.value` is the reward. Unix seconds. `eligible_from` can be up to 90 days back (retroactive bounty); `deadline` is up to 365 days ahead. Returns the bounty id. |
| `register_researcher(github_login)` | write | Binds the login to the caller if the login's profile README contains the caller's address. Re-registering from a new address moves the binding. |
| `claim(bounty_id, ghsa_id)` | write | Evaluates the advisory for the caller's verified login and pays the reward if accepted. Returns the verdict. |
| `preview_claim(bounty_id, ghsa_id, github_login)` | write | Same evaluation, any login, no payment. Returns and stores the verdict. |
| `reclaim(bounty_id)` | write | Sponsor only, after `deadline + 7 days`, if unpaid. |
| `get_bounty(id)` / `get_researcher(login)` / `get_verdict(id, ghsa, login)` / `get_count()` | view | |

Ecosystems use GitHub's names: `actions, composer, erlang, go, maven, npm, nuget, pip, pub, rubygems, rust, swift`.

## Build and test

```bash
py -3.12 -m venv .venv && .venv/Scripts/pip install genlayer-test
.venv/Scripts/python -X utf8 -m pytest tests -q
```

The fixtures in `tests/fixtures/` are trimmed copies of real advisories (fastify auth bypass GHSA-p68q-wchp-6fh7, fastify DoS GHSA-4mh8-r7rc-xpvc, hono XSS GHSA-hxh3-vqpv-xpqv). The direct-mode tests cover:
- input validation and normalization
- identity binding: pass, README without the address, missing README, bad login, and a validator rejecting a leader that lies about the README
- in-scope claim paying once, the same GHSA blocked on a second bounty, an out-of-scope claim recorded but not paid
- deterministic rejections: withdrawn, unreviewed, wrong package, severity too low, outside the window, credited only as remediation developer, not credited at all. In these tests no LLM mock is registered, so they also prove the model is never asked when code already said no
- consensus: validators reject a forged "all checks passed" leader result and a different scope decision, and accept a differently worded reason
- error agreement for 404 / 403 / 5xx and non-boolean model output
- prompt injection
- reclaim timing, sponsor-only, and no double reclaim

Deploy:

```bash
genlayer network set studionet
genlayer deploy --contract contracts/advisory_bounty.py
npm i && node scripts/live_demo.mjs <contract address>
```

## Design choices and limits

- **Payout trigger is publication.** The advisory record decides. A bug the maintainer never publishes cannot be paid. That is the price of not trusting the sponsor's word either way. It also means the maintainer controls timing. If the maintainer is also the sponsor, they could delay publication past the deadline. The 7-day claim grace helps only with short delays.
- **Retroactive bounties are allowed.** `eligible_from` can be up to 90 days in the past, so a sponsor can reward recently disclosed issues. A sponsor who wants prospective-only rewards sets `eligible_from` to the open time.
- **Finder and reporter only.** `remediation_developer`, `remediation_reviewer`, `analyst`, `coordinator` and other credit types do not count. Fixing a bug is not finding it.
- **One advisory, one payout; one bounty, one winner.** The first accepted claim takes the whole reward. If several people are credited as finders, the first to claim gets paid. There is no splitting.
- **Identity through the profile README.** The README is served from a CDN with a cache of about 5 minutes, so wait a few minutes after editing it. Losing control of the GitHub account means losing the binding.
- **GitHub rate limits.** The advisory API allows 60 unauthenticated requests per hour per IP. Each evaluation costs one request per validator. A 403 is tagged `[TRANSIENT]`, so the transaction fails cleanly instead of reaching a wrong verdict.
- **The scope judgment is an LLM judgment.** Validators must agree on the boolean. A vague scope gives a less predictable result. `preview_claim` lets the sponsor test a scope before relying on it.
