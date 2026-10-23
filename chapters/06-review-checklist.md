# Simulation Security Review Checklist

This chapter turns the book into a checklist you can use in three settings: reviewing a wallet's simulation pipeline, reviewing a security API or token scanner, and reviewing a suspicious contract. Each item names the chapter that explains it. Treat a "no" as a finding to triage, not an automatic failure: some controls cost latency and some products accept that trade-off knowingly.

## Scope and rules of engagement

Before you start:

- Get written authorisation from the product owner. Testing a vendor's simulation API at scale without permission may breach its terms and can look like abuse.
- Use local chains and forks for every evasive contract. Never deploy lab honeypots or evasive contracts to public networks where real users could interact with them.
- If you find a bypass in a third-party wallet or scanner, report it privately through the vendor's security contact or bug bounty, give a reasonable fix window, and coordinate publication. ZenGo's Red Pill research is a good example of vendor-coordinated disclosure followed by public write-up.

## Part A: wallet simulation pipeline

### Context realism (Chapter 2, Chapter 5)

| # | Check | Evidence to collect |
|---|---|---|
| A1 | No zero or constant `block.coinbase` in simulations | Run a context probe contract through the wallet's preview path |
| A2 | `tx.gasprice` and base fee match what the wallet will submit | Probe output vs submitted transaction |
| A3 | Gas limit in simulation equals the gas limit that will be signed | Compare preview trace and signed tx |
| A4 | Timestamp and block number reflect the next block, not the parent | Probe output |
| A5 | `prevrandao` not constant across runs | Two probes, compare |
| A6 | Simulation runs from the real user address | Probe `tx.origin` |

### Differential and invariant checks (Chapter 5)

| # | Check | Evidence |
|---|---|---|
| A7 | At least two contexts per transaction, varying several fields at once | Code review, logs |
| A8 | Comparison uses normalised asset deltas, not logs or success flags | Code review |
| A9 | Approvals to EOAs and unlimited approvals flagged | Test with lab ERC-20 |
| A10 | Outflows of assets not mentioned by the dApp flagged | Test with lab contract that pulls an extra token |
| A11 | Context-dependent results produce a block or strong warning, not a silent "success" | Run `RedPillDemo` |

### Freshness (Chapter 3)

| # | Check | Evidence |
|---|---|---|
| A12 | Re-simulation immediately before signing | Run `FlipClaim`, flip state between dialog open and confirm |
| A13 | Preview displays block number and expires after one or two slots | UI review |
| A14 | Target contract storage change between simulations triggers warning | Lab test |
| A15 | Proxy and recently deployed targets labelled | Lab proxy deployed minutes earlier |

### Messages and signatures (Chapter 3)

| # | Check | Evidence |
|---|---|---|
| A16 | EIP-712 permits and orders decoded: spender, token, amount, deadline | Sign lab Permit and Permit2 messages |
| A17 | Long-dated or unlimited permits flagged | Lab test |
| A18 | `eth_sign` of raw hashes blocked or loudly warned | Lab test |

### Infrastructure (Chapter 5)

| # | Check | Evidence |
|---|---|---|
| A19 | Simulation node is current; lag monitored | Compare head with a second source |
| A20 | RPC gas cap close to real block gas limit | Node configuration |
| A21 | Submission path documented (public mempool vs private relay) and users told which | Docs, settings |

## Part B: security API or token scanner

| # | Check | Evidence |
|---|---|---|
| B1 | Buy-then-sell round trip simulated from fresh EOAs with plausible balances | Run `TrapToken` |
| B2 | Same round trip under several contexts; disagreement reported | Lab test |
| B3 | Re-scans over time, not only at launch | Time-gated lab token |
| B4 | Owner-only setters for fees, whitelists, pause flags reported | Static analysis output |
| B5 | Unverified bytecode and source/bytecode mismatches reported | Lab deployment without verification |
| B6 | Static scan for reads of `block.*`, `tx.*`, `gasleft()` in transfer paths | Rule list review |
| B7 | API response states which contexts were simulated | API docs |

## Part C: reviewing a suspicious contract

1. Fetch bytecode and verified source; confirm they match.
2. List every read of `COINBASE`, `TIMESTAMP`, `NUMBER`, `BASEFEE`, `GASPRICE`, `GAS`, `ORIGIN`, `PREVRANDAO`, `EXTCODESIZE`, `EXTCODEHASH`, `SELFBALANCE`. For each, ask why a legitimate contract would need it in this path.
3. List owner-controlled state and its setters. Review their call history.
4. Check proxy patterns and admin keys.
5. Run multi-context differential simulation on a fork for each externally callable function a victim would call.
6. Run symbolic analysis (Mythril or similar) and look for environment-conditioned branches.
7. Write up: fiction shown, fact concealed, trigger condition, affected wallets or scanners, and indicators for others.

For deeper malware triage, continue with **onchain-malware-analysis**. If the target is an AI agent that signs automatically, apply Part A to the agent's toolchain and read **ai-agent-wallet-security**.

## Severity guidance

| Finding | Suggested severity |
|---|---|
| Constant placeholder that lets a contract detect simulation (A1–A5) | High for wallets, medium for offline scanners |
| No re-simulation before signing (A12) | High |
| Preview compares success only, not asset deltas (A8) | High |
| Permits not decoded (A16) | High |
| No RPC lag monitoring (A19) | Medium |
| Submission path undocumented (A21) | Low |

## Writing the report

A useful finding states four things: the condition the attacker controls, the evidence that the product's preview diverged from real execution, the user-visible consequence, and a concrete fix. "Simulation uses zero coinbase" is weak. "A lab contract that branches on `block.coinbase == 0` showed a refund in the preview and kept 1 ETH on inclusion; screenshot and transaction hash attached; fix by sampling a recent fee recipient and adding a second context" is actionable. Keep lab contracts and scripts with the report so the vendor can reproduce the issue on their own fork. Re-test after the fix: evasive behaviour often moves to the next unpatched field, so rerun the whole Part A table rather than the single item.

Adjust to your product's threat model; a hardware wallet companion app that also shows decoded calldata on a trusted screen has different risks from a browser extension. See **hardware-wallet-security**.

## Worked example

> **Execution status:** Not executed in this book's CI; verify locally against a wallet build you control, connected to a local Anvil chain.

1. Run `anvil` and connect a development build of the wallet under review (or a browser wallet configured with a custom RPC at `http://127.0.0.1:8545`).
2. Deploy the lab contracts from Chapters 1–4: `ContextProbe`, `RedPillDemo`, `FlipClaim`, `TrapToken`.
3. Point a minimal local dApp page (a single HTML file using `window.ethereum.request`) at each contract.
4. For each checklist item in Part A, trigger the case and record the preview shown, a screenshot, and whether the wallet blocked, warned or approved.
5. For A12, open the confirmation dialog, run `cast send <flip> "arm(bool)" true` from the owner key, then confirm. Record whether the wallet re-simulated.
6. Fill the table with pass, fail or not applicable, and attach evidence.

## Common pitfalls

- **Testing only the happy path.** Every item above needs an adversarial lab contract.
- **Reviewing code without running it.** Simulation bugs often live in configuration, not code.
- **Ignoring the UI.** A correct delta hidden behind a "details" toggle protects nobody.
- **Public test deployments.** Lab honeypots on public testnets still mislead people and tools.
- **Skipping disclosure.** Bypasses in third-party wallets go to the vendor first.

## Exercises

1. Apply Part A to a wallet you can build locally and produce a findings table with evidence.
2. Apply Part B to an open-source token scanner and propose patches for any failed items.
3. Pick a real contract flagged as a drainer in public reports and run Part C on a fork, writing the "fiction shown / fact concealed" summary.

## Further reading

- ZenGo Red Pill coverage (2023): <https://www.bleepingcomputer.com/news/security/coinbase-wallet-red-pill-flaw-allowed-attacks-to-evade-detection/>
- ScamSniffer, transaction simulation spoofing (2025): <https://drops.scamsniffer.io/transaction-simulation-spoofing-a-new-threat-in-web3>
- EIP-712 typed structured data signing: <https://eips.ethereum.org/EIPS/eip-712>
- CERT Guide to Coordinated Vulnerability Disclosure: <https://certcc.github.io/CERT-Guide-to-CVD/>
- Torres, Steichen and State, "The Art of The Scam", USENIX Security 2019
