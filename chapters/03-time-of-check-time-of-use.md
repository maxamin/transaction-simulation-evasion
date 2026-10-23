# Time-of-Check, Time-of-Use and State Races

Chapter 2 was about *where* a transaction runs. This chapter is about *when*. A wallet simulates at one moment and the transaction executes at a later one. Anything the attacker can change in between can turn an honest preview into a lie, with no need to detect the simulator at all.

## The classic TOCTOU pattern, on-chain

Time-of-check to time-of-use (TOCTOU) bugs are familiar from operating systems. Rex Guo and Junyuan Zeng's "Phantom Attack: Evading System Call Monitoring" (DEF CON 29, 2021) showed that Linux syscall monitors which read arguments at one moment can be fooled when a racing thread changes the memory before the kernel uses it. The monitor checks one value; the kernel acts on another.

Wallet simulation has the same shape:

1. **Check.** The wallet simulates against state at block N and shows the preview.
2. **Gap.** The user reads the preview, thinks, and clicks. The wallet signs and submits. Seconds to minutes pass.
3. **Use.** The transaction executes in block N+k against whatever state exists then.

The attacker controls the contract, so they control its storage. They do not need to detect anything. They only need to flip a switch after the check.

## A documented case: simulation spoofing

In January 2025 the anti-scam firm ScamSniffer reported what it called **transaction simulation spoofing**. As described in its write-up and in BleepingComputer's coverage, a phishing site offered a "claim" transaction. The wallet's simulation showed the user receiving a small amount of ETH. After the simulation, the attacker's backend changed the contract's state, and when the victim signed roughly 30 seconds later the transaction drained the wallet. ScamSniffer attributed a loss of about 143 ETH to one victim (BleepingComputer gives 143.35 and 143.45 ETH in different passages). ScamSniffer recommended that wallets align simulation refresh intervals with block times, force a refresh before signing, and warn when a preview has expired.

The mechanics are simple enough to reproduce in a lab (see the worked example), which is why every wallet should assume this attack exists.

## Variants of the time gap

| Variant | What changes between check and use | Who controls it |
|---|---|---|
| Storage flip | A `mode` flag, recipient address or fee in the attacker's contract | Attacker |
| Proxy upgrade | Implementation behind a proxy is swapped | Attacker (proxy admin) |
| Metamorphic code | Contract destroyed and redeployed with new code at same address (largely closed off by EIP-6780 restricting `SELFDESTRUCT`, but legacy patterns and factories exist) | Attacker |
| Price or pool state | AMM reserves move; slippage changes output | Market, MEV searchers, attacker |
| Approval reuse | Preview shows a small transfer, but the approval granted persists and is used later by a separate transaction | Attacker |
| Signature use | An EIP-712 permit or order is previewed as "sign message", then submitted by the attacker whenever they choose | Attacker |
| Ordering | Attacker's own transaction lands right before the victim's in the same block | Attacker via priority fee or bundle |

The last row links to MEV. Bernhard Mueller and Daniel Luca's talk "The Ether Wars: Exploits, counter-exploits and honeypots on Ethereum" (DEF CON 27, 2019) showed bots that watch the mempool and front-run transactions by outbidding gas price. The same capability lets an attacker see the victim's pending transaction and land a state-changing transaction first. A preview cannot account for transactions that do not exist yet.

### Signatures are a pure time gap

When a wallet asks the user to sign an EIP-712 message (a Permit, a Permit2 transfer, a marketplace order), nothing executes at signing time. Simulation can only predict what *would* happen if the signature were used now. The attacker can wait for the victim's balances to grow, or submit only when a target token arrives. Hardening here means decoding the message, showing the spender, amount and deadline, and treating unbounded or long-dated permissions as high risk. See **ai-agent-wallet-security** for agents that sign messages automatically.

## Measuring the gap

Defenders should know their own numbers:

- **Preview age at signing.** Time from simulation to signature, per transaction. Log it.
- **Inclusion delay.** Time from submission to inclusion. Public mempool transactions with low priority fees can wait several blocks.
- **Block-time ratio.** On Ethereum mainnet a slot is 12 seconds. A preview older than one slot already describes a past state.

## Defences specific to TOCTOU

- **Re-simulate at signing.** Run the simulation again immediately before the signature is produced, not when the dialog opened. If results differ, block and show both.
- **Expire previews.** Show the block number the preview was computed against and invalidate it after one or two blocks.
- **Bind the result on-chain.** Where the dApp cooperates, wrap calls in a guard that checks minimum received amounts or post-conditions and reverts otherwise. Slippage limits in AMMs are the classic example; the same idea generalises to "assert my balance of X does not drop by more than Y".
- **Flag mutable targets.** Contracts that are proxies, were deployed minutes ago, or whose storage changed between two simulations deserve a warning.
- **Private submission.** Sending through a private relay reduces exposure to ordering attacks, but does not stop a storage flip by the contract owner. Chapter 5 covers this.

## Worked example

> **Execution status:** Not executed in this book's CI; verify locally on Anvil only.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// LAB ONLY: owner can flip behaviour after a wallet previews it.
interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }
contract FlipClaim {
    address immutable owner = msg.sender;
    bool public armed;
    function arm(bool a) external { require(msg.sender == owner); armed = a; }
    function claim(IERC20 token, uint256 amount) external {
        if (armed) token.transferFrom(msg.sender, owner, amount); // drain approved tokens
        // else: no-op, preview shows nothing leaving the user
    }
}
```

1. On Anvil, deploy a test ERC-20 and `FlipClaim`. Mint tokens to a "victim" account and approve `FlipClaim`.
2. Simulate: `cast call <flip> "claim(address,uint256)" <token> 100 --from <victim>` and check balances with a state-diff trace (`cast run` on a prepared tx, or `debug_traceCall` with `prestateTracer` in diff mode). Nothing leaves the victim.
3. As the owner, `cast send <flip> "arm(bool)" true`.
4. As the victim, send the same `claim` call. Check `cast call <token> "balanceOf(address)(uint256)" <victim>`: the balance dropped.
5. Implement a defence in a script: simulate at t0, re-simulate immediately before sending, compare the two state diffs, and abort if they differ. Confirm it catches step 3.

## Common pitfalls

- **Simulating once when the dialog opens.** Users leave dialogs open for minutes.
- **Comparing only success/failure.** Both simulations succeed; only the state diff differs.
- **Assuming private relays fix TOCTOU.** They address ordering, not owner-controlled storage.
- **Treating message signing as low risk.** Permits and orders are delayed transactions with no on-chain check at signing.
- **Ignoring existing approvals.** A harmless-looking call can be the trigger that uses an approval granted weeks ago.

## Exercises

1. Instrument a test wallet flow to log preview age at signing for 20 transactions and report the distribution.
2. Replace the `armed` flag with a proxy upgrade and confirm your re-simulation check still catches it.
3. Write a post-condition guard contract that reverts if the caller's balance of a token falls by more than a user-supplied bound.

## Further reading

- ScamSniffer, "Transaction Simulation Spoofing: A New Threat in Web3" (2025): <https://drops.scamsniffer.io/transaction-simulation-spoofing-a-new-threat-in-web3>
- BleepingComputer coverage (2025): <https://www.bleepingcomputer.com/news/security/new-web3-attack-exploits-transaction-simulations-to-steal-crypto/>
- Guo and Zeng, "Phantom Attack: Evading System Call Monitoring", DEF CON 29 (2021)
- Mueller and Luca, "The Ether Wars: Exploits, counter-exploits and honeypots on Ethereum", DEF CON 27 (2019)
- EIP-6780, SELFDESTRUCT only in same transaction: <https://eips.ethereum.org/EIPS/eip-6780>
