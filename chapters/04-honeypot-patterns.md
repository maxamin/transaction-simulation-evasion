# Honeypots and Deceptive Contracts

Simulation evasion has two kinds of victims. The first is the ordinary user, whose wallet preview is fooled. The second is the would-be exploiter: a bot, script or person who simulates a contract, sees what looks like free money, and sends funds to claim it. Contracts built to trap the second group are called **honeypots**. They are worth studying because they are a mature catalogue of tricks for making analysis tools see something false.

## Deception vocabulary

Heckman, Stech, Thomas, Schmoker and Tsow's *Cyber Denial, Deception and Counter-Deception* (2015) offers a useful matrix. Deception reveals fictions ("simulation" in their terms) and conceals facts ("dissimulation"). A honeypot contract does both: it reveals a fiction (an apparent bug that pays out) and conceals a fact (the condition that makes the payout fail or the deposit stick). Evasive phishing contracts mirror this: they reveal a benign preview and conceal the draining branch. Thinking in these terms helps defenders ask two questions of any contract: *what is it trying to show me, and what is it trying to hide?*

## Classic honeypot families

Mastering Ethereum (Antonopoulos and Wood, 2018) describes two early honeypots, **OpenAddressLottery** and **CryptoRoulette**, that exploited Solidity's then-uninitialised storage pointer quirk: a local struct variable silently pointed at storage slot 0, so writing to it overwrote a state variable the reader assumed was safe. The code looked like it paid out to anyone who guessed right; in practice the owner's address or a secret number was overwritten in a way only the owner could exploit.

Mueller and Luca's DEF CON 27 talk "The Ether Wars" (2019) described an arms race: automated exploit tools (such as their Mythril-based "Scrooge McEtherface"), bots scanning for vulnerable contracts, and counter-bots exploiting those scanners. One slide notes that the scanner validates exploits in a sandbox where it can do things like "mine as the coinbase", which is exactly the kind of context difference an adversarial contract can detect.

Academic work later systematised the families. Torres, Steichen and State's "The Art of The Scam: Demystifying Honeypots in Ethereum Smart Contracts" (USENIX Security 2019) built a symbolic-analysis tool, HoneyBadger, and classified honeypot techniques by where the deception lives: the EVM, the Solidity compiler, or the block explorer's presentation.

| Family | Fiction shown | Concealed fact |
|---|---|---|
| Uninitialised storage pointer | Anyone who matches the secret wins | The write clobbers a different slot |
| Balance disorder | Send more than the balance and get it all back | `this.balance` already includes `msg.value` when the check runs |
| Inheritance / shadowing | Owner variable you can overwrite | A different, shadowed variable is checked |
| Hidden state update | Public "secret" visible in a past transaction | Owner changed it later in an internal call not shown by explorers |
| Explorer display tricks | Long whitespace hides code off-screen | Malicious statement is visible only when scrolling |
| Type deduction overflow | Loop pays out | Old `var` deduction gave a `uint8` that overflowed |
| Token "can't sell" | Token buys work on a DEX | Transfers to the pair revert for everyone but whitelisted addresses |

Several of these rely on old compiler versions and are of historical interest. The **can't-sell token** is not historical: it remains common on DEXs. The buy path succeeds in any simulation; the sell path reverts, charges a 100% tax, or works only for addresses the deployer allows.

## Honeypots that detect simulation

The newest honeypots combine the families above with the context checks of Chapter 2:

- **Simulator-aware sell checks.** Sells succeed when `tx.gasprice == 0` or `block.coinbase` is a placeholder, so token-scanning sites that simulate a buy-then-sell report "not a honeypot".
- **Time-gated traps.** Sells work for the first N blocks after launch (when scanners look) and are disabled afterwards.
- **Identity-gated traps.** Sell succeeds when called from known scanner addresses or from contracts, and fails for EOAs holding real balances.

Token scanners that simulate a round trip are therefore subject to the same evasion as wallet previews, and need the same hardening: realistic and varied context, simulation from fresh EOAs with plausible balances, and re-checks over time.

## Analysing a suspected honeypot

A disciplined workflow, all on a local fork:

1. **Source and bytecode.** Verify the source matches deployed bytecode. Unverified bytecode is itself a signal.
2. **Read the hidden paths.** Search for reads of `block.*`, `tx.*`, `gasleft()`, `extcodesize` and for owner-only setters of fees, whitelists or `paused` flags.
3. **Symbolic exploration.** Tools such as Mythril or HoneyBadger-style analysis explore paths that depend on context. Point them at the bytecode and look for branches conditioned on environment values.
4. **Differential execution.** Run the same call under several contexts (Chapter 5) and diff the outcomes.
5. **History.** Review past transactions, including internal calls, for owner actions that changed state after deployment.

See **onchain-malware-analysis** for deeper bytecode triage of drainers and honeypots.

## Worked example

> **Execution status:** Not executed in this book's CI; verify locally on Anvil only.

Build a "can't-sell unless simulated" token and catch it.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// LAB ONLY: honeypot token for detection practice.
contract TrapToken {
    mapping(address => uint256) public balanceOf;
    address public immutable pair;
    constructor(address _pair) { pair = _pair; balanceOf[_pair] = 1e24; }
    function transfer(address to, uint256 v) external returns (bool) {
        bool looksSimulated = tx.gasprice == 0 || block.coinbase == address(0);
        if (to == pair && !looksSimulated) revert("sell blocked");
        balanceOf[msg.sender] -= v; balanceOf[to] += v; return true;
    }
}
```

1. Deploy on Anvil with any address as `pair`. Have the pair transfer tokens to a test account to simulate a buy.
2. Naive scanner: `cast call <token> "transfer(address,uint256)(bool)" <pair> 1 --from <buyer> --gas-price 0`. It returns `true`.
3. Real sell: `cast send <token> "transfer(address,uint256)" <pair> 1 --private-key <buyer key>`. It reverts with `sell blocked`.
4. Hardened scanner: repeat step 2 with a realistic gas price and a non-zero coinbase override (via `eth_simulateV1` block overrides or a fork configured with a coinbase). Confirm it now reports the revert.
5. Run `myth analyze` (Mythril) on the bytecode and note whether it reports the environment-dependent branch.

## Common pitfalls

- **Trusting "honeypot check" sites blindly.** They simulate, and can be evaded like any simulator.
- **Analysing only the buy path.** Most token traps live in the sell or transfer-to-pair path.
- **Reading code on an explorer without scrolling.** Whitespace and long lines have hidden logic.
- **Ignoring owner-only setters.** A token can be fair today and trap tomorrow.
- **Copying honeypot techniques into production.** Lab contracts stay on local chains.

## Exercises

1. Add a time-gated variant to `TrapToken` (sells allowed only in the first 20 blocks) and design a scanner strategy that catches it.
2. Reproduce the "balance disorder" pattern in a modern Solidity version and explain why `address(this).balance` includes `msg.value`.
3. Pick three honeypot families from the table and, for each, write the one-line static-analysis rule you would use to flag it.

## Further reading

- Torres, Steichen and State, "The Art of The Scam: Demystifying Honeypots in Ethereum Smart Contracts", USENIX Security 2019: <https://www.usenix.org/conference/usenixsecurity19/presentation/torres>
- Antonopoulos and Wood, *Mastering Ethereum* (2018), "Real-World Examples: OpenAddressLottery and CryptoRoulette Honey Pots"
- Mueller and Luca, "The Ether Wars", DEF CON 27 (2019)
- Heckman et al., *Cyber Denial, Deception and Counter-Deception* (Springer, 2015)
- Mythril: <https://github.com/Consensys/mythril>
