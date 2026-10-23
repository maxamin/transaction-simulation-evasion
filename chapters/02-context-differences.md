# Context Differences Attackers Key On

A contract cannot see the wallet. It can only see the values the EVM gives it. If any of those values is systematically different during simulation, the contract can branch on it. This chapter catalogues the differences that matter and shows how each one becomes a "red pill".

## The Red Pill disclosure

In March 2023 the wallet vendor ZenGo published research it called the "Red Pill" attack. The core observation: simulators have no correct value for some **special variables** such as the block's miner (`block.coinbase`), so developers often fill them with arbitrary placeholders. ZenGo reported that some simulators set the coinbase to the zero address. A contract that checks `block.coinbase == address(0)` can return a harmless result during simulation and drain the caller during real execution. According to press coverage of the disclosure, several wallet vendors, including Coinbase Wallet, were affected and most fixed their implementations quickly after reports. The fix ZenGo recommended was to fill these variables with realistic values, for example the coinbase of a recent block.

The specific bug is fixed in many wallets, but the class remains. Every placeholder, default or simplification in a simulator is a potential detector.

## Catalogue of distinguishing signals

| Signal | Why it can differ in simulation | Example check an evasive contract might use |
|---|---|---|
| `block.coinbase` | Simulator has no builder; placeholder or zero | `if (block.coinbase == address(0))` behave |
| `block.timestamp` | Simulated at parent timestamp, or parent + fixed delta | Branch on `timestamp % N` or on a deadline set seconds ahead |
| `block.number` | Simulated at `latest` or `latest + 1` | Malicious only when `number > storedTrigger` |
| `block.basefee` / `tx.gasprice` | Simulators often use 0 or a default gas price | `if (tx.gasprice == 0)` behave |
| `gasleft()` | Simulation may run with a huge gas cap (`--rpc.gascap`) | Behave when `gasleft()` exceeds what a real transaction could have |
| `tx.origin` / `msg.sender` | Some scanners call from a zero or fixed address | Behave unless `tx.origin` holds funds or matches a target list |
| `block.prevrandao` | Forks may return a constant | Branch on a constant value |
| `EXTCODESIZE` / `EXTCODEHASH` of caller | Scanners may call from contracts or from accounts with injected code | Behave if caller has code |
| Balances and storage | State overrides or funded fake accounts | Behave if `msg.sender.balance` is suspiciously round |
| Call depth and reentrancy context | Tracing harnesses wrap calls | Behave if called through a known multicall or simulator helper |

Mastering Ethereum (Antonopoulos and Wood, 2018) already warned that `block.timestamp` can be adjusted by block producers and that `tx.origin` should not be used for authorisation. The same properties that make these values unsafe for authorisation make them handy as simulation detectors.

### Gas as a detector

Gas is the subtlest signal. A real transaction carries a gas limit set by the wallet, usually the estimate plus a margin. A simulation run by a security API may set a very high gas cap so that it never fails for out-of-gas reasons. A contract can read `gasleft()` at entry and conclude it is being simulated if the value exceeds the block gas limit, or if it is exactly a common default. Conversely, a contract can make a malicious branch fail in simulation by burning gas only when `gasleft()` is low, so the preview shows "will revert" for the bad path and success for the good one.

`eth_estimateGas` adds a twist: it performs a binary search over gas limits, running the transaction several times. A contract that behaves differently at different gas limits can cause the wallet to set a limit that selects the malicious path.

### Origin and identity

Bulk scanners simulate calls from fixed addresses. If a contract only turns malicious when `tx.origin` holds more than some threshold of assets, or when it is on an attacker-chosen list, a scanner calling from an empty account sees nothing. A wallet simulating from the real user's address, however, does see the user's balance. Attackers therefore often combine identity checks with timing checks: target the real user, but only in the real block.

### External oracles of "realness"

A contract can also ask the outside world. It can read a storage slot that the attacker updates only right before the victim's transaction lands, or check whether a specific other transaction was included earlier in the same block. These rely on the time gap, covered in Chapter 3.

## Why not just copy real values?

Defenders cannot make simulation identical to inclusion because the inclusion context is unknown. Which builder wins the next slot decides the coinbase. Timestamp depends on the slot. Base fee depends on the parent block's gas usage, which is known, but priority fee and ordering are not. The realistic target is: **no constant placeholders, plausible values, and multiple samples**, so that an evasive contract cannot find one condition that is true in every simulation and false in every real block.

## Worked example

> **Execution status:** Not executed in this book's CI; verify locally. Run only on a local Anvil chain.

Build a minimal evasive contract and watch a naive simulator miss it.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// LAB ONLY: demonstrates context-dependent behaviour.
contract RedPillDemo {
    event Outcome(string path);
    function claim() external payable {
        bool looksSimulated = block.coinbase == address(0) || tx.gasprice == 0;
        if (looksSimulated) {
            emit Outcome("benign");
            payable(msg.sender).transfer(msg.value); // refund: looks harmless
        } else {
            emit Outcome("malicious");               // keep the value
        }
    }
}
```

1. `anvil` and deploy with `forge create`.
2. Simulate with zero gas price: `cast call <addr> "claim()" --value 1ether --gas-price 0 --from <user> --trace` (or `cast run` style tracing on a local tx). Observe the `benign` branch.
3. Send a real transaction: `cast send <addr> "claim()" --value 1ether --private-key <key>`. Read the logs with `cast receipt <txhash>` and observe the `malicious` event and the missing refund.
4. Patch your simulator settings: set a non-zero gas price and, with `anvil --block-base-fee-per-gas` and a coinbase override (`--coinbase` on newer Anvil versions, or `eth_simulateV1` block overrides), re-run the call. Confirm the branches now match.

## Common pitfalls

- **Fixing only coinbase.** Red Pill named one variable; gas price, timestamp and gas cap are equally detectable.
- **Constant "realistic" values.** Copying the same recent coinbase forever is still a constant an attacker can learn.
- **Huge gas caps.** Unlimited gas avoids false reverts but is itself a fingerprint.
- **Simulating from a scanner address only.** Identity-gated contracts look clean to bulk scanners.
- **Ignoring `estimateGas` behaviour.** Gas estimation is another execution with its own context.

## Exercises

1. Extend `RedPillDemo` with three more detectors from the table, then write a simulator configuration that defeats each one.
2. Using a mainnet fork, measure how your favourite fork tool sets `block.coinbase`, `prevrandao` and `basefee` for the next block.
3. Write a Foundry test that runs `claim()` under ten randomised contexts and asserts the user's balance delta is identical in all of them.

## Further reading

- ZenGo "Red Pill" disclosure coverage, BleepingComputer (March 2023): <https://www.bleepingcomputer.com/news/security/coinbase-wallet-red-pill-flaw-allowed-attacks-to-evade-detection/>
- TechTarget, "ZenGo finds transaction simulation flaw in Coinbase, others" (2023): <https://www.techtarget.com/searchsecurity/news/365533432/ZenGo-finds-transaction-simulation-flaw-in-Coinbase-others>
- Antonopoulos and Wood, *Mastering Ethereum* (2018), sections on `tx.origin` and block timestamp manipulation
- Solidity documentation, units and global variables: <https://docs.soliditylang.org/en/latest/units-and-global-variables.html>
