# Glossary

- **Transaction simulation:** executing an unsigned transaction against a copy of chain state to predict its effects.
- **`eth_call`:** JSON-RPC method that executes a call without creating a transaction.
- **`eth_simulateV1`:** JSON-RPC method that simulates calls across one or more blocks with block and state overrides.
- **State override:** a simulation parameter that patches an account's balance, code or storage before execution.
- **Block override:** a simulation parameter that sets block fields such as timestamp, number, fee recipient or base fee.
- **Forked execution:** running a local EVM on top of state fetched from a remote node.
- **Special variables:** EVM context values such as `block.coinbase`, `block.timestamp` and `tx.gasprice` that simulators must guess.
- **Red Pill attack:** ZenGo's 2023 name for contracts that detect simulation via placeholder special variables.
- **Simulation spoofing:** changing contract state after a wallet's preview so the signed transaction does something else.
- **TOCTOU:** time-of-check to time-of-use; a race between verifying a condition and acting on it.
- **Balance delta:** the net change in a user's assets produced by a transaction; the core of a wallet preview.
- **Differential simulation:** running the same transaction under several contexts and comparing outcomes.
- **Honeypot (contract):** a contract that appears exploitable but traps funds sent by would-be exploiters.
- **Can't-sell token:** a token whose buy path works but whose sell path reverts or is taxed for non-whitelisted holders.
- **Private relay:** a submission path that sends transactions directly to block builders rather than the public mempool.
- **Permit:** an EIP-712 signed approval that can be submitted later by anyone holding the signature.
