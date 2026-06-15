# Slot Miner

A real Bitcoin miner disguised as a slot machine. One pull, one hash, one shot at the next block.

## What It Does

Each pull of the lever:

1. Fetches the current Bitcoin block from the live network (mempool.space API)
2. Constructs a valid 80-byte block header with a random nonce
3. Performs one double SHA-256 hash -- the exact operation mining ASICs do
4. Checks the result against the real Bitcoin network difficulty target
5. If the hash beats the target, saves the block and submits it to multiple nodes

This is not a simulation. Every hash is a legitimate mining attempt on the real Bitcoin network. If you win, the 3.125 BTC block reward goes directly to your wallet.

## Usage

```
python3 bitcoin_slot_machine.py                              # interactive (intro + address prompt)
python3 bitcoin_slot_machine.py bc1qyouraddresshere...       # jump straight to the machine
```

You must provide a Bitcoin address. The block reward is paid to that address via a proper SegWit coinbase transaction (with BIP34 height encoding and BIP141 witness commitment).

Supports: P2WPKH (`bc1q...`), P2TR (`bc1p...`), P2PKH (`1...`), P2SH (`3...`).

Press Enter to pull. Press Q to walk away.

Requires Python 3.10+ and an internet connection. No external dependencies -- standard library only.

## How the Difficulty Works

Every SHA-256 hash produces 64 hex characters (256 bits). The network sets a target number. Your hash, interpreted as a number, must be less than the target to win.

In practice, this means your hash needs to start with a certain number of leading zeros. Currently the network requires ~19 leading hex zeros. Each zero is a 1-in-16 chance, so 19 in a row = odds of about 1 in 16^19 = 1 in 2^76 per pull.

Real mining ASICs do ~600 trillion of these hashes per second. You get one per pull.

## The Machine

```
  ╔══════════════════════════════════════════════════════════════════════════╗
  ║   SLOT MINER                                                            ║
  ╠══════════════════════════════════════════════════════════════════════════╣
  ║  BLOCK #953,838                     REWARD  3.125 BTC                   ║
  ║  PAYS TO  bc1q...                                                       ║
  ║  ZEROS NEEDED  19                   PULLS  3                            ║
  ╠──────────────────────────────────────────────────────────────────────────╣
  ║                                                                         ║  ╥
  ║   [3] [9] [1] [a] [d] [6] [a] [3] [2] [5] [d] [4] [7] [a] [d] [f]    ║  ║
  ║   [2] [b] [1] [d] [3] [7] [f] [0] [0] [6] [f] [f] [9] [d] [7] [c]    ║  ║
  ║   [c] [e] [a] [c] [e] [c] [5] [d] [3] [3] [9] [d] [e] [9] [d] [6]    ║  ║
  ║   [9] [6] [9] [4] [a] [7] [7] [e] [2] [b] [0] [b] [8] [8] [e] [8]    ║  ║
  ║                                                                         ║  ║
  ║   Nothing. The blockchain shrugs.                                       ║ (●)
  ╠──────────────────────────────────────────────────────────────────────────╣
  ║  HASH  391ad6a3...                                                      ║
  ║  NONCE 4,270,282,621                BEST  0 zeros                       ║
  ╚══════════════════════════════════════════════════════════════════════════╝
```

All 64 hex characters spin like slot reels then lock into place left to right. The lever sits on the right side of the machine.

## If You Win

The code:
1. Saves the raw block hex to `winning_block.hex` immediately
2. Attempts submission to multiple public Bitcoin RPC nodes
3. Prints instructions for manual submission via your own node:
   ```
   bitcoin-cli submitblock $(cat winning_block.hex)
   ```

The coinbase transaction is fully valid (SegWit witness commitment, BIP34 height, correct 3.125 BTC reward to your address). If the block is accepted by the network, the reward matures after 100 confirmations.

## Is This Real?

Yes. The hashing, block header, difficulty check, coinbase transaction, and submission are all real. The odds are astronomically against you (~1 in 2^76 per pull), but the code is fully functional end to end.

It only takes one lucky hash.
