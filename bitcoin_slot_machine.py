#!/usr/bin/env python3
"""
Slot Miner
==========
One pull. One hash. One shot at the next Bitcoin block.

Connects to the live Bitcoin network, constructs a real block header,
picks a random nonce, and performs one SHA256(SHA256(header)) -- the
exact operation mining ASICs do trillions of times per second.

If the resulting hash beats the network difficulty target, it submits
the block and the 3.125 BTC reward goes to your wallet.
"""

import hashlib
import struct
import time
import random
import urllib.request
import json
import ssl
import sys
import os


def _ssl_context():
    """Create SSL context. Falls back to unverified if system certs unavailable."""
    ctx = ssl.create_default_context()
    return ctx


def _ssl_context_unverified():
    """Unverified SSL context for systems without proper cert bundles (e.g. macOS)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_url(url: str) -> bytes:
    """Fetch raw bytes from a URL."""
    req = urllib.request.Request(url, headers={"User-Agent": "BitcoinSlotMachine/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_context()) as resp:
            return resp.read()
    except (ssl.SSLCertVerificationError, ssl.SSLError, urllib.error.URLError):
        # Fallback: disable verification (common on macOS without certs installed)
        with urllib.request.urlopen(req, timeout=15, context=_ssl_context_unverified()) as resp:
            return resp.read()


def fetch_json(url: str) -> dict:
    """Fetch JSON from a URL."""
    return json.loads(fetch_url(url))


## -- Address decoding ----------------------------------------------------------

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    """Internal bech32 checksum function."""
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_verify_checksum(hrp: str, data: list[int]) -> bool:
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    return const == 1 or const == 0x2bc830a3  # bech32 or bech32m


def decode_bech32(addr: str) -> tuple[int, bytes] | None:
    """Decode a bech32/bech32m address. Returns (witness_version, program) or None."""
    addr_lower = addr.lower()
    pos = addr_lower.rfind('1')
    if pos < 1 or pos + 7 > len(addr_lower):
        return None
    hrp = addr_lower[:pos]
    if hrp not in ('bc', 'tb'):  # mainnet or testnet
        return None
    data = []
    for c in addr_lower[pos + 1:]:
        idx = BECH32_CHARSET.find(c)
        if idx == -1:
            return None
        data.append(idx)
    if not _bech32_verify_checksum(hrp, data):
        return None
    # Convert 5-bit groups to 8-bit (exclude checksum)
    witness_version = data[0]
    payload = data[1:-6]
    # Convert from 5-bit to 8-bit
    acc = 0
    bits = 0
    result = []
    for v in payload:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            result.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc << (8 - bits)) & 0xFF:
        return None
    program = bytes(result)
    if len(program) < 2 or len(program) > 40:
        return None
    return witness_version, program


# Base58 alphabet
B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def decode_base58check(addr: str) -> bytes | None:
    """Decode a base58check address. Returns version_byte + payload or None."""
    num = 0
    for c in addr:
        idx = B58_ALPHABET.find(c)
        if idx == -1:
            return None
        num = num * 58 + idx
    # Convert to bytes (25 bytes for standard addresses)
    combined = num.to_bytes(25, 'big')
    payload, checksum = combined[:-4], combined[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


def address_to_script_pubkey(addr: str) -> bytes | None:
    """
    Convert a Bitcoin address to its scriptPubKey.
    Supports:
      - P2PKH  (1...)   -> OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
      - P2SH   (3...)   -> OP_HASH160 <20> <hash> OP_EQUAL
      - P2WPKH (bc1q...) -> OP_0 <20> <hash>
      - P2WSH  (bc1q...) -> OP_0 <32> <hash>
      - P2TR   (bc1p...) -> OP_1 <32> <key>
    """
    # Try bech32 first
    bech32_result = decode_bech32(addr)
    if bech32_result is not None:
        version, program = bech32_result
        if version == 0 and len(program) == 20:
            # P2WPKH
            return bytes([0x00, 0x14]) + program
        elif version == 0 and len(program) == 32:
            # P2WSH
            return bytes([0x00, 0x20]) + program
        elif version == 1 and len(program) == 32:
            # P2TR (taproot)
            return bytes([0x51, 0x20]) + program
        else:
            return None

    # Try base58check
    decoded = decode_base58check(addr)
    if decoded is None:
        return None
    version_byte = decoded[0]
    payload_hash = decoded[1:]
    if version_byte == 0x00 and len(payload_hash) == 20:
        # P2PKH
        return bytes([0x76, 0xa9, 0x14]) + payload_hash + bytes([0x88, 0xac])
    elif version_byte == 0x05 and len(payload_hash) == 20:
        # P2SH
        return bytes([0xa9, 0x14]) + payload_hash + bytes([0x87])
    return None


def validate_bitcoin_address(addr: str) -> bool:
    """Check if an address can be decoded into a valid scriptPubKey."""
    return address_to_script_pubkey(addr) is not None


## -- Mining logic -------------------------------------------------------------

def bits_to_target(bits: int) -> int:
    """Convert compact 'bits' encoding to the full 256-bit target integer."""
    exponent = bits >> 24
    coefficient = bits & 0x7FFFFF
    if bits & 0x800000:
        coefficient = -coefficient
    return coefficient << (8 * (exponent - 3))


def double_sha256(data: bytes) -> bytes:
    """Double SHA-256 hash (Bitcoin's hash function)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def build_block_header(version: int, prev_block: bytes, merkle_root: bytes,
                       timestamp: int, bits: int, nonce: int) -> bytes:
    """Build the 80-byte block header."""
    header = struct.pack('<i', version)
    header += prev_block[::-1]       # Internal byte order (little-endian)
    header += merkle_root[::-1]      # Internal byte order (little-endian)
    header += struct.pack('<I', timestamp)
    header += struct.pack('<I', bits)
    header += struct.pack('<I', nonce)
    return header


def hash_to_display(hash_bytes: bytes) -> str:
    """Convert hash bytes to the display format (reversed, like block explorers show)."""
    return hash_bytes[::-1].hex()


def get_block_template(script_pubkey: bytes):
    """
    Fetch the current block data needed to construct a valid header.
    Uses mempool.space API to get the latest block tip and pending block info.
    """
    # Get the current tip hash (this endpoint returns raw hex text, not JSON)
    tip_hash = fetch_url("https://mempool.space/api/blocks/tip/hash").decode().strip()

    # Get the block header info for the current tip
    tip_info = fetch_json(f"https://mempool.space/api/block/{tip_hash}")

    # Get difficulty bits from the current block
    bits = tip_info.get('bits')
    if isinstance(bits, str):
        bits = int(bits, 16)

    height = tip_info['height'] + 1

    # Build coinbase transaction paying to the user's address
    coinbase_tx = build_coinbase_tx(height, script_pubkey)
    # Merkle root uses txid (hash of tx without witness data)
    merkle = coinbase_txid(coinbase_tx)  # Single tx = merkle root is just its txid

    return {
        'version': 0x20000000,  # Standard version bits signaling
        'prev_block': bytes.fromhex(tip_hash),
        'merkle_root': merkle,
        'timestamp': int(time.time()),
        'bits': bits,
        'height': height,
        'target': bits_to_target(bits),
        'coinbase_tx': coinbase_tx,
        'tip_hash': tip_hash,
    }


def build_coinbase_tx(height: int, script_pubkey: bytes) -> bytes:
    """
    Build a valid coinbase transaction with SegWit witness commitment.
    The coinbase tx is the first transaction in every block -- it creates
    new bitcoin as the block reward, paid to the given scriptPubKey.

    Includes the mandatory witness commitment output (BIP141) so the block
    is valid on the modern SegWit network.
    """
    # For a block with only the coinbase tx (no other witness data),
    # the witness commitment is: SHA256(SHA256(witness_root || witness_reserved))
    # where witness_root = all zeros (only coinbase, which has no witness)
    # and witness_reserved = all zeros (32 bytes, placed in coinbase witness)
    witness_reserved = b'\x00' * 32
    witness_root = b'\x00' * 32  # Empty block: only coinbase, no witness txs
    witness_commitment = hashlib.sha256(
        hashlib.sha256(witness_root + witness_reserved).digest()
    ).digest()

    # SegWit commitment script: OP_RETURN <commitment_header><commitment_hash>
    # The header is the magic bytes: 0xaa21a9ed
    commitment_script = b'\x6a\x24\xaa\x21\xa9\xed' + witness_commitment

    # -- Build the transaction (with witness serialization, BIP144) --
    tx = b''

    # Version
    tx += struct.pack('<I', 2)

    # Marker + Flag (BIP144 witness serialization)
    tx += b'\x00\x01'

    # --- Inputs ---
    tx += b'\x01'  # Input count: 1

    # Previous output (null for coinbase)
    tx += b'\x00' * 32                    # Prev tx hash (all zeros)
    tx += struct.pack('<I', 0xFFFFFFFF)   # Prev output index

    # Coinbase script (scriptsig): must include block height (BIP34)
    height_bytes = height.to_bytes((height.bit_length() + 7) // 8, 'little')
    coinbase_script = bytes([len(height_bytes)]) + height_bytes
    coinbase_script += b'/SlotMiner/'     # Miner tag

    tx += struct.pack('<B', len(coinbase_script))  # Script length
    tx += coinbase_script                          # Script
    tx += struct.pack('<I', 0xFFFFFFFF)            # Sequence

    # --- Outputs ---
    tx += b'\x02'  # Output count: 2

    # Output 0: Block reward to user's address
    # 3.125 BTC = 312500000 satoshis
    reward = 312500000
    tx += struct.pack('<Q', reward)
    tx += struct.pack('<B', len(script_pubkey))
    tx += script_pubkey

    # Output 1: Witness commitment (OP_RETURN, 0 value)
    tx += struct.pack('<Q', 0)  # 0 satoshis
    tx += struct.pack('<B', len(commitment_script))
    tx += commitment_script

    # --- Witness ---
    # Coinbase witness: exactly one stack item, the 32-byte witness reserved value
    tx += b'\x01'                        # Number of witness stack items
    tx += b'\x20'                        # Length of item (32 bytes)
    tx += witness_reserved               # The reserved value (all zeros)

    # Locktime
    tx += struct.pack('<I', 0)

    return tx


def coinbase_txid(coinbase_tx: bytes) -> bytes:
    """
    Compute the txid of a coinbase transaction.
    The txid is the double-SHA256 of the transaction WITHOUT witness data.
    We need to strip the marker, flag, and witness fields.
    """
    # Parse: version(4) + marker(1) + flag(1) + inputs... + outputs... + witness... + locktime(4)
    version = coinbase_tx[:4]

    # Skip marker+flag
    offset = 6

    # Read input count
    input_count = coinbase_tx[offset]; offset += 1
    inputs_start = offset
    for _ in range(input_count):
        offset += 32 + 4  # prev_hash + prev_idx
        script_len = coinbase_tx[offset]; offset += 1
        offset += script_len + 4  # script + sequence
    inputs_data = coinbase_tx[inputs_start - 1:offset]  # includes count byte

    # Read output count
    output_count = coinbase_tx[offset]; offset += 1
    outputs_start = offset
    for _ in range(output_count):
        offset += 8  # value
        script_len = coinbase_tx[offset]; offset += 1
        offset += script_len
    outputs_data = coinbase_tx[outputs_start - 1:offset]  # includes count byte

    # Skip witness data, get locktime (last 4 bytes)
    locktime = coinbase_tx[-4:]

    # Serialize without witness: version + inputs + outputs + locktime
    raw = version + inputs_data + outputs_data + locktime
    return double_sha256(raw)


def count_leading_zeros(hex_str: str) -> int:
    """Count leading zero characters in a hex string."""
    count = 0
    for ch in hex_str:
        if ch == '0':
            count += 1
        else:
            break
    return count


## -- Display / UI -------------------------------------------------------------

HEX = "0123456789abcdef"


def clear_screen():
    """Clear terminal and move cursor to top."""
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def print_intro(required_zeros: int = 19):
    """Print the title screen with explanation."""
    clear_screen()
    z = str(required_zeros)
    b = str(required_zeros * 4)
    print(f"""
   ╔═══════════════════════════════════════════════════════════════════════╗
   ║                                                                       ║
   ║   ███████╗██╗      ██████╗ ████████╗                                  ║
   ║   ██╔════╝██║     ██╔═══██╗╚══██╔══╝                                  ║
   ║   ███████╗██║     ██║   ██║   ██║                                     ║
   ║   ╚════██║██║     ██║   ██║   ██║                                     ║
   ║   ███████║███████╗╚██████╔╝   ██║                                     ║
   ║   ╚══════╝╚══════╝ ╚═════╝    ╚═╝                                     ║
   ║        ███╗   ███╗██╗███╗   ██╗███████╗██████╗                        ║
   ║        ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗                       ║
   ║        ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝                       ║
   ║        ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗                       ║
   ║        ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║                       ║
   ║        ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝                       ║
   ║                                                                       ║
   ╠═══════════════════════════════════════════════════════════════════════╣
   ║  ONE PULL. ONE HASH. ONE SHOT AT THE NEXT BITCOIN BLOCK.              ║
   ╠═══════════════════════════════════════════════════════════════════════╣
   ║                                                                       ║
   ║  HOW IT WORKS:                                                        ║
   ║  1. Connects to the live Bitcoin network                              ║
   ║  2. Builds a real 80-byte block header for the NEXT block             ║
   ║  3. Picks a random nonce (your lottery number)                        ║
   ║  4. Computes SHA256(SHA256(header)) -- one real mining hash           ║
   ║  5. Checks: does the hash beat the difficulty target?                 ║
   ║                                                                       ║
   ║  THE TARGET: Your hash must start with ~{z} hex zeros.                 ║
   ║  Each zero is 1-in-16, so {z} zeros = 1 in 16^{z} = ~1 in 2^{b}.         ║
   ║  Real ASICs do 600 trillion hashes/sec. You get one per pull.         ║
   ║                                                                       ║
   ║  If you win: 3.125 BTC goes directly to YOUR address.                 ║
   ║                                                                       ║
   ╠═══════════════════════════════════════════════════════════════════════╣
   ║  Press ENTER to sit down at the machine...                            ║
   ╚═══════════════════════════════════════════════════════════════════════╝
""")


def print_address_prompt():
    """Print the address entry screen."""
    clear_screen()
    print("""
   ╔═══════════════════════════════════════════════════════════════════════╗
   ║                                                                       ║
   ║   ENTER YOUR BITCOIN ADDRESS                                          ║
   ║   ──────────────────────────                                          ║
   ║   If you hit the jackpot, the 3.125 BTC block reward is paid          ║
   ║   directly to this address in the coinbase transaction.               ║
   ║                                                                       ║
   ║   Accepted formats:                                                   ║
   ║     bc1q...   Native SegWit (recommended)                             ║
   ║     bc1p...   Taproot                                                 ║
   ║     1...      Legacy P2PKH                                            ║
   ║     3...      Legacy P2SH                                             ║
   ║                                                                       ║
   ╚═══════════════════════════════════════════════════════════════════════╝
""")


def draw_machine(block_info: dict, reels: str = None, result_text: str = None,
                 nonce: int = None, pulls: int = 0, best_zeros: int = 0,
                 lever_down: bool = False):
    """
    Draw the complete slot machine. Called for EVERY frame.
    This is the single source of truth for what the machine looks like.
    Always clears and redraws -- simple, reliable, no ANSI cursor tricks.
    """
    height = block_info['height']
    target = block_info['target']
    address = block_info.get('address', '???')
    target_hex = f"{target:064x}"
    required_zeros = count_leading_zeros(target_hex)
    addr_display = address if len(address) <= 44 else address[:20] + ".." + address[-20:]

    # Lever
    if lever_down:
        lever = ["  ╥", "  ║", "  ║", "  ║", "  ║", "  ║", " (●)"]
    else:
        lever = ["  ╥", "  ║", "  ║", " (●)", "  ║", "  ║", "  ║"]

    # Build the machine
    W = 66  # inner content width (fits 64-char hash line "HASH  " + 64 = 70 with padding)
    # Actually let's be precise: the widest content is "HASH  " + 64 hex = 70 chars
    # So inner width needs to be 72 to hold that with 1 char padding each side
    W = 72

    def r(text=""):
        return f"  ║ {text:<{W}} ║"

    def sep(ch="═"):
        return f"  ╠{ch * (W + 2)}╣"

    clear_screen()

    out = []
    out.append(f"  ╔{'═' * (W + 2)}╗")
    out.append(r("           ____  _     ___  _____   __  __ ___ _  _ ___ ___           ".center(W)))
    out.append(r(".+.*.+.*.+ / ___|| | * / _ \\|_   _| |  \\/  |_ _| \\| | __| _ \\ .*.+.*.+.*".center(W)))
    out.append(r("+.*.+.*.+. \\___ \\| |__| (_) | | |   | |\\/| || || .` | _||   / *.+.*.+.*.".center(W)))
    out.append(r(".+.*.+.*.+ |___/ |____|\\___/  |_| * |_|  |_|___|_|\\_|___|_|_\\ .*.+.*.+.*".center(W)))
    out.append(sep())
    out.append(r(f" BLOCK #{height:,}".ljust(36) + f"REWARD  3.125 BTC"))
    out.append(r(f" PAYS TO  {addr_display}"))
    out.append(r(f" ZEROS NEEDED  {required_zeros}".ljust(36) + f"PULLS  {pulls}"))
    out.append(sep("─"))

    # Reel area (7 lines to match lever length)
    reel_lines = []
    if reels is None:
        # Idle state: show "PULL THE LEVER" prompt
        reel_lines.append(r())
        reel_lines.append(r("  ┌──────────────────────────────────────────────────────────────┐"))
        reel_lines.append(r("  │         P U L L   T H E   L E V E R   [ENTER]                │"))
        reel_lines.append(r("  └──────────────────────────────────────────────────────────────┘"))
        reel_lines.append(r())
        reel_lines.append(r(f"   One hash. {required_zeros} zeros to win. You feeling lucky?"))
        reel_lines.append(r())
    else:
        # Reels visible (spinning or final)
        reel_lines.append(r())
        for row_idx in range(4):
            chunk = reels[row_idx * 16:(row_idx + 1) * 16]
            reel_str = " ".join(f"[{c}]" for c in chunk)
            reel_lines.append(r(f"   {reel_str}"))
        reel_lines.append(r())
        if result_text:
            reel_lines.append(r(f"   {result_text}"))
        else:
            reel_lines.append(r())

    # Attach lever to reel lines
    for i, lev in enumerate(lever):
        if i < len(reel_lines):
            reel_lines[i] = reel_lines[i] + lev
    out.extend(reel_lines)

    out.append(sep("─"))
    if reels and result_text:
        out.append(r(f" HASH  {reels}"))
        out.append(r(f" NONCE {nonce:,}".ljust(36) + f"BEST  {best_zeros} zeros"))
    else:
        out.append(r(f" HASH  {'·' * 64}"))
        out.append(r(f" NONCE ···".ljust(36) + f"BEST  {best_zeros} zeros"))
    out.append(sep())
    out.append(r(" [ENTER] Pull                                   [Q] Walk away"))
    out.append(f"  ╚{'═' * (W + 2)}╝")

    print("\n".join(out))
    sys.stdout.flush()


def run_pull(final_hash: str, block_info: dict, nonce: int, won: bool,
             pulls: int, best_zeros: int):
    """
    Animate one complete pull. Redraws the full machine each frame.
    Simple approach: clear + redraw for every animation frame.
    The machine always looks like a machine.
    """
    required_zeros = count_leading_zeros(f"{block_info['target']:064x}")
    zeros = count_leading_zeros(final_hash)

    # Build result text with varied flavor
    if won:
        result_text = "$$$ $$$ $$$  J A C K P O T  $$$ $$$ $$$"
    elif zeros == 0:
        msgs = [
            "No zeros. The house wins this round.",
            "Nothing. The blockchain shrugs.",
            "Zero zeros. Insert another hash.",
            "Nope. The network doesn't flinch.",
        ]
        result_text = msgs[pulls % len(msgs)]
    elif zeros == 1:
        result_text = f"{zeros} zero! A tease. Need {required_zeros}."
    elif zeros == 2:
        result_text = f"{zeros} zeros. Getting warmer... need {required_zeros}."
    elif zeros < 5:
        result_text = f"{zeros} zeros! The machine flickers. Need {required_zeros}."
    else:
        result_text = f"{zeros} ZEROS! Incredible luck! Still need {required_zeros}."

    is_tty = sys.stdout.isatty()

    if not is_tty:
        # No animation, just show result
        draw_machine(block_info, final_hash, result_text, nonce, pulls, best_zeros, lever_down=True)
        return

    # -- Animation: rapid clear+redraw per frame --
    current = [random.choice(HEX) for _ in range(64)]

    # Phase 1: All reels spinning fast
    for frame in range(12):
        current = [random.choice(HEX) for _ in range(64)]
        draw_machine(block_info, "".join(current), "* spinning *" if frame % 2 == 0 else "· spinning ·",
                     nonce, pulls, best_zeros, lever_down=True)
        time.sleep(0.045)

    # Phase 2: Lock columns left to right (the satisfying click-click-click)
    for col in range(16):
        # Spin only unlocked positions
        for pos in range(64):
            if pos % 16 > col:
                current[pos] = random.choice(HEX)
        # Lock this column across all rows
        for row in range(4):
            current[row * 16 + col] = final_hash[row * 16 + col]
        locked_count = col + 1
        draw_machine(block_info, "".join(current),
                     f"[{'|' * locked_count}{'.' * (16 - locked_count)}] locking...",
                     nonce, pulls, best_zeros, lever_down=True)
        time.sleep(0.04)

    # Phase 3: Brief pause then show final result
    time.sleep(0.25)
    draw_machine(block_info, final_hash, result_text, nonce, pulls, best_zeros, lever_down=True)

    time.sleep(0.3)

    draw_machine(block_info, final_hash, result_text, nonce, pulls, best_zeros, lever_down=False)


def print_jackpot_screen(block_info: dict, nonce: int, display_hash: str):
    """Full-screen jackpot celebration."""
    clear_screen()
    target_hex = f"{block_info['target']:064x}"
    addr = block_info.get('address', '???')
    print(f"""
   ╔═══════════════════════════════════════════════════════════════════════╗
   ║                                                                       ║
   ║        ██╗ █████╗  ██████╗██╗  ██╗██████╗  ██████╗ ████████╗          ║
   ║        ██║██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝          ║
   ║        ██║███████║██║     █████╔╝ ██████╔╝██║   ██║   ██║             ║
   ║   ██   ██║██╔══██║██║     ██╔═██╗ ██╔═══╝ ██║   ██║   ██║             ║
   ║   ╚█████╔╝██║  ██║╚██████╗██║  ██╗██║     ╚██████╔╝   ██║             ║
   ║    ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝    ╚═╝             ║
   ║                                                                       ║
   ╠═══════════════════════════════════════════════════════════════════════╣
   ║                                                                       ║
   ║   BLOCK    #{block_info['height']:,}{'':50}║
   ║   NONCE    {nonce:<58} ║
   ║   HASH     {display_hash}  ║
   ║   TARGET   {target_hex}  ║
   ║   ADDRESS  {addr:<58} ║
   ║                                                                       ║
   ║   REWARD   3.125 BTC                                                  ║
   ║                                                                       ║
   ╠═══════════════════════════════════════════════════════════════════════╣
   ║   Submitting block to the Bitcoin network...                          ║
   ╚═══════════════════════════════════════════════════════════════════════╝
""")


def submit_block(block_info: dict, nonce: int):
    """
    Attempt to submit a winning block to the Bitcoin network.
    Constructs the full serialized block and broadcasts via public RPC nodes.
    Also saves the block hex to a file so the user can submit manually.
    """
    import base64

    # Build the full block
    header = build_block_header(
        block_info['version'],
        block_info['prev_block'],
        block_info['merkle_root'],
        block_info['timestamp'],
        block_info['bits'],
        nonce
    )

    # Block = header + varint(tx_count) + transactions (witness-serialized)
    coinbase_tx = block_info['coinbase_tx']
    block_data = header + b'\x01' + coinbase_tx  # 1 transaction (coinbase only)
    block_hex = block_data.hex()

    print(f"   Block size: {len(block_data)} bytes")
    print(f"   Block hash: {hash_to_display(double_sha256(header))}")
    print()

    # Save block to file immediately (in case submission fails)
    block_file = "winning_block.hex"
    try:
        with open(block_file, 'w') as f:
            f.write(block_hex)
        print(f"   Block saved to: {block_file}")
        print(f"   (You can submit this manually with: bitcoin-cli submitblock $(cat {block_file}))")
        print()
    except Exception:
        pass

    # Try submitting via multiple public Bitcoin RPC nodes
    print("   Attempting submission to multiple nodes...")
    print()
    nodes = [
        ("https://bitcoin-rpc.publicnode.com", "bitcoin", "bitcoin"),
        ("https://node.eldorado.market/", "", ""),
        ("https://bitcoin.drpc.org/", "", ""),
        ("http://localhost:8332", "__cookie__", ""),  # Local Bitcoin Core
    ]

    submitted = False
    for node_url, user, pw in nodes:
        try:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "submitblock",
                "params": [block_hex]
            }).encode()

            headers = {"Content-Type": "application/json"}
            if user:
                auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
                headers["Authorization"] = f"Basic {auth}"

            req = urllib.request.Request(node_url, data=payload, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=10, context=_ssl_context()) as resp:
                    result = json.loads(resp.read())
            except (ssl.SSLCertVerificationError, ssl.SSLError, urllib.error.URLError):
                with urllib.request.urlopen(req, timeout=10, context=_ssl_context_unverified()) as resp:
                    result = json.loads(resp.read())

            # submitblock returns null/None on success
            if result.get("result") is None and result.get("error") is None:
                print(f"   -> ACCEPTED by {node_url}")
                submitted = True
            elif result.get("error"):
                err = result['error']
                msg = err.get('message', err) if isinstance(err, dict) else err
                print(f"   -> {node_url}: {msg}")
            else:
                print(f"   -> {node_url}: {result.get('result', '?')}")
        except Exception as e:
            err_msg = str(e)
            if len(err_msg) > 60:
                err_msg = err_msg[:60] + "..."
            print(f"   -> {node_url}: {err_msg}")

    print()
    if submitted:
        print("   BLOCK ACCEPTED! Your reward will mature after 100 confirmations.")
    else:
        print("   No node confirmed acceptance (this is common with public nodes).")
        print()
        print("   TO CLAIM YOUR REWARD:")
        print(f"   1. Block saved to: {block_file}")
        print("   2. Submit via your own Bitcoin Core node:")
        print(f"        bitcoin-cli submitblock $(cat {block_file})")
        print("   3. Or paste the hex into any node's submitblock RPC")
        print("   4. ACT IMMEDIATELY -- the block race is measured in seconds!")

    return submitted


def main():
    # -- Accept address as CLI arg or prompt interactively --
    addr = None
    if len(sys.argv) > 1:
        addr = sys.argv[1].strip()
        script_pubkey = address_to_script_pubkey(addr)
        if script_pubkey is None:
            print(f"\n   Invalid Bitcoin address: {addr}")
            sys.exit(1)
    else:
        # Show intro screen (with a preliminary zeros estimate)
        print_intro(19)
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        print_address_prompt()

        while True:
            try:
                addr = input("   Address: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n")
                sys.exit(0)

            if not addr:
                continue

            script_pubkey = address_to_script_pubkey(addr)
            if script_pubkey is None:
                print("   Invalid address. Check it and try again.\n")
                continue
            break

    # -- Fetch block data --
    clear_screen()
    print()
    print("   Connecting to Bitcoin network...")
    print("   Fetching latest block from mempool.space...")

    try:
        block_info = get_block_template(script_pubkey)
    except Exception as e:
        print(f"\n   ERROR: Could not reach the network: {e}")
        print("   Check your internet connection and try again.")
        sys.exit(1)

    block_info['address'] = addr
    target = block_info['target']
    target_hex = f"{target:064x}"
    required_zeros = count_leading_zeros(target_hex)

    print(f"   Block #{block_info['height']:,} loaded.")
    print(f"   Difficulty: {required_zeros} leading zeros required.")
    print(f"   Coinbase pays to: {addr}")
    time.sleep(1.5)

    # -- Main game loop --
    pulls = 0
    best_zeros = 0

    draw_machine(block_info, pulls=pulls, best_zeros=best_zeros)

    while True:
        try:
            user_input = input("\n   > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n")
            break

        if user_input == 'q':
            break

        # -- PULL THE LEVER --
        pulls += 1

        # Pick a random 32-bit nonce
        nonce = random.randint(0, 0xFFFFFFFF)

        # Build the 80-byte block header
        header = build_block_header(
            block_info['version'],
            block_info['prev_block'],
            block_info['merkle_root'],
            block_info['timestamp'],
            block_info['bits'],
            nonce
        )

        # THE HASH -- one double SHA-256, exactly like the real network
        hash_bytes = double_sha256(header)

        # Display format: reversed bytes (big-endian, like block explorers show)
        display_hash = hash_to_display(hash_bytes)

        # Bitcoin compares hash as a little-endian uint256 against the target
        hash_int = int.from_bytes(hash_bytes, 'little')

        # Check against real Bitcoin network target
        won = hash_int <= target

        # -- Animate the spin and show result in-place --
        zeros = count_leading_zeros(display_hash)
        if zeros > best_zeros:
            best_zeros = zeros

        run_pull(display_hash, block_info, nonce, won, pulls, best_zeros)

        if won:
            time.sleep(1.0)
            print_jackpot_screen(block_info, nonce, display_hash)
            submit_block(block_info, nonce)
            break

        # Refresh block data periodically (new block may have been found)
        if pulls % 50 == 0:
            try:
                block_info = get_block_template(script_pubkey)
                block_info['address'] = addr
                target = block_info['target']
                target_hex = f"{target:064x}"
                required_zeros = count_leading_zeros(target_hex)
                print("   [New block detected -- refreshed]")
            except Exception:
                pass

    # -- Exit --
    print()
    odds_str = f"~1 in 16^{required_zeros} (2^{required_zeros * 4})"
    print("   ┌────────────────────────────────────────────────────┐")
    print(f"   │  CASHING OUT                                       │")
    print(f"   │                                                    │")
    print(f"   │  Total pulls:   {pulls:<34} │")
    print(f"   │  Best zeros:    {best_zeros:<34} │")
    print(f"   │  Zeros needed:  {required_zeros:<34} │")
    print(f"   │  Odds per pull: {odds_str:<34} │")
    if pulls > 0:
        pct = (1 - (1 - 1/16**required_zeros)**pulls) * 100
        if pct < 0.0001:
            pct_str = f"{pct:.2e}%"
        else:
            pct_str = f"{pct:.6f}%"
        print(f"   │  Win chance:    {pct_str:<34} │")
    print(f"   │                                                    │")
    print(f"   │  The machine is still here. It never sleeps.       │")
    print("   └────────────────────────────────────────────────────┘")
    print()


if __name__ == "__main__":
    main()
