# varint

Protobuf-style **varint (LEB128)** encoding and decoding for Nim, plus the
standard **ZigZag** mapping for signed integers. Pure stdlib — no C
dependencies, no build steps.

A varint stores an integer across one or more bytes: each byte carries 7
payload bits and a continuation flag in its most significant bit. Small
values cost fewer bytes:

| Value | Bytes |
|---|---|
| 0–127 | 1 |
| 128–16383 | 2 |
| 2³¹−1 | 5 |
| 2⁶⁴−1 (worst case) | 10 |

This is the integer encoding used by Protocol Buffers, and the same LEB128
family used by WASM, DWARF, SQLite and git.

## Why

Nim's standard library has no varint API, and every project that touches
wire formats ends up re-implementing one. This module keeps the core small
and strictly specified:

- **Truncation is loud.** Decoding an input whose continuation bits promise
  more bytes than are available raises `VarintError` — never a silent
  partial value.
- **`maxVarintLen` (10 bytes) is enforced.** Encodings longer than 10 bytes
  and 10th bytes whose payload exceeds bit 63 are rejected, matching
  protobuf-compatible readers.
- **Non-canonical inputs are accepted.** Over-padded encodings such as
  `0x80 0x00` (a two-byte zero) decode to their value, so real-world
  wire data from other implementations round-trips.
- **Signed integers stay small.** `encodeSVarint(-1)` is a single `0x01`
  byte, not a 10-byte sign-extended unsigned encoding, via the standard
  ZigZag mapping (`zigzagEncode` / `zigzagDecode`).
- **Batch layout without length prefixes.** `pack` concatenates a whole
  sequence of values into one buffer and the `values` iterator reads them
  back — the layout of protobuf packed repeated fields, DWARF ULEB128
  sequences and SQLite header varints.
- **Pure computation.** The sequence/string APIs are side-effect free and
  safe to call from multiple threads.

## API

```nim
import varint

type VarintError* = object of ValueError

const maxVarintLen* = 10

proc varintLen*(value: uint64): int
proc encodeVarint*(value: uint64): seq[uint8]
proc encodeVarint*(value: uint64; outp: var seq[uint8])   # appends
proc decodeVarint*(input: openArray[uint8]; pos: var int): uint64
proc decodeVarint*(input: string; pos: var int): uint64   # wire buffers
proc decodeVarintSafe*(input: openArray[uint8]; startPos = 0):
  tuple[value: uint64, nextPos: int, ok: bool]            # non-raising
proc skipVarint*(input: openArray[uint8]; pos: var int)   # skip unknown fields
proc skipVarint*(input: string; pos: var int)

proc zigzagEncode*(v: int64): uint64
proc zigzagDecode*(u: uint64): int64
proc encodeSVarint*(v: int64): seq[uint8]
proc encodeSVarint*(v: int64; outp: var seq[uint8])
proc decodeSVarint*(input: openArray[uint8]; pos: var int): int64
proc decodeSVarint*(input: string; pos: var int): int64
proc decodeSVarintSafe*(input: openArray[uint8]; startPos = 0):
  tuple[value: int64, nextPos: int, ok: bool]

proc writeVarint*(s: Stream; value: uint64)
proc readVarint*(s: Stream): uint64
proc writeSVarint*(s: Stream; value: int64)
proc readSVarint*(s: Stream): int64

proc pack*(values: openArray[uint64]): seq[uint8]        # batch encode
proc packSigned*(values: openArray[int64]): seq[uint8]   # ZigZag batch
iterator values*(buf: openArray[uint8]): uint64          # batch decode
iterator values*(buf: string): uint64
iterator values*(s: Stream): uint64                      # until EOF
iterator svalues*(buf: openArray[uint8]): int64          # ZigZag batch
iterator svalues*(buf: string): int64
iterator svalues*(s: Stream): int64
```

`pos` is an in-out cursor: after a successful `decodeVarint`, it points
just past the consumed bytes, so consecutive values can be read from one
buffer without slicing. `decodeVarintSafe` returns the offset where
decoding stopped even on failure. `skipVarint` advances the same cursor
past one encoding without building the value — validating exactly like
`decodeVarint` and landing on the same position — which is what protobuf
wire parsers do when skipping unknown fields.

## Example

```nim
import varint

var buf: seq[uint8]
encodeVarint(300'u64, buf)       # @[0xAC, 0x02]
encodeSVarint(-7'i64, buf)       # @[0x0D]

var pos = 0
assert decodeVarint(buf, pos) == 300
assert decodeSVarint(buf, pos) == -7
assert pos == buf.len

# Batch layout: many values, no length prefix needed
let batch = pack([5'u64, 1'u64 shl 40, uint64.high])
for v in values(batch):
  echo v                                  # 5, 1099511627776, 18446744073709551615
```

More in [`examples/`](examples/): `basic.nim` covers cursors and byte
costs; `streamio.nim` covers file streams and error handling.

## Tests

38 tests cover the protobuf reference byte vectors, exhaustive
small-value and power-of-two round-trips, 10,000 deterministic random
round-trips (unsigned + ZigZag), batch `pack`/`values` round-trips
(including 2,000 random values in one buffer), truncation, overlong
encodings, non-canonical acceptance, cursor arithmetic, `skipVarint`
cursor agreement with `decodeVarint` (boundary values, packed buffers,
malformed input) and the stream API. The suite passes on default,
`-d:release`, `-d:danger` and `--mm:orc` builds, and CI checks Nim
1.6.20, 2.0.8, 2.2.4 and stable.

```sh
nimble test
```

## Install

```sh
nimble install https://github.com/Uyuz-ux/varint
```

## License

MIT
