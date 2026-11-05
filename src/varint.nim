## varint — Protobuf-style varint (LEB128) encoding and decoding.
##
## A varint is the compact integer encoding used by Protocol Buffers
## (and the same LEB128 family used by WASM, DWARF, SQLite, git and
## MIDI): each byte carries 7 bits of the value in its low bits and a
## continuation flag in its most significant bit. Small values cost
## fewer bytes: 0..127 encode to a single byte, 128..16383 to two, and
## a worst-case 64-bit value still fits in 10 bytes.
##
## This module provides:
## * unsigned core encode/decode (`encodeVarint`, `decodeVarint`,
##   `decodeVarintSafe`) over byte sequences, strings and streams
## * the standard ZigZag mapping for signed integers
##   (`zigzagEncode`, `zigzagDecode`) plus signed one-call helpers
##   (`encodeSVarint`, `decodeSVarint`, `writeSVarint`, `readSVarint`)
## * a `varintLen` helper for length-prefix layouts without encoding twice
##
## Semantics notes:
## * Decoding accepts non-canonical (over-padded) encodings such as
##   `0x80 0x00` for 0 — matching what protobuf-compatible readers do —
##   but rejects inputs longer than `maxVarintLen` (10) bytes and
##   encodings whose 10th byte carries more than bit 63.
## * A truncated input (fewer bytes than the continuation bits promise)
##   raises `VarintError` instead of silently returning a partial value.
## * All procedures are pure computation over their inputs (except the
##   stream variants, which do I/O); none of them mutate global state,
##   so the core API is safe to call from multiple threads.

import std/[streams]

type
  VarintError* = object of ValueError
    ## Raised for malformed varint input: truncated sequences,
    ## encodings longer than `maxVarintLen` bytes, or 10th bytes
    ## that would push the value beyond 64 bits.

  VarintStatus {.pure.} = enum
    veNone, veTruncated, veTooLong, veOverflow

const
  maxVarintLen* = 10
    ## Number of bytes a 64-bit varint can occupy in the worst case
    ## (9 bytes hold 63 bits; bit 63 rides in the 10th byte).

proc varintLen*(value: uint64): int {.inline.} =
  ## Number of bytes `encodeVarint(value)` produces, without encoding.
  result = 1
  var v = value shr 7
  while v != 0'u64:
    inc result
    v = v shr 7

proc encodeVarint*(value: uint64; outp: var seq[uint8]) =
  ## Append the varint encoding of `value` to `outp`.
  var v = value
  while true:
    let b = v.uint8 and 0x7F'u8
    v = v shr 7
    if v != 0'u64:
      outp.add(b or 0x80'u8)
    else:
      outp.add(b)
      break

proc encodeVarint*(value: uint64): seq[uint8] =
  ## Encode `value` as a fresh varint byte sequence.
  result = newSeqOfCap[uint8](varintLen(value))
  encodeVarint(value, result)

proc decodeCore(input: openArray[uint8]; pos: var int;
                value: var uint64): VarintStatus =
  ## Shared non-raising decoder. `pos` is advanced past the varint on
  ## success; on failure `pos` still points where the trouble began.
  var acc: uint64 = 0
  var shift = 0
  var idx = 0
  while true:
    if pos >= input.len:
      return veTruncated
    let b = input[pos]
    inc pos
    inc idx
    if shift == 63:
      # 10th byte: continuation bit would mean an 11-byte encoding,
      # and any payload beyond bit 63 overflows uint64.
      if (b and 0x80'u8) != 0:
        dec pos
        return veTooLong
      if b > 1'u8:
        dec pos
        return veOverflow
      value = acc or (b.uint64 shl 63)
      return veNone
    acc = acc or ((b and 0x7F'u8).uint64 shl shift)
    if (b and 0x80'u8) == 0:
      value = acc
      return veNone
    inc shift, 7

proc decodeVarint*(input: openArray[uint8]; pos: var int): uint64 =
  ## Decode a varint from `input` starting at `pos`, advancing `pos`
  ## past the consumed bytes. Raises `VarintError` on truncated input,
  ## encodings longer than `maxVarintLen` bytes, or values that do not
  ## fit in 64 bits. Accepts non-canonical over-padded encodings.
  var v: uint64
  let st = decodeCore(input, pos, v)
  if st != veNone:
    let why =
      case st
      of veTruncated: "truncated varint (stream ended mid-encoding) at byte " & $pos
      of veTooLong: "varint longer than " & $maxVarintLen & " bytes at byte " & $pos
      of veOverflow: "varint value overflows 64 bits at byte " & $pos
      of veNone: ""
    raise newException(VarintError, why)
  result = v

proc decodeVarint*(input: string; pos: var int): uint64 =
  ## Convenience overload for binary-buffer strings (wire data often
  ## lives in strings in Nim codebases). Same semantics as the byte
  ## sequence variant.
  var v: uint64
  let st = decodeCore(input.toOpenArrayByte(0, input.high), pos, v)
  if st != veNone:
    let why =
      case st
      of veTruncated: "truncated varint (stream ended mid-encoding) at byte " & $pos
      of veTooLong: "varint longer than " & $maxVarintLen & " bytes at byte " & $pos
      of veOverflow: "varint value overflows 64 bits at byte " & $pos
      of veNone: ""
    raise newException(VarintError, why)
  result = v

proc decodeVarintSafe*(input: openArray[uint8]; startPos = 0):
    tuple[value: uint64, nextPos: int, ok: bool] {.inline.} =
  ## Non-raising variant of `decodeVarint`: returns `(value, nextPos,
  ## ok)` where `ok` is false when the input is malformed; `nextPos`
  ## is the offset at which decoding stopped.
  var p = startPos
  var v: uint64
  let st = decodeCore(input, p, v)
  if st == veNone:
    (value: v, nextPos: p, ok: true)
  else:
    (value: 0'u64, nextPos: p, ok: false)

proc zigzagEncode*(v: int64): uint64 {.inline.} =
  ## Map a signed 64-bit integer to an unsigned one so that
  ## small magnitudes encode to small varints (-1 -> 1, 1 -> 2, ...).
  ## This is the standard "ZigZag" mapping used by Protocol Buffers
  ## for sint32/sint64 fields.
  cast[uint64]((v shl 1) xor ashr(v, 63))

proc zigzagDecode*(u: uint64): int64 {.inline.} =
  ## Inverse of `zigzagEncode`.
  cast[int64]((u shr 1) xor (0'u64 - (u and 1'u64)))

proc encodeSVarint*(v: int64): seq[uint8] =
  ## Encode a signed integer via ZigZag + varint.
  ## `encodeSVarint(-1)` is a single `0x01` byte instead of a 10-byte
  ## sign-extended unsigned encoding.
  encodeVarint(zigzagEncode(v))

proc encodeSVarint*(v: int64; outp: var seq[uint8]) =
  ## Append the ZigZag+varint encoding of `v` to `outp`.
  encodeVarint(zigzagEncode(v), outp)

proc decodeSVarint*(input: openArray[uint8]; pos: var int): int64 =
  ## Decode a ZigZag+varint encoded signed integer. Raises
  ## `VarintError` under the same conditions as `decodeVarint`.
  zigzagDecode(decodeVarint(input, pos))

proc decodeSVarint*(input: string; pos: var int): int64 =
  ## String overload of `decodeSVarint`.
  zigzagDecode(decodeVarint(input, pos))

proc decodeSVarintSafe*(input: openArray[uint8]; startPos = 0):
    tuple[value: int64, nextPos: int, ok: bool] {.inline.} =
  ## Non-raising signed decode; see `decodeVarintSafe`.
  var p = startPos
  var v: uint64
  let st = decodeCore(input, p, v)
  if st == veNone:
    (value: zigzagDecode(v), nextPos: p, ok: true)
  else:
    (value: 0'i64, nextPos: p, ok: false)

proc writeVarint*(s: Stream; value: uint64) =
  ## Write the varint encoding of `value` to `s`.
  var v = value
  while true:
    let b = v.uint8 and 0x7F'u8
    v = v shr 7
    if v != 0'u64:
      s.write(b or 0x80'u8)
    else:
      s.write(b)
      break

proc readVarint*(s: Stream): uint64 =
  ## Read a varint from `s`. Raises `VarintError` on end-of-stream
  ## inside an encoding, on encodings longer than `maxVarintLen`
  ## bytes, or on values that do not fit in 64 bits.
  var acc: uint64 = 0
  var shift = 0
  var idx = 0
  while true:
    if s.atEnd():
      raise newException(VarintError,
        "truncated varint (stream ended mid-encoding) after " & $idx & " bytes")
    let b = s.readUint8()
    inc idx
    if shift == 63:
      if (b and 0x80'u8) != 0:
        raise newException(VarintError,
          "varint longer than " & $maxVarintLen & " bytes")
      if b > 1'u8:
        raise newException(VarintError, "varint value overflows 64 bits")
      result = acc or (b.uint64 shl 63)
      return
    acc = acc or ((b and 0x7F'u8).uint64 shl shift)
    if (b and 0x80'u8) == 0:
      result = acc
      return
    inc shift, 7

proc writeSVarint*(s: Stream; value: int64) =
  ## Write the ZigZag+varint encoding of `value` to `s`.
  writeVarint(s, zigzagEncode(value))

proc readSVarint*(s: Stream): int64 =
  ## Read a ZigZag+varint encoded signed integer from `s`.
  zigzagDecode(readVarint(s))
