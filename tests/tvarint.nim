## Tests for varint.nim — protobuf-style LEB128 encode/decode.
## Reference byte vectors cross-checked against the LEB128/protobuf
## wire format definition (e.g. field value 150 -> 0x96 0x01).

import std/[unittest, streams]
import varint

type
  Xorshift = object
    state: uint64

proc next(xs: var Xorshift): uint64 =
  ## Deterministic xorshift64* — same sequence on every run/ Nim version.
  var x = xs.state
  x = x xor (x shl 13)
  x = x xor (x shr 7)
  x = x xor (x shl 17)
  xs.state = x
  result = x

func u8seq(vals: varargs[int]): seq[uint8] =
  for v in vals:
    result.add(v.uint8)

suite "known vectors (protobuf/LEB128 reference)":
  test "single byte values":
    check encodeVarint(0'u64) == u8seq(0x00)
    check encodeVarint(1'u64) == u8seq(0x01)
    check encodeVarint(127'u64) == u8seq(0x7F)
  test "two and three byte values":
    check encodeVarint(128'u64) == u8seq(0x80, 0x01)
    check encodeVarint(150'u64) == u8seq(0x96, 0x01)
    check encodeVarint(300'u64) == u8seq(0xAC, 0x02)
    check encodeVarint(16384'u64) == u8seq(0x80, 0x80, 0x01)
  test "boundary widths":
    check encodeVarint((1'u64 shl 31) - 1'u64) == u8seq(0xFF, 0xFF, 0xFF, 0xFF, 0x07)
    check encodeVarint(1'u64 shl 32) == u8seq(0x80, 0x80, 0x80, 0x80, 0x10)
    check encodeVarint((1'u64 shl 63) - 1'u64) ==
      u8seq(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F)
    check encodeVarint(uint64.high) ==
      u8seq(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01)
  test "every encoded value decodes back":
    let values = [0'u64, 1'u64, 127'u64, 128'u64, 150'u64, 300'u64, 16384'u64,
      (1'u64 shl 31) - 1'u64, 1'u64 shl 32, (1'u64 shl 63) - 1'u64, uint64.high]
    for v in values:
      var pos = 0
      check decodeVarint(encodeVarint(v), pos) == v
      check pos == encodeVarint(v).len

suite "round-trips":
  test "small values 0..1023":
    for v in 0'u64 .. 1023'u64:
      var pos = 0
      check decodeVarint(encodeVarint(v), pos) == v
  test "all powers of two and their neighbourhoods":
    for k in 0 .. 63:
      let base = 1'u64 shl k
      for v in [base - 1'u64, base, base + 1'u64]:
        if base == 1'u64 and v == 0'u64:
          continue
        var pos = 0
        check decodeVarint(encodeVarint(v), pos) == v
  test "deterministic random 64-bit round-trip":
    var xs = Xorshift(state: 0x9E3779B97F4A7C15'u64)
    for _ in 0 ..< 5000:
      let v = xs.next()
      var pos = 0
      check decodeVarint(encodeVarint(v), pos) == v

suite "zigzag":
  test "mapping table":
    check zigzagEncode(0'i64) == 0'u64
    check zigzagEncode(-1'i64) == 1'u64
    check zigzagEncode(1'i64) == 2'u64
    check zigzagEncode(-2'i64) == 3'u64
    check zigzagEncode(2'i64) == 4'u64
    check zigzagEncode(int64.high) == uint64.high - 1'u64
    check zigzagEncode(int64.low) == uint64.high
  test "zigzag round-trip random":
    var xs = Xorshift(state: 0x0123456789ABCDEF'u64)
    for _ in 0 ..< 5000:
      let v = cast[int64](xs.next())
      check zigzagDecode(zigzagEncode(v)) == v
  test "signed one-call helpers":
    check encodeSVarint(-1'i64) == u8seq(0x01)
    check encodeSVarint(0'i64) == u8seq(0x00)
    check encodeSVarint(1'i64) == u8seq(0x02)
    check encodeSVarint(int64.low).len == 10
    for v in [0'i64, -1'i64, 1'i64, 127'i64, -128'i64, int64.high, int64.low]:
      var pos = 0
      check decodeSVarint(encodeSVarint(v), pos) == v
    # string overload + safe variant
    let bytes = encodeSVarint(-12345'i64)
    var s = ""
    for b in bytes:
      s.add(b.char)
    var pos = 0
    check decodeSVarint(s, pos) == -12345'i64
    let safe = decodeSVarintSafe(bytes, 0)
    check safe.ok and safe.value == -12345'i64 and safe.nextPos == bytes.len

suite "error handling":
  test "truncated input raises VarintError":
    let full = encodeVarint(300'u64)
    check full.len == 2
    for cut in 0 ..< full.len:
      var pos = 0
      expect VarintError:
        discard decodeVarint(full[0 ..< cut], pos)
      let safe = decodeVarintSafe(full[0 ..< cut], 0)
      check not safe.ok
  test "more than 10 bytes rejected":
    # 10 continuation bytes then a payload byte: 11 bytes total.
    var bad: seq[uint8]
    for _ in 0 ..< 10:
      bad.add(0x80'u8)
    bad.add(0x01'u8)
    var pos = 0
    expect VarintError:
      discard decodeVarint(bad, pos)
  test "10th byte payload beyond bit 63 rejected":
    # 9 continuation bytes then payload 0x02: fits in 10 bytes but
    # bit 64 would be needed -> overflow.
    var bad: seq[uint8]
    for _ in 0 ..< 9:
      bad.add(0x80'u8)
    bad.add(0x02'u8)
    var pos = 0
    expect VarintError:
      discard decodeVarint(bad, pos)
    check not decodeVarintSafe(bad, 0).ok
  test "non-canonical encodings accepted (protobuf interop)":
    check decodeVarintSafe(u8seq(0x80, 0x00), 0).value == 0'u64
    check decodeVarintSafe(u8seq(0x81, 0x00), 0).value == 1'u64
    check decodeVarintSafe(u8seq(0x80, 0x80, 0x00), 0).value == 0'u64

suite "cursors and streams":
  test "sequential values share one buffer with correct offsets":
    let values = [300'u64, 1'u64, uint64.high, 0'u64, 42'u64]
    var buf: seq[uint8]
    for v in values:
      encodeVarint(v, buf)
    var pos = 0
    for v in values:
      check decodeVarint(buf, pos) == v
    check pos == buf.len
  test "string overload walks a wire-style buffer":
    var s = ""
    s.add(0xDE'u8.char)  # irrelevant prefix byte
    for v in [7'u64, 2048'u64, 127'u64]:
      for b in encodeVarint(v):
        s.add(b.char)
    var pos = 1
    check decodeVarint(s, pos) == 7'u64
    check decodeVarint(s, pos) == 2048'u64
    check decodeVarint(s, pos) == 127'u64
    check pos == s.len
  test "stream round-trip":
    let ss = newStringStream()
    writeVarint(ss, 0'u64)
    writeVarint(ss, uint64.high)
    writeVarint(ss, 300'u64)
    writeSVarint(ss, -1'i64)
    writeSVarint(ss, 98765'i64)
    ss.setPosition(0)
    check readVarint(ss) == 0'u64
    check readVarint(ss) == uint64.high
    check readVarint(ss) == 300'u64
    check readSVarint(ss) == -1'i64
    check readSVarint(ss) == 98765'i64
    check ss.atEnd()
    ss.close()
  test "stream truncation raises VarintError":
    let ss = newStringStream("\x96")
    expect VarintError:
      discard readVarint(ss)
    ss.close()

suite "varintLen":
  test "length matches encoding size":
    let values = [0'u64, 1'u64, 127'u64, 128'u64, 150'u64, 300'u64,
      (1'u64 shl 31) - 1'u64, 1'u64 shl 32, (1'u64 shl 63) - 1'u64, uint64.high]
    for v in values:
      check varintLen(v) == encodeVarint(v).len
  test "boundaries":
    check varintLen(0'u64) == 1
    check varintLen(127'u64) == 1
    check varintLen(128'u64) == 2
    check varintLen(uint64.high) == 10
    check maxVarintLen == 10
  test "append overload builds multi-value buffers":
    var buf: seq[uint8]
    encodeVarint(150'u64, buf)
    encodeSVarint(-7'i64, buf)
    check buf.len == 2 + 1
    var pos = 0
    check decodeVarint(buf, pos) == 150'u64
    check decodeSVarint(buf, pos) == -7'i64
    check pos == buf.len
