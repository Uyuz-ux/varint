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

suite "pack and values (batch API)":
  test "pack + values round-trip on mixed magnitudes":
    let vals = [0'u64, 1'u64, 127'u64, 128'u64, 300'u64, 1'u64 shl 32,
      (1'u64 shl 63) - 1'u64, uint64.high]
    let buf = pack(vals)
    var expected: seq[uint8]
    for v in vals:
      encodeVarint(v, expected)
    check buf == expected
    var got: seq[uint64]
    for v in values(buf):
      got.add(v)
    check got == @vals
  test "values over a string buffer":
    var s = ""
    for b in pack([7'u64, 2048'u64, 0'u64, uint64.high]):
      s.add(b.char)
    var got: seq[uint64]
    for v in values(s):
      got.add(v)
    check got == @[7'u64, 2048'u64, 0'u64, uint64.high]
  test "packSigned + svalues round-trip with negatives":
    let vals = [0'i64, -1'i64, 1'i64, -128'i64, 300'i64, int64.low, int64.high]
    let buf = packSigned(vals)
    var expected: seq[uint8]
    for v in vals:
      encodeSVarint(v, expected)
    check buf == expected
    var got: seq[int64]
    for v in svalues(buf):
      got.add(v)
    check got == @vals
  test "empty input yields nothing":
    let empty: seq[uint64] = @[]
    check pack(empty).len == 0
    let emptyBuf: seq[uint8] = @[]
    var n = 0
    for _ in values(emptyBuf):
      inc n
    check n == 0
    let emptySigned: seq[int64] = @[]
    check packSigned(emptySigned).len == 0
    for _ in svalues(emptyBuf):
      inc n
    check n == 0
  test "truncated tail raises VarintError":
    let buf = pack([150'u64])   # 0x96 0x01
    let cut = buf[0 ..< 1]      # continuation bit promises a second byte
    expect VarintError:
      for _ in values(cut):
        discard
    var s = ""
    s.add(0x96'u8.char)
    expect VarintError:
      for _ in values(s):
        discard
  test "stream iteration stops at end of stream":
    let ss = newStringStream()
    writeVarint(ss, 5'u64)
    writeVarint(ss, 123456789'u64)
    ss.setPosition(0)
    var got: seq[uint64]
    for v in values(ss):
      got.add(v)
    check got == @[5'u64, 123456789'u64]
    check ss.atEnd()
    ss.close()
  test "signed stream iteration reads every varint":
    let ss = newStringStream()
    writeSVarint(ss, -1'i64)
    writeSVarint(ss, 98765'i64)
    ss.setPosition(0)
    var got: seq[int64]
    for v in svalues(ss):
      got.add(v)
    check got == @[-1'i64, 98765'i64]
    check ss.atEnd()
    ss.close()
  test "stream truncation mid-encoding raises":
    let ss = newStringStream("\x96")
    expect VarintError:
      for _ in values(ss):
        discard
    ss.close()
  test "deterministic random batch round-trip":
    var xs = Xorshift(state: 0xDEADBEEFCAFEBABE'u64)
    var vals: seq[uint64]
    for _ in 0 ..< 2000:
      vals.add(xs.next())
    let buf = pack(vals)
    var n = 0
    for v in values(buf):
      check v == vals[n]
      inc n
    check n == vals.len

suite "skipVarint":
  test "skip lands on the same pos as decode for boundary values":
    const bounds = [0'u64, 1, 127, 128, 300, 16383, 16384, 65535,
                    1'u64 shl 21, 1'u64 shl 28, 1'u64 shl 35,
                    1'u64 shl 42, 1'u64 shl 49, 1'u64 shl 56,
                    1'u64 shl 63, uint64.high]
    for v in bounds:
      let buf = encodeVarint(v)
      var pSkip = 0
      skipVarint(buf, pSkip)
      var pDec = 0
      discard decodeVarint(buf, pDec)
      check pSkip == pDec
      check pSkip == buf.len

  test "skipping a packed buffer consumes it exactly":
    let buf = pack([0'u64, 1, 127, 128, 300, uint64.high])
    var pos = 0
    var count = 0
    while pos < buf.len:
      skipVarint(buf, pos)
      inc count
    check count == 6
    check pos == buf.len

  test "skip accepts over-padded encodings like decode":
    let buf = @[0x80'u8, 0x00]
    var pos = 0
    skipVarint(buf, pos)
    check pos == 2

  test "truncated input raises VarintError":
    let buf = @[0x80'u8]
    var pos = 0
    expect VarintError:
      skipVarint(buf, pos)

  test "encodings longer than maxVarintLen raise":
    var buf: seq[uint8]
    for i in 1 .. 11:
      buf.add(0x80'u8)
    var pos = 0
    expect VarintError:
      skipVarint(buf, pos)

  test "10th byte payload beyond bit 63 raises":
    var buf: seq[uint8]
    for i in 1 .. 9:
      buf.add(0x80'u8)
    buf.add(0x02'u8)
    var pos = 0
    expect VarintError:
      skipVarint(buf, pos)

  test "string overload matches sequence semantics":
    let batch = pack([7'u64, 999'u64])
    var s = newString(batch.len)
    for i, b in batch:
      s[i] = char(b)
    var pos = 0
    skipVarint(s, pos)
    check pos == varintLen(7'u64)
    skipVarint(s, pos)
    check pos == s.len

  test "skip interleaves with decode without cursor drift":
    let buf = packSigned([-3'i64, 0, 1, -2147483648, 2147483647])
    var pSkip = 0
    var pDec = 0
    var steps = 0
    while pSkip < buf.len:
      skipVarint(buf, pSkip)
      discard decodeSVarint(buf, pDec)
      check pSkip == pDec
      inc steps
    check steps == 5
