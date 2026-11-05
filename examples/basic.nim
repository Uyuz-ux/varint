## Basic varint usage: encode, decode, and inspect byte costs.
import varint

# Encode an unsigned value to a fresh byte sequence.
let bytes = encodeVarint(300'u64)
echo "300 encodes to ", bytes, " (", bytes.len, " bytes)"  # @[172, 2] -> 0xAC 0x02

# Decode with a cursor: the cursor advances past the consumed bytes.
var pos = 0
echo "decoded: ", decodeVarint(bytes, pos)  # 300
echo "cursor now at: ", pos                # 2

# Byte cost is predictable via varintLen — useful for length-prefixed
# layouts, no need to encode first:
echo "length of 150: ", varintLen(150'u64)          # 2
echo "length of uint64.high: ", varintLen(uint64.high)  # 10

# Signed integers go through ZigZag so small magnitudes stay small:
echo "-1 encodes to ", encodeSVarint(-1'i64)  # @[1]  (not ten bytes!)

# A wire-style buffer can hold several values back to back:
var buf: seq[uint8]
encodeVarint(1'u64, buf)
encodeVarint(150'u64, buf)
encodeSVarint(-7'i64, buf)
pos = 0
echo decodeVarint(buf, pos)     # 1
echo decodeVarint(buf, pos)     # 150
echo decodeSVarint(buf, pos)    # -7
echo "consumed ", pos, " of ", buf.len, " bytes"
