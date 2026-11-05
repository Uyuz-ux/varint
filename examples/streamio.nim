## Streaming varints: write/read values on a Stream (file, socket
## buffer, memory — any std/streams source).
import std/[streams, os]
import varint

let path = getTempDir() / "varint_example.bin"

# Write a few values, including a signed one.
var outp = newFileStream(path, fmWrite)
writeVarint(outp, 42'u64)
writeVarint(outp, uint64.high)
writeSVarint(outp, -12345'i64)
outp.close()

# Read them back in order. readVarint raises VarintError if the
# stream ends in the middle of an encoding — never a silent partial.
var inp = newFileStream(path, fmRead)
echo readVarint(inp)    # 42
echo readVarint(inp)    # 18446744073709551615
echo readSVarint(inp)   # -12345
echo "stream consumed: ", inp.atEnd()
inp.close()

removeFile(path)

# Error handling: 0x96 alone is a truncated varint.
try:
  let broken = newStringStream("\x96")
  discard readVarint(broken)
except VarintError as e:
  echo "caught: ", e.msg
