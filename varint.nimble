# Package

version       = "0.2.0"
author        = "Uyuz-ux"
description   = "Protobuf-style varint (LEB128) encode/decode + ZigZag signed encoding"
license       = "MIT"
srcDir        = "src"

# Dependencies

requires "nim >= 1.6"

# Tests

task test, "Runs the test suite":
  exec "nim c -r --path:src tests/tvarint.nim"
