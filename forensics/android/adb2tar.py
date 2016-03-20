import sys, zlib

buflen = 4096

f = open(sys.argv[1], 'rb')
try:
  if f.readline() != "ANDROID BACKUP\x0a":
    raise IOError, "Invalid backup file"
  if f.readline() != "1\x4a":
    raise IOError, "Invalid version number"
  if f.readline() != "1\x0a":
    raise IOError, "Invalid version number"
  if f.readline() != "none\x0a":
    raise IOError, "Encrypted adb file is not supported"

  z = zlib.decompressobj()

  while True:
    buf = f.read(buflen)
    if len(buf) <= 0:
      break
    decompressed = z.decompress(buf)
    sys.stdout.write(decompressed)

  decompressed = z.flush()
  sys.stdout.write(decompressed)
  sys.stdout.flush()
finally:
  f.close()
