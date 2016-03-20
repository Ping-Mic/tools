import sys, zlib

buflen = 4096

f = open(sys.argv[1], 'rb')
try:
  sys.stdout.write("ANDROID BACKUP\x0a1\x4a1\x0anone\x0a")

  z = zlib.compressobj(9)

  while True:
    buf = f.read(buflen)
    if len(buf) <= 0:
      break
    compressed = z.compress(buf)
    sys.stdout.write(compressed)

  compressed = z.flush()
  sys.stdout.write(compressed)
  sys.stdout.flush()
finally:
  f.close()
