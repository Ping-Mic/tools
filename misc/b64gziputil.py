import sys
import base64
import zlib

def usage():
    print("%s <c or d> <text>" % sys.argv[0])
    exit()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()

    option = sys.argv[1]
    data = (sys.argv[2]).encode('utf-8')

    if option == "c":
        c = base64.b64encode(zlib.compress(data))
        print(c)
    elif option == "d":
        d = zlib.decompress(base64.b64decode(data))
        print(d)
    else:
        usage()


