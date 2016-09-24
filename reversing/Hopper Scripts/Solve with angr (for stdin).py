import subprocess
import signal
import os

"""you can solve following problems with this plugin:
https://github.com/angr/angr-doc/tree/master/examples/defcamp_r100
"""

def print_array(prefix, arr):
    buf = []
    for x in arr:
        buf.append(x)
    print prefix + " = " + ', '.join(buf)

doc = Document.getCurrentDocument()

BIN = doc.getExecutableFilePath()
print("[*] bin path = " + BIN)

tag_find = doc.buildTag("find")
tag_avoid = doc.buildTag("avoid")
FINDS = []
AVOIDS = []

INPUT_LENGTH = doc.ask("input length; empty is OK") # string
if INPUT_LENGTH == None:
    INPUT_LENGTH = ""
else:
    print("[*] input length = " + INPUT_LENGTH)

BUF_INIT_CODE = ""
if not INPUT_LENGTH == "":
    BUF_INIT_CODE = r"""
initial_state.libc.buf_symbolic_bytes = INPUT_LENGTH + 1
initial_state.posix.files[0].seek(0)
for i in range(INPUT_LENGTH): # initialize all array items
    k = initial_state.posix.files[0].read_from(1)
    initial_state.add_constraints(k != '\x00') # null
    initial_state.add_constraints(k >= ' ') # '\x20'
    initial_state.add_constraints(k <= '~') # '\x7e'
initial_state.posix.files[0].seek(0)
"""

FLAG_PREFIX = doc.ask("input flag prefix (`flag{` and `CTF{` and so on); empty is OK")
FLAG_PREFIX_CODE = ""
if not FLAG_PREFIX == None:
    print("[*] flag prefix = " + FLAG_PREFIX)
    for i in range(len(FLAG_PREFIX)):
        FLAG_PREFIX_CODE += "k = initial_state.posix.files[0].read_from(1)\ninitial_state.se.add(k == ord('%s'))\n" % (FLAG_PREFIX[i])
    FLAG_PREFIX_CODE += "initial_state.posix.files[0].seek(0)\n"

if doc.getTagWithName("find") == None:
    print("[!] #find not found")
if doc.getTagWithName("avoid") == None:
    print("[!] #avoid not found")

nsegs = doc.getSegmentCount()
for segnum in range(nsegs):
    seg = doc.getSegment(segnum)

    num_procedure = seg.getProcedureCount()
    for i in range(num_procedure):
        p = seg.getProcedureAtIndex(i)
        num_bb = p.getBasicBlockCount()
        for j in range(num_bb):
            bb = p.getBasicBlock(j)
            start_addr = bb.getStartingAddress()
            if doc.hasTagAtAddress(tag_find, start_addr):
                print("  found #find at 0x%x" % (start_addr))
                FINDS.append(hex(start_addr)[:-1])
            elif doc.hasTagAtAddress(tag_avoid, start_addr):
                print("  found #avoid at 0x%x" % (start_addr))
                AVOIDS.append(hex(start_addr)[:-1])

print_array("finds", FINDS)
print_array("avoids", AVOIDS)

if len(FINDS) == 0 and len(AVOIDS) == 0:
    print("[!] no #find and no #avoid is not given. exit")
else:
    source_code = r"""
import angr

BIN = "__BIN__"

p = angr.Project(BIN, load_options={"auto_load_libs": False})
initial_state = p.factory.entry_state(args=[BIN])

BUF_INIT_CODE
FLAG_PREFIX_CODE

initial_path = p.factory.path(initial_state)
pg = p.factory.path_group(initial_state)
print("[*] angr exploring...")
pg.explore(find=FINDS, avoid=AVOIDS)

if len(pg.found):
    found = pg.found[0]
    print("[*] found: stdin = " + found.state.posix.dumps(0).strip('\0\n'))
else:
    print("[!] not found")
"""

    source_code = source_code.replace("__BIN__", BIN)
    source_code = source_code.replace("FLAG_PREFIX_CODE", FLAG_PREFIX_CODE)
    source_code = source_code.replace("BUF_INIT_CODE", BUF_INIT_CODE)
    source_code = source_code.replace("INPUT_LENGTH", INPUT_LENGTH)
    source_code = source_code.replace("FINDS", "(" + ','.join([str(x) for x in FINDS]) + ")")
    source_code = source_code.replace("AVOIDS", "(" + ','.join([str(x) for x in AVOIDS]) + ")")

    open("angr-solve.py", "w").write(source_code)
    print("[*] executing angr script")
    p = subprocess.Popen("python2 angr-solve.py", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    print("==== [angr] ====")
    print(out[:-1])
    if len(err) > 0:
        print("\033[31m;==== [angr:stderr] ====\033[0m;")
        print(err)
    else:
        pass
        # os.system("rm angr-solve.py")

    print("================")
    print("[*] solve done")

"""memo
* class Basic Block/Procedure hasTag(), getTagCount() not works
"""