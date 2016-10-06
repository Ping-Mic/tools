import subprocess
import os
import re

"""you can solve following problems with this plugin:
./examples/license_file
"""

def print_array(prefix, arr):
    buf = []
    for x in arr:
        buf.append(x)
    print prefix + " = " + ', '.join(buf)

def cleansing(text):
    text = re.sub("^\.", "", text, flags=re.MULTILINE)
    text = re.sub("^\.*\n", "", text, flags=re.MULTILINE)
    text = re.sub("^\s*\n", "", text, flags=re.MULTILINE)
    return text

doc = Document.getCurrentDocument()

BIN = doc.getExecutableFilePath()
print("[*] bin path = " + BIN)

tag_find = doc.buildTag("find")
tag_avoid = doc.buildTag("avoid")
FINDS = []
AVOIDS = []

# addr = doc.getAddressForName("file_name")
# if addr < 0:
#     print("[!] sim_start not found. exit")
#     return
FILE_NAME = BIN + "/../license"

INPUT_LENGTH = doc.ask("input length") # string
if INPUT_LENGTH == None:
    INPUT_LENGTH = "30"
print("[*] input length = " + INPUT_LENGTH)

FLAG_PREFIX = doc.ask("input flag prefix (`flag{` and `CTF{` and so on); empty is OK")
FLAG_PREFIX_CODE = ""
if not FLAG_PREFIX == None:
    print("[*] flag prefix = " + FLAG_PREFIX)
    for i in range(len(FLAG_PREFIX)):
        FLAG_PREFIX_CODE += "initial_state.add_constraints(argv1.chop(8)[%d] == '%s')\n" % (i, FLAG_PREFIX[i])

if doc.getTagWithName("find") == None:
    print("[!] #find not found")
if doc.getTagWithName("avoid") == None:
    print("[!] #avoid not found")

nsegs = doc.getSegmentCount()
for segnum in range(nsegs):
    seg = doc.getSegment(segnum)

    num_procedure = seg.getProcedureCount()
    # print("[*] found %d procedures" % num_procedure)
    for i in range(num_procedure):
        p = seg.getProcedureAtIndex(i)
        num_bb = p.getBasicBlockCount()
        # print("[*] procedure %d has %d basic blocks" % (i, num_bb))
        for j in range(num_bb):
            bb = p.getBasicBlock(j)
            start_addr = bb.getStartingAddress()
            if doc.hasTagAtAddress(tag_find, start_addr):
                print("  found #find at 0x%x" % (start_addr))
                FINDS.append(hex(start_addr)[:-1])
                if not seg.getNameAtAddress(start_addr):
                    seg.setNameAtAddress(start_addr, "find_" + hex(start_addr)[:-1])
            elif doc.hasTagAtAddress(tag_avoid, start_addr):
                print("  found #avoid at 0x%x" % (start_addr))
                AVOIDS.append(hex(start_addr)[:-1])
                if not seg.getNameAtAddress(start_addr):
                    seg.setNameAtAddress(start_addr, "avoid_" + hex(start_addr)[:-1])

print_array("finds", FINDS)
print_array("avoids", AVOIDS)

if len(FINDS) == 0 and len(AVOIDS) == 0:
    print("[!] NO #find and #avoid are found. exit")
else:
    source_code = r"""
# ref. https://github.com/angr/angr-doc/blob/master/examples/asisctffinals2015_license/solve.py
import angr
import simuvex
import sys, threading

FLAG_FINISHED = False

def cyclic_task():
    # NOTE: enable SIGINT while this child process is runnig 
    # (stdX.read() in PIPE.communicate() may blocks asynchronous SIGINT)
    sys.stdout.write('.') 
    sys.stdout.flush()
    if FLAG_FINISHED == False:
        threading.Timer(1, cyclic_task).start()

BIN = "__BIN__"

p = angr.Project(BIN, load_options={"auto_load_libs": False})
initial_state = p.factory.entry_state(args=[BIN]) 

bytes = None
constraints = [ ]
for i in xrange(1):
    line = [ ]
    for j in xrange(INPUT_LENGTH):
        line.append(initial_state.se.BVS('license_file_byte_%d_%d' % (i, j), 8))
        initial_state.add_constraints(line[-1] != 0x0a)
    if bytes is None:
        bytes = initial_state.se.Concat(*line)
    else:
        bytes = initial_state.se.Concat(bytes, initial_state.se.BVV(0x0a, 8), *line)
content = simuvex.SimSymbolicMemory(memory_id="file_%s" % "license") # TODO
content.set_state(initial_state)
content.store(0, bytes)

file = simuvex.SimFile("FILE_NAME", 'r', content=content, size=len(bytes) / 8)
fs = {
    "FILE_NAME": file
}
initial_state.posix.fs = fs

# initial_state.libc.buf_symbolic_bytes = INPUT_LENGTH + 1
# for byte in argv1.chop(8): # initialize all array items
#     initial_state.add_constraints(byte != '\x00') # null
#     initial_state.add_constraints(byte >= ' ') # '\x20'
#     initial_state.add_constraints(byte <= '~') # '\x7e'
FLAG_PREFIX_CODE

initial_path = p.factory.path(initial_state)
pg = p.factory.path_group(initial_state)
print("[*] angr exploring...")
cyclic_task()
pg.explore(find=FINDS, avoid=AVOIDS)
FLAG_FINISHED = True
print("")
if len(pg.found):
    found = pg.found[0]
    print(found.state.posix.files)
    fd = max(found.state.posix.files.keys())
    print("[*] found: file = " + found.state.posix.dumps(fd))
else:
    print("[!] not found")
"""

    source_code = source_code.replace("__BIN__", BIN)
    source_code = source_code.replace("FILE_NAME", FILE_NAME)
    source_code = source_code.replace("FLAG_PREFIX_CODE", FLAG_PREFIX_CODE)
    source_code = source_code.replace("INPUT_LENGTH", INPUT_LENGTH)
    source_code = source_code.replace("FINDS", "(" + ','.join([str(x) for x in FINDS]) + ")")
    source_code = source_code.replace("AVOIDS", "(" + ','.join([str(x) for x in AVOIDS]) + ")")

    try:
        open("angr-solve.py", "w").write(source_code)
        print("[*] executing angr script")
        p = subprocess.Popen("python2 angr-solve.py", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        print("==== [angr] ====")
        out = cleansing(out)
        print(out[:-1])
        if len(err) > 0:
            print("==== [angr:stderr] ====")
            print(err)
        else:
            pass
            # os.system("rm angr-solve.py")
        print("================")
        print("[*] solve done")
    except KeyboardInterrupt:
        print("[!] canceled")

"""memo
* class Basic Block/Procedure hasTag(), getTagCount() not works
"""