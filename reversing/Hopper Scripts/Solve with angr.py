import subprocess
import os

doc = Document.getCurrentDocument()
# seg = doc.getCurrentSegment()

# BIN = "~/tmp/Hopper/fairlight"
BIN = doc.getExecutableFilePath()
print("[*] bin path = " + BIN)

tag_find = doc.buildTag("find")
tag_avoid = doc.buildTag("avoid")
FINDS = []
AVOIDS = []

def print_array(prefix, arr):
    buf = []
    for x in arr:
        buf.append(hex(x)[:-1])
    print prefix + " = " + ', '.join(buf)

if doc.getTagWithName("find") == None:
    print("[!] #find not found")
# else:
#     print("[*] #find found")
if doc.getTagWithName("avoid") == None:
    print("[!] #avoid not found")
# else:
#     print("[*] #avoid found")

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
                print("found #find at 0x%x" % (start_addr))
                FINDS.append(start_addr)
            elif doc.hasTagAtAddress(tag_avoid, start_addr):
                print("found #avoid at 0x%x" % (start_addr))
                AVOIDS.append(start_addr)

# tags = doc.getTagWithName("find")
# FINDS = []
# for t in tags:
#     FINDS.append(t.getStartingAddress())
# tags = doc.getTagWithName("avoid")
# AVOIDS = []
# for t in tags:
#     AVOIDS.append(t.getStartingAddress())

print_array("finds", FINDS)
print_array("avoids", AVOIDS)

source_code = """
import angr

BIN = "__BIN__"

p = angr.Project(BIN, load_options={"auto_load_libs": False})
argv1 = angr.claripy.BVS("argv1", 0xE * 8)
initial_state = p.factory.entry_state(args=[BIN, argv1]) 

initial_path = p.factory.path(initial_state)
pg = p.factory.path_group(initial_state)
print("[*] angr exploring...")
pg.explore(find=FINDS, avoid=AVOIDS)

if len(pg.found):
    found = pg.found[0]
    print("[*] found: argv1 = " + found.state.se.any_str(argv1))
else:
    print("[!] not found")
"""

source_code = source_code.replace("__BIN__", BIN)
source_code = source_code.replace("FINDS", "(" + ','.join([str(x) for x in FINDS]) + ")")
source_code = source_code.replace("AVOIDS", "(" + ','.join([str(x) for x in AVOIDS]) + ")")

open("angr-solve.py", "w").write(source_code)
print("[*] executing angr script")
p = subprocess.Popen("python2 angr-solve.py", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate()
print("==== [angr] ====")
print(out[:-1])
if len(err) > 0:
    print("==== [angr:stderr] ====")
    print(err)

print("================")
os.system("rm angr-solve.py")
print("[*] solve done")

"""memo
* class Basic Block/Procedure hasTag(), getTagCount() not works
"""