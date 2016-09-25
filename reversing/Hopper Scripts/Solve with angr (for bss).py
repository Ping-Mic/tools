import subprocess
import os, sys
import re

"""you can solve following problems with this plugin:
./examples/bss_flag
"""

def print_array(prefix, arr):
    buf = []
    for x in arr:
        buf.append(str(x))
    print prefix + " = " + ', '.join(buf)

def cleansing(text):
    text = re.sub("^\.", "", text, flags=re.MULTILINE)
    text = re.sub("^\.*\n", "", text, flags=re.MULTILINE)
    text = re.sub("^\s*\n", "", text, flags=re.MULTILINE)
    return text

def main():
    doc = Document.getCurrentDocument()

    BIN = doc.getExecutableFilePath()
    print("[*] bin path = " + BIN)

    tag_find = doc.buildTag("find")
    tag_avoid = doc.buildTag("avoid")
    # tag_pass = doc.buildTag("pass")
    FINDS = []
    AVOIDS = []
    PASS = []
    TARGET_ADDR = ""

    print("")

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
                    print("--found #find at 0x%x" % (start_addr))
                    FINDS.append(hex(start_addr)[:-1])
                    if not seg.getNameAtAddress(start_addr):
                        seg.setNameAtAddress(start_addr, "find_" + hex(start_addr)[:-1])
                elif doc.hasTagAtAddress(tag_avoid, start_addr):
                    print("--found #avoid at 0x%x" % (start_addr))
                    AVOIDS.append(hex(start_addr)[:-1])
                    if not seg.getNameAtAddress(start_addr):
                        seg.setNameAtAddress(start_addr, "avoid_" + hex(start_addr)[:-1])
                # elif doc.hasTagAtAddress(tag_pass, start_addr):
                #     print("  found #pass at 0x%x" % (start_addr))
                #     PASS.append({"start":start_addr, "end":bb.getEndingAddress()})
                #     if not seg.getNameAtAddress(start_addr):
                #         seg.setNameAtAddress(start_addr, "pass_" + hex(start_addr)[:-1])                    

    print_array("finds", FINDS)
    print_array("avoids", AVOIDS)
    # print_array("pass", AVOIDS)
    if len(FINDS) == 0 and len(AVOIDS) == 0:
        print("[!] NO #find and #avoid are found. exit")
        return

    addr = doc.getAddressForName("sim_start")
    if addr < 0:
        print("[!] sim_start not found. exit")
        return
    SIM_START = "0x{0:x}".format(addr)
    print("[*] simulation starts from " + SIM_START)

    target = doc.ask("target symbol user input comes:")
    if target == None:
        print("[!] not target specified. exit")
        return
    else:
        TARGET_ADDR = doc.getAddressForName(target)
        TARGET_ADDR = "0x%x" % TARGET_ADDR
    print("[*] target address = " + TARGET_ADDR)

    INPUT_LENGTH = doc.ask("input length (Default:30):") # string
    if INPUT_LENGTH == None:
        INPUT_LENGTH = "30"
    print("[*] input length = " + INPUT_LENGTH)

    FLAG_PREFIX = doc.ask("flag prefix (`flag{`, `CTF{`, ...; empty OK):")
    FLAG_PREFIX_CODE = ""
    if not FLAG_PREFIX == None:
        print("[*] flag prefix = " + FLAG_PREFIX)
        for i in range(len(FLAG_PREFIX)):
            FLAG_PREFIX_CODE += "initial_state.add_constraints(flag.chop(8)[%d] == '%s')\n" % (i, FLAG_PREFIX[i])

    # P_HOOK = ""
    # if len(PASS) > 0:
    #     for addr in PASS:
    #         P_HOOK += "p.hook(0x%x, patch_0, length=0x%x-0x%x)\n" % (addr.start, addr.end, addr.start)
    # else:
    #     print("[*] set no hooks")

    source_code = r"""
import angr
import simuvex
import sys, threading

FLAG_FINISHED = False

def patch_0(state):
    pass

def cyclic_task():
    # NOTE: enable SIGINT while this child process is runnig 
    # (stdX.read() in PIPE.communicate() may blocks asynchronous SIGINT)
    sys.stdout.write('.') 
    sys.stdout.flush()
    if FLAG_FINISHED == False:
        threading.Timer(1, cyclic_task).start()

BIN = "__BIN__"

p = angr.Project(BIN, load_options={"auto_load_libs": False})
flag = angr.claripy.BVS("flag", INPUT_LENGTH * 8)
initial_state = p.factory.blank_state(addr=SIM_START, remove_options={simuvex.s_options.LAZY_SOLVES})

initial_state.memory.store(0xd0000010, flag) # assign flag the address
initial_state.mem[TARGET_ADDR:].dword = 0xd0000010 # overwrite pointer
# initial_state.regs.rsp = 0x7fffffffe870
# initial_state.regs.rbp = 0x7fffffffe880

initial_state.libc.buf_symbolic_bytes = INPUT_LENGTH + 1
for byte in flag.chop(8): # initialize all array items
    initial_state.add_constraints(byte != '\x00') # null
    initial_state.add_constraints(byte >= ' ') # '\x20'
    initial_state.add_constraints(byte <= '~') # '\x7e'
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
    print("[*] found: flag = " + found.state.se.any_str(flag))
else:
    print("[!] not found")
"""

    source_code = source_code.replace("__BIN__", BIN)
    # source_code = source_code.replace("P_HOOK", P_HOOK)
    source_code = source_code.replace("SIM_START", SIM_START)
    source_code = source_code.replace("FLAG_PREFIX_CODE", FLAG_PREFIX_CODE)
    source_code = source_code.replace("TARGET_ADDR", TARGET_ADDR)
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

if __name__ == "__main__":
    main()

"""memo
* class Basic Block/Procedure hasTag(), getTagCount() not works
"""