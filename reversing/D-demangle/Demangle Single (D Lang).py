import subprocess
import signal
import threading

# ref. : https://github.com/phracker/HopperScripts/blob/9468cdadb2c139d474662ae82716a5098e7350e4/Annotation%20Export.py

doc = Document.getCurrentDocument()
seg = doc.getCurrentSegment()

BIN = "~/bin/ping-mic-tools/reversing/D-demangle/demangle"

old_name = doc.getHighlightedWord()
p = subprocess.Popen(BIN, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate(input=old_name)
new_name = out.replace('\n', '')
addr = doc.getAddressForName(old_name)

if old_name != new_name and seg.getTypeAtAddress(addr) == Segment.TYPE_PROCEDURE:
    print("renameing %s->%s at 0x%x" % (old_name, new_name, addr))
    doc.setNameAtAddress(addr, new_name)

doc.refreshView()
print("[*] Demangle Finished")