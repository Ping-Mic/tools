import subprocess
import signal
import threading
import re

# ref. : https://github.com/phracker/HopperScripts/blob/9468cdadb2c139d474662ae82716a5098e7350e4/Annotation%20Export.py

doc = Document.getCurrentDocument()
doc.destroyTag(doc.buildTag("DanglingFunctions"))

BIN = ""

nsegs = doc.getSegmentCount()
for segnum in range(nsegs):
    seg = doc.getSegment(segnum)
    doc.log('processing segment %d/%d: %s' % (segnum+1,nsegs, seg.getName()))
    labels = seg.getLabelsList()

    # p = subprocess.Popen(BIN, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # out, err = p.communicate(input='\n'.join(old_labels))

    len_labels = len(labels)
    print("[*] found %d labels in %s" % (len_labels, seg.getName()))

    for i in range(len_labels):
        label = labels[i]
        addr = doc.getAddressForName(label)
        if not seg.getTypeAtAddress(addr) == Segment.TYPE_PROCEDURE:
            continue
        m = re.search("(type|libc|@|core|std|container|exception|pop|push|info|tmp|length|trace|scan|array|sync|stat|find|collect|dummy|assert|test|pool|shared|object|init|bits|D2gc|D2rt|start|fini|_do_global|_dmd_)", label, re.I)
        if not m == None:
            continue
        refs = seg.getReferencesOfAddress(addr)
        if len(refs) == 0:
            # print("No one calls %s at 0x%x" % (label, addr))
            tag = doc.buildTag("DanglingFunctions")
            doc.addTagAtAddress(tag, addr)

doc.refreshView()
print("[*] Finished Finding Dangling Functions")