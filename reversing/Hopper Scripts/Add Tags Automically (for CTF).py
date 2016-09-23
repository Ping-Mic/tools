import subprocess
import signal
import threading
import re

# ref. : https://github.com/phracker/HopperScripts/blob/9468cdadb2c139d474662ae82716a5098e7350e4/Annotation%20Export.py

doc = Document.getCurrentDocument()

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
        m = re.search("(flags|libc)", label)
        if not m == None:
            # print("[*] dismissed %s" % label)
            continue
        m = re.findall("(flag|enc|dec|encrypt|decrypt|encode|decode|main)", label)
        if not m == None:
            for tag_name in m:
                # print("(%d/%d) Tagging #%s to %s at 0x%x" % (i+1, len_labels, tag_name, label, addr))
                tag = doc.buildTag(tag_name)
                doc.addTagAtAddress(tag, addr)

doc.refreshView()
print("[*] Added Tags Automically")