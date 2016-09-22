import subprocess

# ref. : https://github.com/phracker/HopperScripts/blob/9468cdadb2c139d474662ae82716a5098e7350e4/Annotation%20Export.py

doc = Document.getCurrentDocument()

BIN = "~/bin/ping-mic-tools/reversing/D-demangle/demangle"


nsegs = doc.getSegmentCount()
for segnum in range(nsegs):
    doc.log('processing segment %d/%d' % (segnum+1,nsegs))
    seg = doc.getSegment(segnum)
    print(seg.getName())
    # if not seg.getName() == "TEXT":
    #     continue
    old_labels = seg.getLabelsList()

    p = subprocess.Popen(BIN, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(input='\n'.join(old_labels))
    # print(out)
    new_labels = out[:-1].split('\n')

    len_new_labels = len(new_labels)
    if len_new_labels == 0:
        break
    print("[*] demangling section %s (total %d labels)" % (seg.getName(), len_new_labels))
    for i in range(len_new_labels):
        label = new_labels[i]
        addr = doc.getAddressForName(old_labels[i])
        if old_labels[i] != new_labels[i] and seg.getTypeAtAddress(addr) == Segment.TYPE_PROCEDURE:
            print("(%d/%d) renameing %s at 0x%x" % (i+1, len_new_labels, label, addr))
            doc.setNameAtAddress(addr, label.replace(' ', '_'))
            # seg.markAsProcedure(addr)

doc.refreshView()
print("[*] Demangle Finished")