import dpkt
from pcapfex.core.FileScanner import FileScanner
from pcapfex.core.Streams.StreamBuilder import PcapIter
import os
import csv

if __name__ == '__main__':
    pcapfile = "custom.pcap"
    f = open("file.csv", "w")
    fileWriter = csv.writer(f)
    fileWriter.writerow(["src", "dst", "type", "size", "ts", "md5", "sha1", "sha256"])
    fileScanner = FileScanner(
        fileObjectCallback=lambda fileObj:
        fileWriter.writerow([fileObj.source, fileObj.destination, fileObj.fileEnding, fileObj.size,
                             fileObj.timestamp, fileObj.md5, fileObj.sha1, fileObj.sha256]))
    with open(pcapfile, 'rb') as pcap:
        dpkt.pcap.Reader.__iter__ = PcapIter
        packets = dpkt.pcap.Reader(pcap)
        capLenError = False

        fileSize = float(os.path.getsize(pcapfile))
        progress = -1

        print('  Size of file %s: %.2f mb' % (pcapfile, fileSize / 1000000))
        for packetNumber, (ts, complete, buf) in enumerate(packets, 1):
            if not complete:
                continue
            ethPacket = dpkt.ethernet.Ethernet(buf)
            fileScanner.addPacket(packetNumber, ts, ethPacket)
        fileScanner.done()
        f.close()
