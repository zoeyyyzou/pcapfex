# -*- coding: utf8 -*-
__author__ = 'Viktor Winkelmann'

from .TCPStream import *
from .UDPStream import *
import socket
import dpkt


# Workaround to get access to pcap packet record capture length field
def PcapIter(self):
    while True:
        buf = self._Reader__f.read(dpkt.pcap.PktHdr.__hdr_len__)
        if not buf:
            break
        else:
            try:
                hdr = self._Reader__ph(buf)
            except:
                print(' > Finish with error')
                break
        buf = self._Reader__f.read(hdr.caplen)
        yield hdr.tv_sec + (hdr.tv_usec / 1000000.0), hdr.caplen == hdr.len, buf


class StreamBuilder:
    def __init__(self, udpTimeout=120, verifyChecksums=True, onStreamCallback=None):
        # self.tcpStreams = []
        # self.udpStreams = []
        self.openTcpStreams = []
        self.openUdpStreams = []
        self.UDP_TIMEOUT = udpTimeout
        self.VERIFY_CHECKSUMS = verifyChecksums  # Might need to be disabled if Checksum Offloading
        self.onStreamCallback = onStreamCallback

    # Verify Layer3/4 Checksums, see dpkt/ip.py __str__ method
    @classmethod
    def __verify_checksums(cls, ippacket):
        if dpkt.in_cksum(ippacket.pack_hdr() + bytes(ippacket.opts)) != 0:
            return False

        if (ippacket.off & (dpkt.ip.IP_MF | dpkt.ip.IP_OFFMASK)) != 0:
            return True

        p = bytes(ippacket.data)
        s = dpkt.struct.pack('>4s4sxBH', ippacket.src, ippacket.dst,
                             ippacket.p, len(p))
        s = dpkt.in_cksum_add(0, s)
        s = dpkt.in_cksum_add(s, p)
        return dpkt.in_cksum_done(s) == 0

    def addPacket(self, packetNumber: int, ts: float, eth: dpkt.ethernet.Ethernet):
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            return

        ip = eth.data

        if self.VERIFY_CHECKSUMS and not self.__verify_checksums(ip):
            return

        packet = ip.data
        if ip.p == dpkt.ip.IP_PROTO_TCP:

            # get last matching stream occurrence for packet
            tcpStream = self.__findLastStreamOccurenceIn(self.openTcpStreams,
                                                         ip.src, packet.sport,
                                                         ip.dst, packet.dport)

            # no matching open stream found, create new stream if syn flag is set
            if tcpStream is None:
                if not packet.flags & dpkt.tcp.TH_SYN:
                    return

                tcpStream = TCPStream(socket.inet_ntoa(ip.src), packet.sport,
                                      socket.inet_ntoa(ip.dst), packet.dport, packetNumber, "")
                self.openTcpStreams.append(tcpStream)

            # add packet to currently referenced stream
            tcpStream.addPacket(packet, ts)

            # check if stream needs to be closed due to fin flag and verify stream
            if packet.flags & dpkt.tcp.TH_FIN:
                if tcpStream.isValid():
                    tcpStream.closed = True
                    if self.onStreamCallback:
                        self.onStreamCallback(tcpStream)
                self.openTcpStreams.remove(tcpStream)

        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            if len(packet.data) == 0:
                return

            # get last matching stream occurrence for packet
            udpStream = self.__findLastStreamOccurenceIn(self.openUdpStreams,
                                                         ip.src, packet.sport,
                                                         ip.dst, packet.dport)

            # no matching open stream found, create new stream
            if udpStream is None or udpStream.closed:
                udpStream = UDPStream(socket.inet_ntoa(ip.src), packet.sport,
                                      socket.inet_ntoa(ip.dst), packet.dport, packetNumber, "")
                self.openUdpStreams.append(udpStream)

            else:
                lastSeen = udpStream.tsLastPacket

                # timeout happened, close old and create new stream
                if lastSeen and (ts - lastSeen) > self.UDP_TIMEOUT:
                    udpStream.closed = True
                    self.openUdpStreams.remove(udpStream)
                    if self.onStreamCallback:
                        self.onStreamCallback(udpStream)

                    udpStream = UDPStream(socket.inet_ntoa(ip.src), packet.sport,
                                          socket.inet_ntoa(ip.dst), packet.dport, packetNumber, "")
                    self.openUdpStreams.append(udpStream)

            # add packet to currently referenced udpStream
            udpStream.addPacket(packet, ts)
        else:
            return

    def done(self):
        pass
        # self.tcpStreams += [s for s in self.openTcpStreams if s.isValid()]
        # self.udpStreams += self.openUdpStreams

    @staticmethod
    def __findLastStreamOccurenceIn(targetList, ipSrc, portSrc, ipDst, portDst):
        for stream in targetList[::-1]:
            if stream.portSrc == portSrc \
                    and stream.portDst == portDst \
                    and stream.ipSrc == socket.inet_ntoa(ipSrc) \
                    and stream.ipDst == socket.inet_ntoa(ipDst):
                return stream

        return None
