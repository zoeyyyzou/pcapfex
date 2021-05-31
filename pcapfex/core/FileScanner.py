from .Streams.PacketStream import PacketStream
from .Streams.StreamBuilder import StreamBuilder, PcapIter
from .Plugins.PluginManager import PluginManager
from .Files.FileObject import FileObject


class FileScanner:
    def __init__(self, entropy=False, fileObjectCallback=None):
        self.pm = PluginManager()
        self.useEntropy = entropy
        self.streamBuilder = StreamBuilder(onStreamCallback=self.dealStreamCallback)
        self.fileObjectCallback = fileObjectCallback

    def addPacket(self, packetNumber: int, ts: float, rawPacket: bytes):
        self.streamBuilder.addPacket(packetNumber, ts, rawPacket)

    def done(self):
        self.streamBuilder.done()

    def dealStreamCallback(self, stream: PacketStream):
        (stream, result) = self._findFiles(stream)
        if self.fileObjectCallback:
            for fileObj in result:
                self.fileObjectCallback(fileObj)

    def _findFiles(self, stream: PacketStream):
        files = []
        payloads = []
        streamdata = stream.getAllBytes()
        streamPorts = (stream.ipSrc, stream.ipDst)

        for protocol in self.pm.getProtocolsByHeuristics(streamPorts):
            payloads = self.pm.protocolDissectors[protocol].parseData(streamdata)

            if payloads is not None:
                stream.protocol = self.pm.protocolDissectors[protocol].protocolName
                break

        for encPayload in payloads:
            for decoder in self.pm.decoders:
                payload = self.pm.decoders[decoder].decodeData(encPayload)
                if payload is None:
                    continue

                for datarecognizer in self.pm.dataRecognizers:
                    for occ in self.pm.dataRecognizers[datarecognizer].findAllOccurences(payload):
                        file = FileObject(payload[occ[0]:occ[1]])
                        file.source = stream.ipSrc
                        file.destination = stream.ipDst
                        file.firstPacketNumber = stream.firstPacketNumber
                        file.pcapFile = stream.pcapFile
                        file.fileEnding = self.pm.dataRecognizers[datarecognizer].fileEnding
                        file.type = self.pm.dataRecognizers[datarecognizer].dataCategory
                        if stream.tsFirstPacket:
                            file.timestamp = stream.tsFirstPacket
                        files.append(file)

                if self.useEntropy:
                    type = self.pm.entropyClassifier.classify(payload)
                    file = FileObject(payload)
                    file.source = stream.ipSrc
                    file.destination = stream.ipDst
                    file.type = type
                    if stream.tsFirstPacket:
                        file.timestamp = stream.tsFirstPacket
                    files.append(file)

        return stream, files
