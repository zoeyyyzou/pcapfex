# -*- coding: utf8 -*-
import hashlib

__author__ = 'Viktor Winkelmann'

import datetime


class FileObject(object):
    def __init__(self, data):
        self.data = data
        self.md5 = hashlib.md5(data).hexdigest()
        self.sha1 = hashlib.sha1(data).hexdigest()
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.size = len(data)
        self._name = None
        self.source = 'unknown'
        self.destination = 'unknown'
        self.pcapFile = 'unknown'
        self._timestamp = 'unknown'
        self.type = 'unknown'
        self.fileEnding = 'unknown'
        self.firstPacketNumber = None

        # set data to None to release memory
        self.data = None

    @property
    def name(self):
        if self._name:
            return self._name
        else:
            return self.type.split('/')[-1]

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        self._timestamp = value
        #
        # try:
        #     self._timestamp = str(datetime.datetime.utcfromtimestamp(value)).replace(':', '-')
        # except ValueError:
        #     self._timestamp = value

    def __repr__(self):
        return f"FileObject(md5={self.md5}, sha1={self.sha1}, sha256={self.sha256}, size={self.size}, name={self._name}," \
               f"src={self.source}, dst={self.destination}, pcapFile={self.pcapFile}, ts={self._timestamp}, " \
               f"type={self.type}, fileEnding={self.fileEnding}, firstPacketNumber={self.firstPacketNumber})"