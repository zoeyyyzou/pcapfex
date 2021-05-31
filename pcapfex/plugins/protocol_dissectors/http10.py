# -*- coding: utf8 -*-
__author__ = 'Viktor Winkelmann'

import sys

sys.path.append('../../..')

from pcapfex.plugins.protocol_dissectors.http11 import HTTP11
from io import BytesIO
from contextlib import closing


def getClassReference():
    return HTTP10


# Parses HTTP Requests / Responses according to http://tools.ietf.org/html/rfc1945
class HTTP10(HTTP11):
    basePriority = 45

    protocolName = "HTTP 1.0"

    @classmethod
    def parseData(cls, data):
        with closing(BytesIO(data)) as data:
            # check start line for HTTP 1.0 tag
            line = data.readline()
            if b'HTTP/1.0' not in line:
                return None

            # classify as Request or Response
            if line.startswith(b'HTTP'):
                return cls.getResponsePayload(data)
            else:
                return cls.getRequestPayload(data)
