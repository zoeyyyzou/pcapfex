# -*- coding: utf8 -*-
__author__ = 'Viktor Winkelmann'

import sys

sys.path.append('../../..')
from pcapfex.core.Plugins.DataRecognizer import *


def getClassReference():
    return MP3File


class MP3File(DataRecognizer):
    signatures = [(b'ID3', None)]
    fileEnding = "mp3"
    dataType = "MP3 file"
    dataCategory = DataCategory.AUDIO