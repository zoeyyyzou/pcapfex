# -*- coding: utf8 -*-
__author__ = 'Viktor Winkelmann'

import sys

sys.path.append('../../..')
from pcapfex.core.Plugins.DataRecognizer import *


def getClassReference():
    return AviFile


class AviFile(DataRecognizer):
    signatures = [(b'RIFF.{4}AVI LIST', None)]
    fileEnding = "avi"
    dataType = "AVI file"
    dataCategory = DataCategory.VIDEO