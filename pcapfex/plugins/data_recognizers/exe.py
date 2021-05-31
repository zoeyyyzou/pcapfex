# -*- coding: utf8 -*-
__author__ = 'Viktor Winkelmann'

import sys

sys.path.append('../../..')
from pcapfex.core.Plugins.DataRecognizer import *


def getClassReference():
    return EXEFile


class EXEFile(DataRecognizer):
    signatures = [(b'MZ.{254}PE', None)]
    fileEnding = "exe"
    dataType = "Windows PE file"
    dataCategory = DataCategory.EXECUTABLE
