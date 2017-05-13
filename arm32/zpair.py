#  Fix Thumb-2 movw/movt offsets for zero-based binaries (no ADD PC)
#
#  Copyright (c) 2017 xerub
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import idaapi
import idc

DISTANCE = 4

CODE = 2
DATA = 3

def get_segments_of_type(attr):
    segs = []
    seg = FirstSeg()
    while seg != BADADDR:
        if GetSegmentAttr(seg, SEGATTR_TYPE) == attr:
            segs.append(seg)
        seg = NextSeg(seg)
    return segs

def doit(seg_start, low, high):
    seg_end = SegEnd(seg_start)

    for funcea in Functions(seg_start, seg_end):
        functionName = GetFunctionName(funcea)
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                #print functionName, ":", hex(head), ":", GetDisasm(head)
                i1 = Dword(head)
                if (i1 & 0x8000FBF0) == 0xF240:
                    reg = (i1 >> 24) & 0xF
                    tail = head + 4
                    while tail <= head + 4 + DISTANCE:
                        i2 = Dword(tail)
                        if (i2 & 0x8000FBF0) == 0xF2C0 and (i2 >> 24) & 0xF == reg:
                            lo = i1 & 0xFFFF
                            hi = (i1 >> 16) & 0xFFFF
                            val1 = ((lo & 0xF) << 12) | ((lo & 0x0400) << 1) | ((hi & 0x7000) >> 4) | (hi & 0xFF)
                            lo = i2 & 0xFFFF
                            hi = (i2 >> 16) & 0xFFFF
                            val2 = ((lo & 0xF) << 12) | ((lo & 0x0400) << 1) | ((hi & 0x7000) >> 4) | (hi & 0xFF)
                            val = val1 | (val2 << 16)
                            if val >= low and val <= high:
                                if tail > head + 4:
                                    #print "0x%x-0x%x    R%d = 0x%x" % (head, tail, reg, val)
                                    OpOffEx(head, 1, REF_LOW16, val, 0, 0)
                                    OpOffEx(tail, 1, REF_HIGH16, val, 0, 0)
                                else:
                                    #print "0x%x+0x%x    R%d = 0x%x" % (head, tail, reg, val)
                                    OpOff(head, 1, 0)
                            break
                        if ((i2 >> 8) & 0xF8) > 0xE0:
                            tail = tail + 2
                        tail = tail + 2


code = get_segments_of_type(CODE)
if len(code) > 0:
    doit(code[0], GetLongPrm(INF_LOW_OFF), GetLongPrm(INF_HIGH_OFF))
