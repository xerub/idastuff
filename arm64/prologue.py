#  Fix clang function prologues
#  WARNING: this WILL patch bytes in the database
#
#  Copyright (c) 2015 xerub
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

# convert this:
#__text:0000000100004730 FA 67 BB A9                 STP             X26, X25, [SP,#-0x50]!
#__text:0000000100004734 F8 5F 01 A9                 STP             X24, X23, [SP,#0x10]
#__text:0000000100004738 F6 57 02 A9                 STP             X22, X21, [SP,#0x20]
#__text:000000010000473C F4 4F 03 A9                 STP             X20, X19, [SP,#0x30]
#__text:0000000100004740 FD 7B 04 A9                 STP             X29, X30, [SP,#0x40]
#__text:0000000100004744 FD 03 01 91                 ADD             X29, SP, #0x40
#
# to this:
#__text:0000000100004730 FD 7B BF A9                 STP             X29, X30, [SP,#-0x10]!
#__text:0000000100004734 FD 03 00 91                 MOV             X29, SP
#__text:0000000100004738 F4 4F BF A9                 STP             X20, X19, [SP,#-0x10]!
#__text:000000010000473C F6 57 BF A9                 STP             X22, X21, [SP,#-0x10]!
#__text:0000000100004740 F8 5F BF A9                 STP             X24, X23, [SP,#-0x10]!
#__text:0000000100004744 FA 67 BF A9                 STP             X26, X25, [SP,#-0x10]!

import idaapi
import idc

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

def doit(seg_start):
	seg_end = SegEnd(seg_start)

	ea = seg_start
	while ea < seg_end:
		d = Dword(ea)
		if (d & 0xFFC003FF) == 0x910003FD:
			# add x29, sp, #imm
			delta = (d >> 10) & 0xFFF
			if delta != 0 and (delta & 0xF) == 0:
				prev_ea = ea - 4
				prev_imm = delta + 0x10
				insns = []

				while prev_ea >= seg_start:
					prev = Dword(prev_ea)

					imm = (prev >> 15) & 0x7F
					if imm > 63:
						imm -= 128
					imm *= 8

					if (prev & 0xFFC003E0) == 0xA90003E0 and prev_imm == imm + 0x10 and imm > 0:
						# stp x, y, [sp,#imm]
						insns.append([prev & 0x7c1f, imm, False])
					elif (prev & 0xFFC003E0) == 0xA98003E0 and delta + imm + 0x10 == 0:
						# stp x, y, [sp,#-imm]!
						insns.append([prev & 0x7c1f, imm, True])
						break
					else:
						break

					prev_imm = imm
					prev_ea -= 4

				if len(insns) != 0 and insns[-1][2] == True and insns[0][0] == 0x781D:
					print "fixing BP frame at %x: 0x%x" % (prev_ea, delta)
					startf = prev_ea

					first = True
					for elt in insns:
						PatchDword(prev_ea, 0xA9BF03E0 | elt[0])
						if first:
							first = False
							prev_ea += 4
							PatchDword(prev_ea, 0x910003FD)
						prev_ea += 4

					DelFunction(startf)
					MakeFunction(startf, BADADDR)

		ea += 4

code = get_segments_of_type(CODE)
if len(code) > 0:
	doit(code[0])
