#  AArch64 mov simplifier IDA7 plugin
#
#  Copyright (c) 2015, 2017 xerub
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
#
# based on Rolf Rolles x86 deobfuscator http://www.msreverseengineering.com

import idaapi
import idc

ARM64_MOVE_I = idaapi.ARM_mov

def dump_cmd(insn):
	print "cs = %lx" % insn.cs
	print "ip = %lx" % insn.ip
	print "ea = %lx" % insn.ea
	print "itype = %lx" % insn.itype
	print "size = %lx" % insn.size
	print "auxpref = %lx" % insn.auxpref
	print "segpref = %x" % ord(insn.segpref)
	print "insnpref = %x" % ord(insn.insnpref)
	print "flags = %lx" % insn.flags

def dump_op(op):
	print "n = %lx" % op.n
	print "type = %lx" % op.type
	print "offb = %lx" % op.offb
	print "offo = %lx" % op.offo
	print "flags = %lx" % op.flags
	print "dtyp = %lx" % op.dtype
	print "reg = %lx" % op.reg
	print "phrase = %lx" % op.phrase
	print "value = %lx" % op.value
	print "addr = %lx" % op.addr
	print "specval = %lx" % op.specval
	print "specflag1 = %lx" % op.specflag1
	print "specflag2 = %lx" % op.specflag2
	print "specflag3 = %lx" % op.specflag3
	print "specflag4 = %lx" % op.specflag4

def HighestSetBit(N, imm):
	i = N - 1
	while i >= 0:
		if imm & (1 << i):
			return i
		i -= 1
	return -1

def ZeroExtendOnes(M, N):				# zero extend M ones to N width
	return (1 << M) - 1

def RORZeroExtendOnes(M, N, R):
	val = ZeroExtendOnes(M, N)
	return ((val >> R) & ((1 << (N - R)) - 1)) | ((val & ((1 << R) - 1)) << (N - R))

def Replicate(val, bits):
	ret = val
	shift = bits
	while shift < 64:				# XXX actually, it is either 32 or 64
		ret |= (val << shift)
		shift += bits
	return ret

def DecodeBitMasks(immN, imms, immr, immediate):
	len = HighestSetBit(7, (immN << 6) | (~imms & 0x3F))
	if len < 1:
		return None
	levels = ZeroExtendOnes(len, 6)
	if immediate and (imms & levels) == levels:
		return None
	S = imms & levels
	R = immr & levels
	esize = 1 << len
	return Replicate(RORZeroExtendOnes(S + 1, esize, R), esize)

def DecodeMov(opcode, total, first):
	# opc
	o = (opcode >> 29) & 3
	# constant
	k = (opcode >> 23) & 0x3F

	if k == 0x24 and o == 1:			# MOV (bitmask imm) <=> ORR (immediate)
		# sf
		s = (opcode >> 31) & 1
		# N
		N = (opcode >> 22) & 1
		if s == 0 and N != 0:
			return None
		# rn
		rn = (opcode >> 5) & 0x1F
		if rn == 31:
			imms = (opcode >> 10) & 0x3F
			immr = (opcode >> 16) & 0x3F
			return DecodeBitMasks(N, imms, immr, True)
	elif k == 0x25:					# MOVN/MOVZ/MOVK
		# sf
		s = (opcode >> 31) & 1
		# hw
		h = (opcode >> 21) & 3
		# imm16
		i = (opcode >> 5) & 0xFFFF
		if s == 0 and h > 1:
			return None
		h *= 16
		i <<= h
		if o == 0:				# MOVN
			return ~i
		elif o == 2:				# MOVZ
			return i
		elif o == 3 and not first:		# MOVK
			return (total & ~(0xFFFF << h)) | i
	elif (k | 1) == 0x23 and not first:		# ADD (immediate)
		# shift
		h = (opcode >> 22) & 3
		if h > 1:
			return None
		# rn
		rd = opcode & 0x1F
		rn = (opcode >> 5) & 0x1F
		if rd != rn:
			return None
		# imm12
		i = (opcode >> 10) & 0xFFF
		h *= 12
		i <<= h
		if o & 2:				# SUB
			return total - i
		else:					# ADD
			return total + i

	return None

def check_mov_sequence(ea):
	oldea = ea
	reg = -1
	total = 0
	is64 = False
	while idaapi.getseg(ea).use64():
		d = idaapi.get_dword(ea)
		# reg
		r = d & 0x1F
		if reg >= 0 and reg != r:
			break
		newval = DecodeMov(d, total, reg < 0)
		if newval is None:
			break
		if reg >= 0 and idaapi.get_first_fcref_to(ea) != idaapi.BADADDR:
			break
		if (d >> 31) & 1:
			is64 = True
		total = newval
		reg = r
		ea += 4
	return ea - oldea, reg, is64, total

def is_my_mov(insn):
	if insn.itype == ARM64_MOVE_I and insn.flags == idaapi.INSN_MACRO and insn.size > 4:
		return True
	return False

class simpA64Hook(idaapi.IDP_Hooks):
	def __init__(self):
		idaapi.IDP_Hooks.__init__(self)
		self.n = idaapi.netnode("$ A64 Simplifier",0,1)

	def ev_ana_insn(self, insn):
		len, reg, is64, imm = check_mov_sequence(insn.ea)
		if len > 4:
			#print "0x%x: MOV/MOVK %c%d, #0x%x" % (insn.ea, 'X' if is64 else 'W', reg, imm)
			#dump_cmd(insn)
			#dump_op(insn.Op1)
			#dump_op(insn.Op2)
			insn.itype = ARM64_MOVE_I
			insn.segpref = 14 # ARM Condition = ALways
			insn.Op1.type = idaapi.o_reg
			insn.Op1.dtype = idaapi.dt_qword if is64 else idaapi.dt_dword
			insn.Op1.reg = reg + 129 # Use Wn/Xn registers instead of Rn
			insn.Op2.type = idaapi.o_imm
			insn.Op2.dtype = idaapi.dt_qword if is64 else idaapi.dt_dword
			insn.Op2.value = imm
			insn.flags = idaapi.INSN_MACRO
			insn.size = len
			return True
		return False

	def ev_out_mnem(self, ctx): # totally optional
		if is_my_mov(ctx.insn):
			ctx.out_custom_mnem("MOVE", idaapi.get_inf_structure().indent)
			return 1
		return 0

class simpa64_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_PROC
	comment = "Simplifier"
	wanted_hotkey = "Alt-Z"
	help = "Runs transparently"
	wanted_name = "simpa64"
	hook = None
	enabled = 1

	def init(self):
		self.hook = None
		if idaapi.ph_get_id() != idaapi.PLFM_ARM or idaapi.BADADDR <= 0xFFFFFFFF:
			return idaapi.PLUGIN_SKIP

		self.hook = simpA64Hook()
		flag = self.hook.n.altval(0)
		if flag:
			self.enabled = flag - 1
		print "%s is %sabled" % (self.wanted_name, "en" if self.enabled else "dis")
		if self.enabled:
			self.hook.hook()
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		print "%sabling %s" % ("dis" if self.enabled else "en", self.wanted_name)
		if self.enabled:
			self.hook.unhook()
		else:
			self.hook.hook()
		self.enabled = self.enabled ^ 1
		self.hook.n.altset(0, self.enabled + 1)
		idc.Refresh()

	def term(self):
		if self.hook:
			self.hook.unhook()

def PLUGIN_ENTRY():
	return simpa64_t()
