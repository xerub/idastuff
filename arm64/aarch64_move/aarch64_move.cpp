/*
 *  AArch64 MOV simplifier IDA plugin
 *
 *  Copyright (c) 2016-2017 xerub
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License version 
 * 2 as published by the Free Software Foundation. 
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * based on Rolf Rolles x86 deobfuscator http://www.msreverseengineering.com
 * Augmenting IDA UI with your own actions: http://www.hexblog.com/?p=886
 */


#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>
#include <segregs.hpp>

#define MAGIC_ACTIVATED   2
#define MAGIC_DEACTIVATED 1

#define ARM64_MOVE_I ARM_mov

inline bool is_arm64_ea(ea_t ea)
{
	segment_t *seg = getseg(ea);
	return seg != NULL && seg->use64();
}

static int HighestSetBit(int N, uint32_t imm)
{
	int i;
	for (i = N - 1; i >= 0; i--) {
		if (imm & (1 << i)) {
			return i;
		}
	}
	return -1;
}

static uint64_t ZeroExtendOnes(unsigned M, unsigned N)	// zero extend M ones to N width
{
	(void)N;
	return ((uint64_t)1 << M) - 1;
}

static uint64_t RORZeroExtendOnes(unsigned M, unsigned N, unsigned R)
{
	uint64_t val = ZeroExtendOnes(M, N);
	if (R == 0) {
		return val;
	}
	return ((val >> R) & (((uint64_t)1 << (N - R)) - 1)) | ((val & (((uint64_t)1 << R) - 1)) << (N - R));
}

static uint64_t Replicate(uint64_t val, unsigned bits)
{
	uint64_t ret = val;
	unsigned shift;
	for (shift = bits; shift < 64; shift += bits) {	// XXX actually, it is either 32 or 64
		ret |= (val << shift);
	}
	return ret;
}

static int DecodeBitMasks(unsigned immN, unsigned imms, unsigned immr, int immediate, uint64_t *newval)
{
	unsigned levels, S, R, esize;
	int len = HighestSetBit(7, (immN << 6) | (~imms & 0x3F));
	if (len < 1) {
		return -1;
	}
	levels = ZeroExtendOnes(len, 6);
	if (immediate && (imms & levels) == levels) {
		return -1;
	}
	S = imms & levels;
	R = immr & levels;
	esize = 1 << len;
	*newval = Replicate(RORZeroExtendOnes(S + 1, esize, R), esize);
	return 0;
}

static int DecodeMov(uint32_t opcode, uint64_t total, uint64_t *newval, uint64_t inmask, uint64_t *outmask)
{
	unsigned s = (opcode >> 31) & 1;
	unsigned o = (opcode >> 29) & 3;
	unsigned k = (opcode >> 23) & 0x3F;
	unsigned rn, rd;
	uint64_t i;

	if (k == 0x24 && o == 1) {			// MOV (bitmask imm) <=> ORR (immediate)
		unsigned N = (opcode >> 22) & 1;
		if (s == 0 && N != 0) {
			return -1;
		}
		rn = (opcode >> 5) & 0x1F;
		if (rn == 31) {
			unsigned imms = (opcode >> 10) & 0x3F;
			unsigned immr = (opcode >> 16) & 0x3F;
			*outmask = -1ULL;
			return DecodeBitMasks(N, imms, immr, 1, newval);
		}
	} else if (k == 0x25) {				// MOVN/MOVZ/MOVK
		unsigned h = (opcode >> 21) & 3;
		if (s == 0 && h > 1) {
			return -1;
		}
		i = (opcode >> 5) & 0xFFFF;
		h *= 16;
		i <<= h;
		if (o == 0) {				// MOVN
			*outmask = -1ULL;
			*newval = ~i;
			if (s == 0) {
				*newval &= 0xFFFFFFFF;
			}
			return 0;
		} else if (o == 2) {			// MOVZ
			*outmask = -1ULL;
			*newval = i;
			return 0;
		} else if (o == 3) {			// MOVK
			uint64_t mask = (uint64_t)0xFFFF << h;
			if (s == 0) {
				inmask |= ~0xFFFFFFFFULL;
			}
			*outmask = inmask | mask;
			*newval = (total & ~mask) | i;
			return 0;
		}
	} else if ((k | 1) == 0x23) {			// ADD (immediate)
		unsigned h = (opcode >> 22) & 3;
		if (h > 1) {
			return -1;
		}
		if (inmask != -1ULL && (inmask != 0xFFFFFFFF || s)) {
			return -1;
		}
		rd = opcode & 0x1F;
		rn = (opcode >> 5) & 0x1F;
		if (rd != rn) {
			return -1;
		}
		i = (opcode >> 10) & 0xFFF;
		h *= 12;
		i <<= h;
		if (o & 2) {				// SUB
			total -= i;
		} else {				// ADD
			total += i;
		}
		if (s == 0) {
			total &= 0xFFFFFFFF;
		}
		*outmask = -1ULL;
		*newval = total;
		return 0;
	}

	return -1;
}

static size_t check_mov_sequence(ea_t ea, int *_reg, int *_is64, uint64_t *_imm)
{
	ea_t oldea;
	int reg = -1;
	int is64 = 0;
	uint64_t total = 0;
	uint64_t inmask = 0;
	for (oldea = ea; is_arm64_ea(ea); ea += 4) {
		uint64_t newval = 0;
		uint64_t outmask = 0;
		uint32_t d = get_dword(ea);
		int r = d & 0x1F;
		if (reg >= 0 && reg != r) {
			break;
		}
		if (DecodeMov(d, total, &newval, inmask, &outmask) < 0) {
			break;
		}
		if (reg >= 0 && get_first_fcref_to(ea) != BADADDR) {
			break;
		}
		if ((d >> 31) & 1) {
			is64 = 1;
		}
		total = newval;
		inmask = outmask;
		reg = r;
	}
	if (inmask != -1ULL) {
		return 0;
	}
	*_reg = reg;
	*_is64 = is64;
	*_imm = total;
	return ea - oldea;
}

static size_t ana(insn_t *insn)
{
	uint64_t imm;
	int reg, is64;
	size_t sz = check_mov_sequence(insn->ea, &reg, &is64, &imm);
	if (sz > 4) {
		insn->itype = ARM64_MOVE_I;
		insn->segpref = 14;			// ARM Condition = ALways
		insn->Op1.type = o_reg;
		insn->Op1.reg = reg + 129;		// Use Wn/Xn registers instead of Rn
		insn->Op1.dtype = is64 ? dt_qword : dt_dword;
		insn->Op2.type = o_imm;
		insn->Op2.value = imm;
		insn->Op2.dtype = is64 ? dt_qword : dt_dword;
		insn->flags = INSN_MACRO;
		return sz;
	}
	return 0;
}

static long idaapi aarch64_extension_callback(void * user_data, int event_id, va_list va)
{
	switch (event_id) {
		case processor_t::ev_ana_insn: {
			insn_t *insn = va_arg(va, insn_t *);
			size_t length = ana(insn);
			if (length) {
				insn->size = (uint16)length;
				return length;
			}
		}
		break;
		case processor_t::ev_out_mnem: { /* totally optional */
			outctx_t *ctx = va_arg(va, outctx_t *);
			const insn_t *insn = &ctx->insn;
			if (0) {
				unsigned i;
				printf("cs:ip = 0x%llx:0x%llx\n", insn->cs, insn->ip);
				printf("ea = 0x%llx\n", insn->ea);
				printf("itype = 0x%x\n", insn->itype);
				printf("size = 0x%x\n", insn->size);
				printf("auxpref = 0x%x\n", insn->auxpref);
				printf("segpref = 0x%x\n", insn->segpref);
				printf("insnpref = 0x%x\n", insn->insnpref);
				printf("flags = 0x%x\n", insn->flags);
				for (i = 0; i < UA_MAXOP; i++) {
					printf("\tn = 0x%x\n", insn->ops[i].n);
					printf("\ttype = 0x%x\n", insn->ops[i].type);
					printf("\toffb/offo = 0x%x/0x%x\n", insn->ops[i].offb, insn->ops[i].offo);
					printf("\tflags = 0x%x\n", insn->ops[i].flags);
					printf("\tdtyp = 0x%x\n", insn->ops[i].dtype);
					printf("\treg = 0x%x\n", insn->ops[i].reg);
					printf("\tvalue = 0x%llx\n", insn->ops[i].value);
					printf("\taddr = 0x%llx\n", insn->ops[i].addr);
					printf("\tspecval = 0x%llx\n", insn->ops[i].specval);
					printf("\tspecflag[1..4] = 0x%x, 0x%x, 0x%x, 0x%x\n", insn->ops[i].specflag1, insn->ops[i].specflag2, insn->ops[i].specflag3, insn->ops[i].specflag4);
				}
				printf("---\n");
			}
			if (insn->itype == ARM64_MOVE_I && insn->flags == INSN_MACRO && insn->size > 4) {
				ctx->out_custom_mnem("MOVE", inf.indent);
				return 2;
			}
		}
		break;
	}
	return 0;
}

static bool enabled = false;
static netnode aarch64_node;
static const char node_name[] = "$ A64 Simplifier";

int idaapi init(void)
{
	if (ph.id != PLFM_ARM) return PLUGIN_SKIP;
	addon_info_t *addon = new(addon_info_t);
	addon->id = "org.xerub.mov";
	addon->name = "AArch64 MOV";
	addon->producer = "xerub";
	addon->url = "xerub@protonmail.com";
	addon->version = "7.0";
	register_addon(addon);
	aarch64_node.create(node_name);
	enabled = aarch64_node.altval(0) != MAGIC_DEACTIVATED;
	if (enabled) {
		hook_to_notification_point(HT_IDP, aarch64_extension_callback, NULL);
		msg("AArch64 MOV simplifier is enabled\n");
		return PLUGIN_KEEP;
	}
	return PLUGIN_OK;
}


void idaapi term(void)
{
	unhook_from_notification_point(HT_IDP, aarch64_extension_callback);
}

bool idaapi run(size_t /*arg*/)
{
	if (enabled) {
		unhook_from_notification_point(HT_IDP, aarch64_extension_callback);
	} else {
		hook_to_notification_point(HT_IDP, aarch64_extension_callback, NULL);
	}
	enabled = !enabled;
	aarch64_node.create(node_name);
	aarch64_node.altset(0, enabled ? MAGIC_ACTIVATED : MAGIC_DEACTIVATED);
	info("AUTOHIDE NONE\n" "AArch64 MOV simplifier is now %sabled", enabled ? "en" : "dis");
	refresh_idaview_anyway();
	return true;
}

//--------------------------------------------------------------------------

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,
	init,
	term,
	run,
	"AArch64 MOV simplifier", // comment
	"Runs transparently", // help
	"Aarch64 MOV", // name
	"Alt-Z" // hotkey
};
