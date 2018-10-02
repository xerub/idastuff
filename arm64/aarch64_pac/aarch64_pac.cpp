/*
 *  AArch64 8.3-A Pointer Authentication extension
 *
 *  Copyright (c) 2018 xerub
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
 */


#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>
#include <segregs.hpp>

/*
 * Fix for decompiler analysis:
 * Copyright (c) 2018 Eloi Benoist-Vanderbeken - Synacktiv
 * https://github.com/Synacktiv/kernelcache-laundering/blob/master/aarch64_pac.py
 */
#define CONVERT_INSN 1

#ifdef CONVERT_INSN
#define ARM64_PAC_I ARM_hlt	// op1=io, op2=in, op3=in
#else
#define ARM64_PAC_I ARM_hint	// op1=in
#endif

inline bool is_arm64_ea(ea_t ea)
{
	segment_t *seg = getseg(ea);
	return seg != NULL && seg->use64();
}

enum PAC {
	pac_NONE,
	pac_PACIASP, pac_PACIBSP, pac_AUTIASP, pac_AUTIBSP,
	pac_PACIAZ, pac_PACIBZ, pac_AUTIAZ, pac_AUTIBZ,
	pac_PACIA1716, pac_PACIB1716, pac_AUTIA1716, pac_AUTIB1716,
	pac_PACIA, pac_PACIB, pac_PACDA, pac_PACDB, pac_AUTIA, pac_AUTIB, pac_AUTDA, pac_AUTDB,
	pac_PACIZA, pac_PACIZB, pac_PACDZA, pac_PACDZB, pac_AUTIZA, pac_AUTIZB, pac_AUTDZA, pac_AUTDZB,
	pac_PACGA,
	pac_XPACLRI,
	pac_XPACI, pac_XPACD,
	pac_RETAA, pac_RETAB,
	pac_BRAA, pac_BRAB, pac_BRAAZ, pac_BRABZ, pac_BLRAA, pac_BLRAB, pac_BLRAAZ, pac_BLRABZ,
	pac_ERETAA, pac_ERETAB,
	pac_LDRAA, pac_LDRAB,
};

static const char *pac_tab[] = {
	"PACIASP", "PACIBSP", "AUTIASP", "AUTIBSP",
	"PACIAZ", "PACIBZ", "AUTIAZ", "AUTIBZ",
	"PACIA1716", "PACIB1716", "AUTIA1716", "AUTIB1716",
	"PACIA", "PACIB", "PACDA", "PACDB", "AUTIA", "AUTIB", "AUTDA", "AUTDB",
	"PACIZA", "PACIZB", "PACDZA", "PACDZB", "AUTIZA", "AUTIZB", "AUTDZA", "AUTDZB",
	"PACGA",
	"XPACLRI",
	"XPACI", "XPACD",
	"RETAA", "RETAB",
	"BRAA", "BRAB", "BRAAZ", "BRABZ", "BLRAA", "BLRAB", "BLRAAZ", "BLRABZ",
	"ERETAA", "ERETAB",
	"LDRAA", "LDRAB",
};

static size_t ana(insn_t *insn)
{
	ea_t ea = insn->ea;
	if (is_arm64_ea(ea)) {
		unsigned d = get_32bit(ea);
		if ((d & 0xffffc000) == 0xdac10000) {
			int m = (d >> 10) & 7;
			int Z = (d >> 13) & 1;
			int Xn = (d >> 5) & 0x1F;
			int Xd = d & 0x1F;
			if (Z == 0) {
				insn->itype = ARM64_PAC_I;
				insn->segpref = 14;
				insn->Op1.type = o_reg;
				insn->Op1.reg = Xd + 129;
				insn->Op1.dtype = dt_qword;
				insn->Op2.type = o_reg;
				insn->Op2.reg = Xn + 129;
				insn->Op2.dtype = dt_qword;
				insn->Op2.flags = OF_SHOW;
#ifdef CONVERT_INSN
				insn->Op3 = insn->Op1;
				insn->Op3.flags = 0;
#endif
				insn->insnpref = pac_PACIA + m;
				return 4;
			} else if (Xn == 31) {
				insn->itype = ARM64_PAC_I;
				insn->segpref = 14;
				insn->Op1.type = o_reg;
				insn->Op1.reg = Xd + 129;
				insn->Op1.dtype = dt_qword;
#ifdef CONVERT_INSN
				insn->Op2 = insn->Op1;
				insn->Op2.flags = 0;
#endif
				insn->insnpref = pac_PACIZA + m;
				return 4;
			}
		}
		if ((d & 0xfffffd1f) == 0xd503211f) {
			int m = (d >> 6) & 3;
			int CRm = (d >> 9) & 1;
			int op2 = (d >> 5) & 1;
			if (CRm == 0) {
				insn->itype = ARM64_PAC_I;
				insn->segpref = 14;
#ifdef CONVERT_INSN
				insn->Op1.type = o_reg;
				insn->Op1.reg = 17 + 129;
				insn->Op1.dtype = dt_qword;
				insn->Op1.flags = 0;
				insn->Op2.type = o_reg;
				insn->Op2.reg = 16 + 129;
				insn->Op2.dtype = dt_qword;
				insn->Op2.flags = 0;
				insn->Op3 = insn->Op1;
#else
				insn->Op1.type = o_void;
#endif
				insn->insnpref = pac_PACIA1716 + m;
				return 4;
			} else if (op2) {
				insn->itype = ARM64_PAC_I;
				insn->segpref = 14;
#ifdef CONVERT_INSN
				insn->Op1.type = o_reg;
				insn->Op1.reg = 30 + 129;
				insn->Op1.dtype = dt_qword;
				insn->Op1.flags = 0;
				insn->Op2.type = o_reg;
				insn->Op2.reg = 31 + 129;
				insn->Op2.dtype = dt_qword;
				insn->Op2.flags = 0;
				insn->Op3 = insn->Op1;
#else
				insn->Op1.type = o_void;
#endif
				insn->insnpref = pac_PACIASP + m;
				return 4;
			} else {
				insn->itype = ARM64_PAC_I;
				insn->segpref = 14;
#ifdef CONVERT_INSN
				insn->Op1.type = o_reg;
				insn->Op1.reg = 30 + 129;
				insn->Op1.dtype = dt_qword;
				insn->Op1.flags = 0;
				insn->Op2 = insn->Op1;
#else
				insn->Op1.type = o_void;
#endif
				insn->insnpref = pac_PACIAZ + m;
				return 4;
			}
		}
		if ((d & 0xffe0fc00) == 0x9ac03000) {
			int Xm = (d >> 16) & 0x1F;
			int Xn = (d >> 5) & 0x1F;
			int Xd = d & 0x1F;
			insn->itype = ARM64_PAC_I;
			insn->segpref = 14;
			insn->Op1.type = o_reg;
			insn->Op1.reg = Xd + 129;
			insn->Op1.dtype = dt_qword;
			insn->Op2.type = o_reg;
			insn->Op2.reg = Xn + 129;
			insn->Op2.dtype = dt_qword;
			insn->Op3.type = o_reg;
			insn->Op3.reg = Xm + 129;
			insn->Op3.dtype = dt_qword;
			insn->insnpref = pac_PACGA;
			return 4;
		}
		if ((d & 0xfffffbe0) == 0xdac143e0) {
			int D = (d >> 10) & 1;
			int Xd = d & 0x1F;
			insn->itype = ARM64_PAC_I;
			insn->segpref = 14;
			insn->Op1.type = o_reg;
			insn->Op1.reg = Xd + 129;
			insn->Op1.dtype = dt_qword;
#ifdef CONVERT_INSN
			insn->Op2 = insn->Op1;
			insn->Op2.flags = 0;
#endif
			insn->insnpref = pac_XPACI + D;
			return 4;
		}
		if (d == 0xd50320ff) {
			insn->itype = ARM64_PAC_I;
			insn->segpref = 14;
#ifdef CONVERT_INSN
			insn->Op1.type = o_reg;
			insn->Op1.reg = 30 + 129;
			insn->Op1.dtype = dt_qword;
			insn->Op1.flags = 0;
			insn->Op2 = insn->Op1;
#else
			insn->Op1.type = o_void;
#endif
			insn->insnpref = pac_XPACLRI;
			return 4;
		}
		if ((d & 0xfffffbff) == 0xd65f0bff) {
			int M = (d >> 10) & 1;
			insn->insnpref = pac_RETAA + M;
			insn->itype = ARM_ret;
			insn->segpref = 14;
			insn->Op1.type = o_reg;
			insn->Op1.reg = 30 + 129;
			insn->Op1.dtype = dt_qword;
			insn->Op1.flags = 0;
			return 4;
		}
		if ((d & 0xfedff800) == 0xd61f0800) {
			int is_blr = (d >> 19) & 4;
			int Z = (d >> 24) & 1;
			int M = (d >> 10) & 1;
			int Xn = (d >> 5) & 0x1F;
			int Xm = d & 0x1F;
			if (Z == 0 && Xm == 31) {
				insn->itype = is_blr ? ARM_blr : ARM_br;
				insn->segpref = 14;
				insn->Op1.type = o_reg;
				insn->Op1.reg = Xn + 129;
				insn->Op1.dtype = dt_qword;
				insn->insnpref = pac_BRAAZ + M + is_blr;
				return 4;
			} else if (Z) {
				insn->itype = is_blr ? ARM_blr : ARM_br;
				insn->segpref = 14;
				insn->Op1.type = o_reg;
				insn->Op1.reg = Xn + 129;
				insn->Op1.dtype = dt_qword;
				insn->Op2.type = o_reg;
				insn->Op2.reg = Xm + 129;
				insn->Op2.dtype = dt_qword;
				insn->Op2.flags = OF_SHOW;
				insn->insnpref = pac_BRAA + M + is_blr;
				return 4;
			}
		}
		if ((d & 0xfffffbff) == 0xd69f0bff) {
			int M = (d >> 10) & 1;
			insn->insnpref = pac_ERETAA + M;
			insn->itype = ARM_eret;
			insn->segpref = 14;
			return 4;
		}
		if ((d & 0xff200400) == 0xf8200400) {
			int M = (d >> 23) & 1;
			int imm10 = ((d & 0x400000) << 9) | ((d & 0x1ff000) << 10);
			int offset = imm10 >> 19;
			int W = (d >> 11) & 1;
			int Xn = (d >> 5) & 0x1F;
			int Xt = d & 0x1F;
			insn->itype = ARM_ldr;
			insn->segpref = 14;
			insn->Op1.type = o_reg;
			insn->Op1.reg = Xt + 129;
			insn->Op1.dtype = dt_qword;
			insn->Op2.type = o_displ;
			insn->Op2.reg = Xn + 129;
			insn->Op2.dtype = dt_qword;
			insn->Op2.addr = offset;
			if (W) {
				insn->auxpref = 0x20;
			}
			insn->insnpref = pac_LDRAA + M;
			return 4;
		}
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
		case processor_t::ev_out_mnem: {
			outctx_t *ctx = va_arg(va, outctx_t *);
			const insn_t *insn = &ctx->insn;
			if (insn->insnpref) {
				int pri = insn->itype;
				int sec = insn->insnpref;
				const int indent = 16;
				if (pri == ARM64_PAC_I && sec >= pac_PACIASP && sec <= pac_XPACD) {
					ctx->out_custom_mnem(pac_tab[sec - 1], indent);
					return 2;
				}
				if (pri == ARM_ret && sec >= pac_RETAA && sec <= pac_RETAB) {
					ctx->out_custom_mnem(pac_tab[sec - 1], indent);
					return 2;
				}
				if (pri == ARM_br && sec >= pac_BRAA && sec <= pac_BRABZ) {
					ctx->out_custom_mnem(pac_tab[sec - 1], indent);
					return 2;
				}
				if (pri == ARM_blr && sec >= pac_BLRAA && sec <= pac_BLRABZ) {
					ctx->out_custom_mnem(pac_tab[sec - 1], indent);
					return 2;
				}
				if (pri == ARM_eret && sec >= pac_ERETAA && sec <= pac_ERETAB) {
					ctx->out_custom_mnem(pac_tab[sec - 1], indent);
					return 2;
				}
				if (pri == ARM_ldr && sec >= pac_LDRAA && sec <= pac_LDRAB) {
					ctx->out_custom_mnem(pac_tab[sec - 1], indent);
					return 2;
				}
			}
		}
		break;
	}
	return 0;
}

static bool enabled = true;

int idaapi init(void)
{
	if (ph.id != PLFM_ARM) return PLUGIN_SKIP;
	addon_info_t *addon = new(addon_info_t);
	addon->id = "org.xerub.pac";
	addon->name = "AArch64 PAC";
	addon->producer = "xerub";
	addon->url = "xerub@protonmail.com";
	addon->version = "7.0";
	register_addon(addon);
	if (enabled) {
		hook_to_notification_point(HT_IDP, aarch64_extension_callback, NULL);
		msg("AArch64 PAC extension is enabled\n");
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
	info("AUTOHIDE NONE\n" "AArch64 PAC extension is now %sabled", enabled ? "en" : "dis");
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
	"ARM v8.3-A Pointer Authentication extension", // comment
	"Runs transparently", // help
	"Aarch64 PAC", // name
	"Ctrl-Alt-Shift-A" // hotkey
};
