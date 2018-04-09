/*
 *  cmp/ccmp
 *
 *  Copyright (c) 2015 xerub
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

/*
        CMP             A, B
        CCMP            C, D, NZCV, COND1
        B.COND2         label

        nzcv = cmp(A, B);
        if (COND1(nzcv)) {
                nzcv = cmp(C, D);
        } else {
                nzcv = NZCV
        }
        if (COND2(nzcv)) {
                goto label
        }

        if (COND1(A, B)) {
                if (COND2(C, D)) {
                        goto label
                }
        } else {
                if (COND2(NZCV)) {
                        goto label
                }
        }
*/

#define FLAG_N (1 << 3)
#define FLAG_Z (1 << 2)
#define FLAG_C (1 << 1)
#define FLAG_V (1 << 0)

struct condition_t {
        const char *name;
        unsigned int mask;
        unsigned int result1;
        unsigned int result2;
        int inverse;
        char *templ;
} tab[] = {
             /* flags tested (mask)                     (must equal this)       (or this) */
        { "eq",          FLAG_Z,                        FLAG_Z,                 FLAG_Z,         0, "%s == %s" },
        { "ne",          FLAG_Z,                        FLAG_Z,                 FLAG_Z,         1, "%s != %s" },
        { "cs",                   FLAG_C,               FLAG_C,                 FLAG_C,         0, "(unsigned)%s >= %s" },
        { "cc",                   FLAG_C,               FLAG_C,                 FLAG_C,         1, "(unsigned)%s < %s" },
        { "hi",          FLAG_Z | FLAG_C,               FLAG_C,                 FLAG_C,         0, "(unsigned)%s > %s" },
        { "ls",          FLAG_Z | FLAG_C,               FLAG_C,                 FLAG_C,         1, "(unsigned)%s <= %s" },
        { "ge", FLAG_N |                   FLAG_V,      FLAG_N|FLAG_V,          0,              0, "(signed)%s >= %s" },
        { "lt", FLAG_N |                   FLAG_V,      FLAG_N|FLAG_V,          0,              1, "(signed)%s < %s" },
        { "gt", FLAG_N | FLAG_Z |          FLAG_V,      FLAG_N|FLAG_V,          0,              0, "(signed)%s > %s" },
        { "le", FLAG_N | FLAG_Z |          FLAG_V,      FLAG_N|FLAG_V,          0,              1, "(signed)%s <= %s" },
        { NULL, 0,                                      0,                      0,              0, NULL }
};

/*
eq      Equal.                                                  Z==1
ne      Not equal.                                              Z==0
cs/hs   Unsigned higher or same (or carry set).                 C==1
cc/lo   Unsigned lower (or carry clear).                        C==0
mi      Negative. The mnemonic stands for "minus".              N==1
pl      Positive or zero. The mnemonic stands for "plus".       N==0
vs      Signed overflow. The mnemonic stands for "V set".       V==1
vc      No signed overflow. The mnemonic stands for "V clear".  V==0
hi      Unsigned higher.                                        (C==1) && (Z==0)
ls      Unsigned lower or same.                                 (C==0) || (Z==1)
ge      Signed greater than or equal.                           N==V
lt      Signed less than.                                       N!=V
gt      Signed greater than.                                    (Z==0) && (N==V)
le      Signed less than or equal.                              (Z==1) || (N!=V)
*/

static const struct condition_t *
flipcond(const struct condition_t *c)
{
        if (c->inverse) {
                return --c;
        }
        return ++c;
}

static const struct condition_t *
getcond(const char *name)
{
        struct condition_t *c;
        for (c = tab; c->name; c++) {
                if (!strcasecmp(c->name, name)) {
                        return c;
                }
        }
        return NULL;
}

static int
evalcond(const char *name, unsigned int nzcv)
{
        struct condition_t *c;
        for (c = tab; c->name; c++) {
                if (!strcasecmp(c->name, name)) {
                        /* found condition */
                        unsigned int r = nzcv & c->mask;
                        int result = (r == c->result1 || r == c->result2);
                        if (result ^ c->inverse) {
                                return 1;
                        }
                        return 0;
                }
        }
        return -1;
}

static int
pr1(const char *A,
    const char *B,
    const char *C,
    const char *D,
    unsigned int NZCV,
    const char *COND1,
    const char *COND2,
    const char *label)
{
        const struct condition_t *c1 = getcond(COND1);
        const struct condition_t *c2 = getcond(COND2);
        int e = evalcond(COND2, NZCV);
        assert(c1 && c2 && e >= 0);

        printf("if (");
        printf(c1->templ, A, B);
        printf(") {\n");

        printf("\tif (");
        printf(c2->templ, C, D);
        printf(") {\n");
        printf("\t\tgoto %s;\n", label);
        printf("\t}\n");
        if (e) {
                printf("} else {\n");
                printf("\tgoto %s;\n", label);
        }

        printf("}\n");

        return 0;
}

static int
qr1(const char *A,
    const char *B,
    const char *C,
    const char *D,
    unsigned int NZCV,
    const char *COND1,
    const char *COND2,
    const char *label)
{
        const struct condition_t *c1 = getcond(COND1);
        const struct condition_t *c2 = getcond(COND2);
        int e = evalcond(COND2, NZCV);
        assert(c1 && c2 && e >= 0);

        printf("if (");
        if (e) {
                c1 = flipcond(c1);
                printf(c1->templ, A, B);
                printf(" || ");
        } else {
                printf(c1->templ, A, B);
                printf(" && ");
        }
        printf(c2->templ, C, D);
        printf(") goto %s;\n", label);

        return 0;
}

int
main(void)
{
        /*
        CMP             W12, W9
        CCMP            W2, #0, #0, HI
        B.EQ            label
        */
        pr1("W12", "W9", "W2", "0", 0, "HI", "EQ", "label");
        printf("-\n");
        qr1("W12", "W9", "W2", "0", 0, "HI", "EQ", "label");
        printf("==\n");

        /*
        CMP              W11, #0x80
        CCMP             W11, #0x1F, #0, NE
        B.CC             label
        */
        pr1("W11", "0x80", "W11", "0x1F", 0, "NE", "CC", "label");
        printf("-\n");
        qr1("W11", "0x80", "W11", "0x1F", 0, "NE", "CC", "label");
        printf("==\n");
        return 0;
}
