/*
 *  Alyal - A file encryption and decryption tool based on Baheem.
 *  Copyright (C) 2022 M. Rajululkahf
 *  https://codeberg.org/rajululkahf/alyal
 *  https://codeberg.org/rajululkahf/baheem
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>  /* uint*_t */
#include <stdio.h>   /* fprintf, printf, fopen, fread, fwrite, fclose,
                        feof, perror */
#include <string.h>  /* strcmp, memset */
#include <stdlib.h>  /* malloc, free, fileno */
#include <unistd.h>  /* STDIN_FILENO */
#include <termios.h> /* tcgetattr, tcsetattr */

#define VERSION "3"
#define YEAR "2022"
#define DEFAULT_TRNG "/dev/random"
#define OPSNUM 512   /* must be an even number */

void alyal_info(char *s) {
    fprintf(stderr, "%s\n", s);
}

void alyal_error(char *s) {
    fprintf(stderr, "Error: %s\n", s);
}

void alyal_help(char *cmd_name) {
    printf(
        "Alyal v%s [1] - A file encryption tool implementing:\n"
        "    - Baheem [2] for encryption and decryption.\n"
        "Copyright (c) M. Rajululkahf %s.\n"
        "Licensed under the GNU GPLv3 [3].\n"
        "[1] https://codeberg.org/rajululkahf/alyal\n"
        "[2] https://codeberg.org/rajululkahf/baheem\n"
        "[3] https://www.gnu.org/licenses/gpl-3.0.txt\n"
        "\n"
        "Usage:\n"
        "   %s (enc|dec) IN OUT [TRNG]\n"
        "   %s help\n"
        "\n"
        "Subcommands:\n"
        "   enc     Use raw 128-bit key to encrypt IN into OUT.\n"
        "   dec     use raw 128-bit key to decrypt IN into OUT.\n"
        "   help    Print this menu then exist.\n"
        "\n"
        "Arguments:\n"
        "   IN      Input file path.\n"
        "   OUT     Output file path.\n"
        "   TRNG    TRNG device path.  Default is '%s'.\n"
        "\n",
        VERSION, YEAR, cmd_name, cmd_name, DEFAULT_TRNG
    );
}

int alyal_open(FILE **f, char *path, char *mode) {
    *f = fopen(path, mode);
    if (*f == NULL) {
        perror(path);
        return 1;
    }
    return 0;
}

int alyal_random(void *out, size_t n, void *in) {
    if (fread(out, n, 1, in) != 1) {
        alyal_error("TRNG read failed");
        return 1;
    }
    return 0;
}

int alyal_get_key(uint64_t *k) {
    alyal_info("Reading 128-bit hexadecimal key from STDIN..");
    k[0] = 0;
    k[1] = 0;
    unsigned char *kb = (unsigned char *)k;
    char c;
    int i = 0, j = 0;
    while (fread(&c, 1, 1, stdin)) {
        if (c == '\n') break;
        if (j > 15)    goto bad_length;
        if      (c >= '0' && c <= '9') kb[j] ^= c - '0';
        else if (c >= 'a' && c <= 'f') kb[j] ^= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') kb[j] ^= c - 'A' + 10;
        else goto bad_format;
        if (i % 2 == 0) kb[j] <<= 4;
        else j++;
        i++;
    }
    if (j == 16) return 0;
bad_length:
    alyal_error("Key length must be 128 bits"); return 1;
bad_format:
    alyal_error("Key must be encoded in hex");  return 1;
}

/*
 * functions implementing Baheem:
 * https://codeberg.org/rajululkahf/baheem
 */
void baheem_session_enc(
    uint64_t *k,    /* pre-shared key */
    uint64_t *s,    /* session key    */
    uint64_t *s_enc /* encrypted s    */
) {
    s_enc[0] = s[0] + k[0];
    s_enc[1] = s[1] + k[1];
}

void baheem_session_dec(
    uint64_t *k, /* pre-shared key */
    uint64_t *s  /* session key    */
) {
    s[0] -= k[0];
    s[1] -= k[1];
}

void baheem_block_enc(
    uint64_t *k, /* pre-shared key    */
    uint64_t *s, /* session key       */
    uint64_t *p, /* pad keys          */
    uint64_t *m, /* message           */
    size_t  len  /* length of m and p */
) {
    size_t i;
    for (i = 0; i < len; i += 2) {
        m[i]   ^= p[i]   + s[0];
        m[i+1] ^= p[i+1] + s[1];
        p[i]   += k[0];
        p[i+1] += k[1];
    }
}

void baheem_block_dec(
    uint64_t *k, /* pre-shared key    */
    uint64_t *s, /* session key       */
    uint64_t *p, /* pad keys          */
    uint64_t *m, /* message           */
    size_t  len  /* length of m and p */
) {
    size_t i;
    for (i = 0; i < len; i += 2) {
        p[i]   -= k[0];
        p[i+1] -= k[1];
        m[i]   ^= p[i]   + s[0];
        m[i+1] ^= p[i+1] + s[1];
    }
}

int main(int argc, char **argv) {
    /* parse arguments */
    int is_enc = 0, is_badarg = 0;
    char *inpath, *outpath, *trngpath = DEFAULT_TRNG;
    switch(argc) {
        case 5:
            trngpath = argv[4];
            /* fall through */
        case 4:
            if (strcmp(argv[1], "enc") == 0) {
                is_enc = 1;
            } else if (strcmp(argv[1], "dec") == 0) {
                /* same values as already set */
            } else {
                is_badarg = 1;
            }
            inpath = argv[2];
            outpath = argv[3];
            break;
        case 2:
            if (strcmp(argv[1], "help") == 0) {
                alyal_help(argv[0]);
                return 0;
            }
            is_badarg = 1;
            /* fall through */
        default:
            alyal_error("Incorrect arguments");
            is_badarg = 1;
    }
    if (is_badarg) {
        alyal_info("Use the `help` subcommand for help");
        return 1;
    }

    /* define sizes */
    size_t k_size = 2 * sizeof(uint64_t);
    size_t s_size = k_size;
    size_t p_size = OPSNUM * sizeof(uint64_t);
    size_t m_size = p_size;

    /* allocate resources */
    int ret = 1;
    FILE *in        = NULL;
    FILE *out       = NULL;
    FILE *trng      = NULL;
    uint64_t *pad   = NULL;
    if (alyal_open(&in,   inpath,   "r")) goto fail;
    if (alyal_open(&out,  outpath,  "w")) goto fail;
    if (alyal_open(&trng, trngpath, "r")) goto fail;
    pad = malloc(k_size + s_size + p_size + m_size);
    if (pad == NULL) {
        perror("Memory allocation");
        goto fail;
    }
    uint64_t *k = pad;
    uint64_t *s = k + 2;
    uint64_t *p = s + 2;
    uint64_t *m = p + OPSNUM;

    /* get a 128-bit key */
    if (alyal_get_key(k)) goto fail;

    /* process input into output */
    size_t in_size;
    if (is_enc) {
        alyal_info("Encrypting...");
        if (alyal_random(s, s_size, trng)) goto fail;
        baheem_session_enc(k, s, p);
        if (fwrite(p, s_size, 1, out) != 1) {
            alyal_error("Writing encryptd session key failed");
            goto fail;
        }
        while ((in_size = fread(m, 1, m_size, in))) {
            if (alyal_random(p, p_size, trng)) goto fail;
            baheem_block_enc(k, s, p, m, OPSNUM);
            if (fwrite(p, p_size + in_size, 1, out) != 1) {
                alyal_error("Writing ciphertext failed");
                goto fail;
            }
        }
    } else {
        alyal_info("Decrypting...");
        if (fread(s, s_size, 1, in) != 1) {
            alyal_error("Reading encryptd session key failed");
            goto fail;
        }
        baheem_session_dec(k, s);
        while ((in_size = fread(p, 1, p_size + m_size, in))) {
            if (in_size < p_size + 1) {
                alyal_error("Corrupted ciphertext");
                goto fail;
            }
            baheem_block_dec(k, s, p, m, OPSNUM);
            if (fwrite(m, in_size - p_size, 1, out) != 1) {
                alyal_error("Writing cleartext failed");
                goto fail;
            }
        }
    }
    if (feof(in) == 0) {
        alyal_error("Reading input failed");
        goto fail;
    }

    /* free resources and exit */
    ret = 0;
fail:
    if (pad) {
        memset(pad, 0, k_size + s_size + p_size + m_size);
        free(pad);
    }
    if (in)   fclose(in);
    if (out)  fclose(out);
    if (trng) fclose(trng);
    return ret;
}
