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

#include <stdint.h> /* uint*_t */
#include <stdio.h>  /* fprintf, printf, fopen, fread, fwrite, fclose, feof,
                       perror */
#include <string.h> /* strcmp, memset */
#include <stdlib.h> /* malloc, free */

#define VERSION "1"
#define YEAR "2022"
#define DEFAULT_TRNG "/dev/random"
#define OPSNUM 512

void alyal_info(char *s) {
    fprintf(stderr, "%s\n", s);
}

void alyal_error(char *s) {
    fprintf(stderr, "Error: %s\n", s);
}

void alyal_help(char *cmd_name) {
    printf(
        "Alyal v%s [1] - A file encryption tool using Baheem [2]\n"
        "Copyright (c) M. Rajululkahf %s\n"
        "Licensed under the GNU GPLv3 [3]\n"
        "[1] https://codeberg.org/rajululkahf/alyal\n"
        "[2] https://codeberg.org/rajululkahf/baheem\n"
        "[3] https://www.gnu.org/licenses/gpl-3.0.txt\n"
        "\n"
        "Usage:\n"
        "   %s (enc|dec) IN OUT [TRNG]\n"
        "\n"
        "Arguments:\n"
        "   enc     Encrypt IN into OUT\n"
        "   dec     Decrypt IN into OUT\n"
        "   IN      Input file path\n"
        "   OUT     Outpuf file path\n"
        "   TRNG    TRNG device path.  Default is '%s'\n"
        "\n",
        VERSION, YEAR, cmd_name, DEFAULT_TRNG
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

void baheem_enc(
    uint64_t *k, /* 128-bit pre-shared key */
    uint64_t *p, /* random pad 1           */
    uint64_t *q, /* random pad 2           */
    uint64_t *m, /* message                */
    size_t  len  /* length of m = p = q    */
) {
    size_t i;
    for (i = 0; i < len; i++) {
        m[i] ^= p[i] ^ q[i];
        p[i] ^= k[0];
        q[i] ^= k[1];
    }
}

void baheem_dec(
    uint64_t *k, /* 128-bit pre-shared key */
    uint64_t *p, /* random pad 1           */
    uint64_t *q, /* random pad 2           */
    uint64_t *m, /* message                */
    size_t  len  /* length of m = p = q    */
) {
    size_t i;
    for (i = 0; i < len; i++) {
        p[i] ^= k[0];
        q[i] ^= k[1];
        m[i] ^= p[i] ^ q[i];
    }
}

int main(int argc, char **argv) {
    /* parse arguments */
    int is_enc = 0;
    char *inpath, *outpath, *trngpath = DEFAULT_TRNG;
    switch(argc) {
        case 5:
            trngpath = argv[4];
            /* fall through */
        case 4:
            if (strcmp(argv[1], "enc") == 0) {
                is_enc = 1;
            } else if (strcmp(argv[1], "dec")) {
                alyal_help(argv[0]);
                alyal_error("Unknown mode");
                return 1;
            }
            inpath = argv[2];
            outpath = argv[3];
            break;
        default:
            alyal_help(argv[0]);
            alyal_error("Incorrect number of arguments");
            return 1;
    }

    /* define sizes */
    size_t k_size = 2 * sizeof(uint64_t);
    size_t m_size = OPSNUM * sizeof(uint64_t);
    size_t p_size = m_size;
    size_t q_size = m_size;

    /* allocate resources */
    int ret = 1;
    FILE *in        = NULL;
    FILE *out       = NULL;
    FILE *trng      = NULL;
    uint64_t *pad   = NULL;
    if (alyal_open(&in,   inpath,   "r")) goto fail;
    if (alyal_open(&out,  outpath,  "w")) goto fail;
    if (alyal_open(&trng, trngpath, "r")) goto fail;
    pad = malloc(k_size + p_size + q_size + m_size);
    memset(pad, 0, k_size + p_size + q_size + m_size);
    if (pad == NULL) {
        perror("Memory allocation");
        goto fail;
    }
    uint64_t *k = pad;
    uint64_t *p = k + 2;
    uint64_t *q = p + OPSNUM;
    uint64_t *m = q + OPSNUM;

    /* get a 128-bit hexadecimal key from STDIN */
    alyal_info("Reading 128-bit hexadecimal key from STDIN..");
    char k_tmp;
    int i = 0, j = 0;
    while(fread(&k_tmp, 1, 1, stdin)) {
        if (k_tmp == '\n') break;
        if (
            !(k_tmp >= '0' && k_tmp <= '9') &&
            !(k_tmp >= 'a' && k_tmp <= 'f') &&
            !(k_tmp >= 'A' && k_tmp <= 'F')
        ) {
            alyal_error("Invalid hexadecimal input");
            goto fail;
        }
        if (j > 15) {
            alyal_error("Too long key");
            goto fail;
        }
        if      (k_tmp <= '9') ((unsigned char *)k)[j] ^= k_tmp - '0';
        else if (k_tmp <= 'f') ((unsigned char *)k)[j] ^= k_tmp - 'a' + 10;
        else if (k_tmp <= 'F') ((unsigned char *)k)[j] ^= k_tmp - 'A' + 10;
        if (i % 2 == 0) ((unsigned char *)k)[j] <<= 4;
        else j++;
        i++;
    }
    if (j < 16) {
        alyal_error("Too short key");
        goto fail;
    }

    /* process input into output */
    size_t in_size;
    if (is_enc) {
        alyal_info("Encrypting...");
        while((in_size = fread(m, 1, m_size, in))) {
            if (fread(p, p_size + q_size, 1, trng) != 1) {
                alyal_error("TRNG read failed");
                goto fail;
            }
            baheem_enc(k, p, q, m, OPSNUM);
            if (fwrite(p, p_size + q_size + in_size, 1, out) != 1) {
                alyal_error("Writing ciphertext failed");
                goto fail;
            }
        }
    } else {
        alyal_info("Decrypting...");
        while((in_size = fread(p, 1, p_size + q_size + m_size, in))) {
            if (in_size < p_size + q_size + 1) {
                alyal_error("Corrupted ciphertext");
                goto fail;
            }
            baheem_dec(k, p, q, m, OPSNUM);
            if (fwrite(m, in_size - p_size - q_size, 1, out) != 1) {
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
    if (pad)  free(pad);
    if (in)   fclose(in);
    if (out)  fclose(out);
    if (trng) fclose(trng);
    return ret;
}
