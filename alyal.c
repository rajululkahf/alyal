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

#define VERSION "1.1"
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
        "Alyal v%s [1] - A file encryption tool implementing:\n"
        "    - Ghasaq [2] for key derivation.\n"
        "    - Baheem [3] for encryption and decryption.\n"
        "Copyright (c) M. Rajululkahf %s.\n"
        "Licensed under the GNU GPLv3 [4].\n"
        "[1] https://codeberg.org/rajululkahf/alyal\n"
        "[2] https://codeberg.org/rajululkahf/ghasaq\n"
        "[3] https://codeberg.org/rajululkahf/baheem\n"
        "[4] https://www.gnu.org/licenses/gpl-3.0.txt\n"
        "\n"
        "Usage:\n"
        "   %s (dkenc|dkdec|enc|dec) IN OUT [TRNG]\n"
        "   %s help\n"
        "\n"
        "Subcommands:\n"
        "   dkenc   Derive key from password then encrypt IN into OUT.\n"
        "   dkdec   Derive key from password then decrypt IN into OUT.\n"
        "   enc     Use raw 128-bit key to encrypt IN into OUT.\n"
        "   dec     use raw 128-bit key to decrypt IN into OUT.\n"
        "   help    Print this menu then exist.\n"
        "\n"
        "Arguments:\n"
        "   IN      Input file path.\n"
        "   OUT     Outpuf file path.\n"
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
    char k_tmp;
    int i = 0, j = 0;
    while (fread(&k_tmp, 1, 1, stdin)) {
        if (k_tmp == '\n') break;
        if (
            !(k_tmp >= '0' && k_tmp <= '9') &&
            !(k_tmp >= 'a' && k_tmp <= 'f') &&
            !(k_tmp >= 'A' && k_tmp <= 'F')
        ) {
            alyal_error("Invalid hexadecimal input");
            return 1;
        }
        if (j > 15) {
            alyal_error("Too long key");
            return 1;
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
        return 1;
    }
    return 0;
}

/*
 * function implementing Ghasaq:
 * https://codeberg.org/rajululkahf/ghasaq
 */
int ghasaq(
    FILE *in,    /* input file         */
    FILE *out,   /* output file        */
    uint64_t *k  /* 128-bit key output */
) {
    /* disable terminal echo */
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, 0, &term);

    /* derive key */
    alyal_info("Reading password from STDIN..");
    k[0] = 0;
    k[1] = 0;
    char passchar;
    int done = 0;
    while (fread(&passchar, 1, 1, stdin)) {
        if (passchar == '\n') {
            done = 1;
            break;
        }
        int i;
        for (i = 1; i <= 128; i <<= 1) {
            uint64_t r[2];
            if (alyal_random(r, 16, in)) break;
            if (out != NULL) {
                k[0] ^= r[0];
                k[1] ^= r[1];
            }
            if (passchar & i) {
                r[0] ^= 0xffffffffffffffff;
                r[1] ^= 0xffffffffffffffff;
            }
            passchar = 0; /* clear the password from memory ASAP */
            if (out != NULL) {
                fwrite(r, 16, 1, out);
            } else {
                k[0] ^= r[0];
                k[1] ^= r[1];
            }
        }
    }

    /* enable terminal echo */
    term.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, 0, &term);

    /* handle errors */
    if (feof(stdin) == 0 && done == 0) {
        alyal_error("Reading password failed");
        return 1;
    }

    return 0;
}

/*
 * functions implementing Baheem:
 * https://codeberg.org/rajululkahf/baheem
 */
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
    int is_enc = 0, is_dk = 0, is_badarg = 0;
    char *inpath, *outpath, *trngpath = DEFAULT_TRNG;
    switch(argc) {
        case 5:
            trngpath = argv[4];
            /* fall through */
        case 4:
            if (strcmp(argv[1], "dkenc") == 0) {
                is_enc = 1;
                is_dk  = 1;
            } else if (strcmp(argv[1], "dkdec") == 0) {
                is_dk  = 1;
            } else if (strcmp(argv[1], "enc") == 0) {
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

    /* get a 128-bit key */
    if (is_dk) {
        if (is_enc) {
            if (ghasaq(trng, out, k)) goto fail;
        } else {
            if (ghasaq(in, NULL, k)) goto fail;
        }
    } else {
        if (alyal_get_key(k)) goto fail;
    }

    /* process input into output */
    size_t in_size;
    if (is_enc) {
        alyal_info("Encrypting...");
        while ((in_size = fread(m, 1, m_size, in))) {
            if (alyal_random(p, p_size + q_size, trng)) {
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
        while ((in_size = fread(p, 1, p_size + q_size + m_size, in))) {
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
