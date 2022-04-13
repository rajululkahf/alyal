#include <stdint.h> /* uint*_t */
#include <stdio.h>  /* fprintf, printf, fopen, fread, fwrite, fclose,
                       perror */
#include <string.h> /* strcmp, memset */
#include <stdlib.h> /* malloc, free */

#define VERSION "0"
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
        "\n"
        "Alyal v%s - A provably secure file encryptor\n"
        "Copyright (c) M. Rajululkahf %s\n"
        "Licensed under the GNU GPLv3\n"
        "https://codeberg.org/rajululkahf/alyal\n"
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
    uint64_t *k, /* 128bit pre-shared key */
    uint64_t *p, /* random pad 1          */
    uint64_t *q, /* random pad 2          */
    uint64_t *m, /* message               */
    size_t  len  /* length of m = p = q   */
) {
    size_t i;
    for (i = 0; i < len; i++) {
        m[i] ^= p[i] ^ q[i];
        p[i] ^= k[0];
        q[i] ^= k[1];
    }
}

void baheem_dec(
    uint64_t *k, /* 128bit pre-shared key */
    uint64_t *p, /* random pad 1          */
    uint64_t *q, /* random pad 2          */
    uint64_t *m, /* message               */
    size_t  len  /* length of m = p = q   */
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
    int is_error = 0;
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
                alyal_error("Unknown mode");
                is_error = 1;
            }
            inpath = argv[2];
            outpath = argv[3];
            break;
        default:
            alyal_error("Incorrect number of arguments");
            is_error = 1;
    }
    if (is_error) {
        alyal_help(argv[0]);
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
    pad = malloc(k_size + m_size + p_size + q_size);
    memset(pad, 0, k_size + m_size + p_size + q_size);
    if (pad == NULL) {
        perror("Memory allocation");
        goto fail;
    }
    uint64_t *k = pad;
    uint64_t *m = k + 2;
    uint64_t *p = m + OPSNUM;
    uint64_t *q = p + OPSNUM;

    /* get 128bit key from STDIN */
    alyal_info("Reading 128bit key from STDIN..");
    if (fread(k, 2 * sizeof(uint64_t), 1, stdin) != 1) {
        alyal_error("Too small key");
        goto fail;
    }

    /* process input into output */
    size_t in_size, out_size;
    if (is_enc) {
        alyal_info("Encrypting...");
        while((in_size = fread(m, 1, m_size, in))) {
            if (fread(p, p_size + q_size, 1, trng) != 1) {
                alyal_error("TRNG read failed");
                goto fail;
            }
            baheem_enc(k, p, q, m, OPSNUM);
            out_size = fwrite(p, p_size + q_size, 1, out);
            out_size += fwrite(m, in_size, 1, out);
            if (out_size != 2) {
                alyal_error("Writing output failed");
                goto fail;
            }
        }
    } else {
        alyal_info("Decrypting...");
        while((in_size = fread(m, 1, m_size + p_size + q_size, in))) {
            baheem_dec(k, p, q, m, OPSNUM);
            if (fwrite(m, in_size - p_size - q_size, 1, out) != 1) {
                alyal_error("Writing output failed");
                goto fail;
            }
        }
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
