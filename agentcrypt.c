/*
 * Copyright (c) 2019, Nicola Di Lieto <nicola.dilieto@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "libagentcrypt.h"

static int ask(char *format, ...)
{
    char *line = NULL;
    size_t line_size = 0;
    int rc = -1;
    char c;
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    if (getline(&line, &line_size, stdin) > 0 &&
            sscanf(line, " %c", &c) == 1)
    {
        rc = (unsigned char)c;
    }
    free(line);
    return rc;
}

static int process(const char *agent, const char *name, const char *key,
        bool decrypt, bool text, bool keep, bool to_stdout, bool force,
        bool verbose)
{
    int rc = 0;
    const char *iname = NULL;
    char *oname = NULL;
    FILE *input = NULL;
    FILE *output = NULL;
    const char *ext = text ? ".act" : ".acb";
    struct stat ist, ost;

    if (name)
    {
        if (lstat(name, &ist) != 0)
        {
            warn("%s: stat failed", name);
            return 0;
        }
        if (S_ISDIR(ist.st_mode))
        {
            warnx("%s: is a directory - ignored", name);
            return 0;
        }
        if (!S_ISREG(ist.st_mode))
        {
            warnx("%s: is not a regular file - ignored", name);
            return 0;
        }
        if (ist.st_mode & (S_ISUID | S_ISGID))
        {
            warnx("%s: is SUID or SGID on execution - ignored", name);
            return 0;
        }

        const char *name_ext = strrchr(name, '.');
        if (!name_ext || strcasecmp(ext, name_ext))
        {
            if (decrypt)
            {
                warnx("%s: suffix is not %s - ignored", name, ext);
                return 0;
            }
        }
        else
        {
            if (!decrypt)
            {
                warnx("%s already has %s suffix - ignored", name, ext);
                return 0;
            }
        }

        iname = name;
        input = fopen(name, "r");
        if (!input)
        {
            warn("failed to open %s", name);
            rc = -1;
            goto done;
        }

        if (to_stdout)
        {
            output = stdout;
            oname = strdup("stdout");
            if (!oname)
            {
                warn("strdup failed");
                rc = -1;
                goto done;
            }
        }
        else
        {
            if (decrypt)
            {
                oname = strdup(name);
                if (!oname)
                {
                    warn("strdup failed");
                    rc = -1;
                    goto done;
                }
                oname[strlen(oname) - 4] = 0;
            }
            else
            {
                if (asprintf(&oname, "%s%s", name, ext) < 0)
                {
                    oname = NULL;
                    warn("asprintf failed");
                    rc = -1;
                    goto done;
                }
            }

            if (access(oname, F_OK) == 0)
            {
                if (lstat(oname, &ost) != 0)
                {
                    warn("%s: already exists and stat failed", oname);
                    rc = -1;
                    goto done;
                }
                if (S_ISDIR(ost.st_mode))
                {
                    warnx("%s: already exists and a directory", oname);
                    rc = -1;
                    goto done;
                }
                if (!S_ISREG(ost.st_mode))
                {
                    warnx("%s: already exists and not a regular file", oname);
                    rc = -1;
                    goto done;
                }
                if (!force)
                {
                    int c = ask("%s already exists; do you wish to overwrite"
                            " (y or n)? ", oname);
                    if (c < 0 || tolower(c) != 'y')
                    {
                        rc = 0;
                        keep = true;
                        goto done;
                    }
                }
            }

            output = fopen(oname, "w");
            if (!output)
            {
                warn("failed to open %s", oname);
                rc = -1;
                goto done;
            }
        }
    }
    else
    {
        input = stdin;
        iname = "stdin";
        output = stdout;
        oname = strdup("stdout");
        if (!oname)
        {
            warn("strdup failed");
            rc = -1;
            goto done;
        }
    }

    if (text)
    {
        char *line = NULL;
        size_t line_size = 0;
        ssize_t line_length = 0;
        int lno = 0;
        struct termios oflags, nflags;
        int fd = fileno(input);
        if (fd < 0)
        {
            warn("fileno failed");
            rc = -1;
        }
        else if (fd >= 0 && isatty(fd) && !decrypt)
        {
            if (tcgetattr(fd, &oflags))
            {
                warn("tcgetattr failed");
                rc = -1;
            }
            else
            {
                nflags = oflags;
                nflags.c_lflag &= ~ECHO;
                if (tcsetattr(fd, TCSANOW, &nflags))
                {
                    warn("tcsetattr failed");
                    rc = -1;
                }
            }
        }
        else
        {
            fd = -1;
        }
        if (!rc && verbose)
        {
            warnx("%s %s to %s in text mode",
                    decrypt ? "decrypting" : "encrypting",
                    iname, oname);
        }
        while (!rc && (line_length = getline(&line, &line_size, input)) != -1)
        {
            uint8_t *buf = NULL;
            size_t buf_size = 0;
            size_t out_size = 0;
            lno++;
            if (line_length > 0 && line[line_length-1] == '\n')
            {
                line[line_length-1] = 0;
                line_length--;
            }
            if (decrypt)
            {
                uint8_t *out = NULL;
                if (agc_from_b64(line, &buf, &buf_size)
                        || agc_decrypt(agent, buf, buf_size, &out, &out_size)
                        || fwrite(out, 1, out_size, output) != out_size
                        || fputc('\n', output) == EOF
                        || fflush(output) == EOF)
                {
                    warn("failed to decrypt line %d of %s", lno, iname);
                    rc = -1;
                }
                agc_free(out, out_size);
            }
            else
            {
                char *out = NULL;
                if (agc_encrypt(agent, key, (uint8_t *)line, line_length, 0,
                            &buf, &buf_size) < 0
                        || agc_to_b64(buf, buf_size, &out, &out_size) < 0
                        || fprintf(output, "%s\n", out) < 0
                        || fflush(output) == EOF)
                {
                    warn("failed to encrypt line %d of %s", lno, iname);
                    rc = -1;
                }
                agc_free(out, out_size);
            }
            agc_free(buf, buf_size);
        }
        free(line);
        if (fd >= 0 && tcsetattr(fd, TCSANOW, &oflags))
        {
            warn("tcsetattr failed");
        }
    }
    else
    {
        if (decrypt)
        {
            if (verbose)
            {
                warnx("decrypting %s to %s in binary mode",
                    iname, oname);
            }
            if (agc_fdecrypt(agent, input, output) < 0)
            {
                warn("failed to decrypt %s", iname);
                rc = -1;
                goto done;
            }
        }
        else
        {
            if (verbose)
            {
                warnx("encrypting %s to %s in binary mode",
                    iname, oname);
            }
            if (agc_fencrypt(agent, key, input, output) < 0)
            {
                warn("failed to encrypt %s", iname);
                rc = -1;
                goto done;
            }
        }
    }
done:
    if (input && input != stdin)
    {
        fclose(input);
    }
    if (output && output != stdout)
    {
        fclose(output);
        if (rc < 0)
        {
            if (oname)
            {
                unlink(oname);
            }
        }
        else if (name)
        {
            if (!keep)
            {
                if (verbose)
                {
                    warnx("removing %s", name);
                }
                if (unlink(name) < 0)
                {
                    warn("failed to unlink %s", name);
                    rc = -1;
                }
            }
            if (chown(oname, ist.st_uid, ist.st_gid))
            {
                warn("%s: chown failed", oname);
            }
            if (chmod(oname, ist.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != 0)
            {
                warn("%s: chmod failed", oname);
            }
            struct timespec times[2] = { ist.st_atim, ist.st_mtim };
            if (utimensat(AT_FDCWD, oname, times, 0) != 0)
            {
                warn("%s: failed to set file timestamps", oname);
            }
        }
    }
    free(oname);
    return rc;
}

static void usage(const char *progname)
{
    fprintf(stderr,
    "Usage: %s [OPTION]... [FILE]...\n"
    "Encrypt/decrypt FILEs with ssh-agent (by default, encrypt in-place).\n\n"
    "  -c    write on stdout, keep input files unchanged\n"
    "  -d    decrypt\n"
    "  -e FP encrypt using a ssh key with the specfied SHA256 fingerprint\n"
    "        Use 'ssh-add -l -E sha256' to display available fingerprints\n"
    "  -f    force overwrite of output files\n"
    "  -h    give this help\n"
    "  -k    keep (don't delete) input files\n"
    "  -t    encrypt/decrypt line by line, output text\n"
    "  -v    verbose mode\n"
    "  -V    display version number\n\n"
    "With no FILE, read standard input.\n\n"
    "Report bugs at https://github.com/ndilieto/agentcrypt/issues\n",
    progname);
}

static void version(const char *progname)
{
    fprintf(stderr, "%s %s (https://github.com/ndilieto/libagentcrypt)\n"
            "Copyright (C) 2019 Nicola Di Lieto\nYou may redistribute "
            "this program under the terms of the ISC license.\n",
    progname, PACKAGE_VERSION);
}

int main(int argc, char *argv[])
{
    bool to_stdout = false;
    bool decrypt = false;
    bool force = false;
    bool keep = false;
    bool text = false;
    bool verbose = false;
    const char *key = NULL;
    const char *agent = getenv("SSH_AUTH_SOCK");
    if (!agent)
    {
        errx(EXIT_FAILURE, "SSH_AUTH_SOCK not found");
    }

    while (1)
    {
        int c = getopt(argc, argv, "cde:fhktvV");
        if (c == -1) break;
        switch (c)
        {
            case 'c':
                to_stdout = true;
                break;

            case 'd':
                decrypt = true;
                break;

            case 'e':
                key = optarg;
                break;

            case 'f':
                force = true;
                break;

            case 'k':
                keep = true;
                break;

            case 't':
                text = true;
                break;

            case 'v':
                verbose = true;
                break;

            case 'V':
                version(basename(argv[0]));
                return EXIT_SUCCESS;

            case 'h':
                usage(basename(argv[0]));
                return EXIT_SUCCESS;

            default:
                usage(basename(argv[0]));
                return EXIT_FAILURE;
        }
    }

    if (key && decrypt)
    {
        errx(EXIT_FAILURE, "specify either -e or -d, not both");
    }

    if (optind == argc)
    {
        if (keep)
        {
            warnx("-k is redundant when reading from stdin");
        }
        if (to_stdout)
        {
            warnx("-c is redundant when reading from stdin");
        }
        if (!text && !force)
        {
            int fd = fileno(stdout);
            if (fd >= 0 && isatty(fd))
            {
                warnx("encrypted data not written to a terminal.\n"
                        "Use -f to force encryption, or -t for text mode\n"
                        "For help, type: %s -h", basename(argv[0]));
                return EXIT_FAILURE;
            }
        }
        if (process(agent, NULL, key, decrypt, text, false, true,
                    force, verbose) < 0)
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        if (keep && to_stdout)
        {
            warnx("-k is redundant with -c");
        }

        if (!text && to_stdout && !force)
        {
            int fd = fileno(stdout);
            if (fd >= 0 && isatty(fd))
            {
                warnx("encrypted data not written to a terminal.\n"
                        "Use -f to force encryption, or -t for text mode\n"
                        "For help, type: %s -h", basename(argv[0]));
                return EXIT_FAILURE;
            }
        }

        while (optind < argc)
        {
            if (process(agent, argv[optind++], key, decrypt, text, keep,
                        to_stdout, force, verbose) < 0)
            {
                return EXIT_FAILURE;
            }
        }
    }
    return EXIT_SUCCESS;
}

