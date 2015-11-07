/*
 * Compressed pcap packet indexing program (CPPIP)
 * main.c: main module
 *
 * Copyright (c) 2013 - 2015, Mike Schiffman <themikeschiffman@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to 
 * deal in the Software without restriction, including without limitation the 
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
 * sell copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "../include/cppip.h"

int
main(int argc, char **argv)
{
    cppip_t *c;
    int n, opt;
    uint8_t mode, flags;
    char *opt_s, errbuf[BUFSIZ];

    if (argc == 1)
    {
        return usage();
    }
    mode = flags = 0;
    while ((opt = getopt(argc, argv, "DdvIi:he:fiV")) >= 0)
    {
        switch (opt)
        {
            case 'D':
                flags |= CPPIP_CTRL_DEBUG;
                break;
            case 'd':
                if (argc - optind != 1)
                {
                    return usage();
                }
                mode = DUMP;
                c = control_context_init(flags, argv[optind], NULL, NULL, NULL,
                                         mode, errbuf);
                break;
            case 'e':
                /** -e index_mode:n{-m} index pcap.bz new.pcap */
                if (argc - optind != 3)
                {
                    return usage();
                }
                opt_s = optarg;
                mode  = EXTRACT;
                c = control_context_init(flags, argv[optind], argv[optind + 1], 
                                         argv[optind + 2], opt_s, mode, errbuf);
                break;
            case 'f':
                flags |= CPPIP_CTRL_TS_FM;
                break;
            case 'h':
                return usage();
            case 'I':
                return index_dump_modes();
            case 'i':
                /** -i index_mode:index_level */
                if (argc - optind != 2)
                {
                    return usage();
                }
                opt_s = optarg;
                mode  = INDEX;
                c = control_context_init(flags, argv[optind], argv[optind + 1],
                                         NULL, opt_s, mode, errbuf);
                break;
            case 'V':
                return version();
            case 'v':
                if (argc - optind != 1)
                {
                    return usage();
                }
                mode = VERIFY;
                c = control_context_init(flags, argv[optind], NULL, NULL, NULL,
                                         mode, errbuf);
                break;
            default:
                return usage();
        }
    }
    if (c == NULL)
    {
        fprintf(stderr, "control_context_init(): %s", errbuf);
        return -1;
    }

    if (cppip_dispatch(mode, c) == -1)
    {
        fprintf(stderr, "%s", c->errbuf);
    }
    /** shut 'er down */
    if (c)
    {
        control_context_destroy(c);
    }
    return 1;
}

int
cppip_dispatch(int mode, cppip_t *c)
{
    void *index_hdr;
    int n;

    switch (mode)
    {
        case DUMP:
            return index_verify(c, V_DUMP);
        case INDEX:
            printf("indexing %s...\n", c->pcap_fname);
            n = index_dispatch(c);
            if (n == -1)
            {
                return -1;
            }
            else
            {
                fprintf(stderr, "wrote %d records to %s\n", n, c->index_fname);
            }
            return n;
        case EXTRACT:
            if (index_verify(c, 0) == -1)
            {
                return -1;
            }
            printf("extracting from %s using %s...\n", c->pcap_fname, 
                                                       c->index_fname);
            n = extract(c);
            if (n == -1)
            {
                fprintf(stderr, "extract(): %s", c->errbuf);
            }
            fprintf(stderr, "wrote %d packets to %s.\n", c->e_pkts.pkts_w, 
                        c->pcap_new_fname);
            break;
        case VERIFY:
            return index_verify(c, V_DETAILED);
        default:
            snprintf(c->errbuf, BUFSIZ, "unknown mode: %d\n", mode);
            return -1;
    }
    return 1;
}

/** EOF */
