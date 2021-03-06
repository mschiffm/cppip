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

cppip_t *
control_context_init(uint8_t flags, char *index_fname, char *pcap_fname, 
        char *pcap_new_fname, char *opt, int mode, char *errbuf)
{
    cppip_t *c;

    /** gather all the memory we need for a control context */  
    c = malloc(sizeof (cppip_t));
    if (c == NULL)
    {
        snprintf(errbuf, BUFSIZ, "malloc(): %s", strerror(errno));
        return NULL;
    }
    memset(c, 0, sizeof (cppip_t));

    c->flags = flags;
    switch (mode)
    {
        case DUMP:
            break;
        case INDEX:
            /** parse index mode options string */
            if (opt_parse_index(opt, c) == -1)
            {
                memcpy(errbuf, c->errbuf, BUFSIZ);
                goto err;
            }
            if (bgzf_is_bgzf(pcap_fname) == 0)
            {
                snprintf(errbuf, BUFSIZ, "%s is not a bgzf compressed file\n",
                        pcap_fname);
                goto err;
            }
            c->pcap = bgzf_open(pcap_fname, "r");
            if (c->pcap == NULL)
            {
                snprintf(errbuf, BUFSIZ, "can't open bgzip pcap file %s: %s", 
                        pcap_fname, strerror(errno));
                goto err;
            }
            c->pcap_fname = pcap_fname;
            break;
        case VERIFY:
            break;
        case EXTRACT:
            if (opt_parse_extract(opt, c) == -1)
            {
                memcpy(errbuf, c->errbuf, BUFSIZ);
                goto err;
            }
            if (bgzf_is_bgzf(pcap_fname) == 0)
            {
                snprintf(errbuf, BUFSIZ, "%s is not a bgzf compressed file\n",
                        pcap_fname);
                goto err;
            }
            c->pcap = bgzf_open(pcap_fname, "r");
            if (c->pcap == NULL)
            {
                snprintf(errbuf, BUFSIZ, "can't open bgzip pcap file %s: %s", 
                        pcap_fname, strerror(errno));
                goto err;
            }
            c->pcap_fname = pcap_fname;
            c->pcap_new = open(pcap_new_fname, O_WRONLY | O_CREAT | O_TRUNC, 
                                               S_IRUSR  | S_IWUSR | S_IRGRP | 
                                               S_IWGRP  | S_IROTH | S_IWOTH);
            if (c->pcap_new == -1)
            {
                snprintf(c->errbuf, BUFSIZ, "can't open pcap %s: %s",
                        strerror(errno), pcap_new_fname);
                goto err;
            }
            c->pcap_new_fname = pcap_new_fname;
            break;
        default:
            snprintf(errbuf, BUFSIZ, "unknown mode %d\n", mode);
            goto err;
    }
    /** every mode of the program will need an index file */
    if (index_open(index_fname, mode, c, errbuf) == -1)
    {
        goto err;
    }
    return c;
err:
    control_context_destroy(c);
    return NULL;
}

void
control_context_destroy(cppip_t *c)
{
    struct stat stat_buf;

    if (c->pcap)
    {
        bgzf_close(c->pcap);
    }
    if (c->index)
    {
        /** try to keep the file system clean and remove empty files */
        fstat(c->index, &stat_buf);
        if (stat_buf.st_size == 0)
        {
            unlink(c->index_fname);
        }
        close(c->index);
    }
    if (c->pcap_new)
    {
        close(c->pcap_new);
    }
    free(c);
    c = NULL;
}

/* EOF */
