/**
 * Compressed pcap packet indexing program (CPPIP)
 * util.c: utility routines
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
#include "../include/index_modes.h"
#include <ctype.h>

int
usage()
{
    printf("\nCompressed Pcap Packet Indexing Program\n");
    printf("(c) 2013 - 2014 Mike Schiffman\n");
    printf("Mike Schiffman <themikeschiffman@gmail.com>\n\n");
    printf("Fast compressed pcap indexing and extraction, made easy\n");
    printf("see https://github.com/mschiffm/cppip for complete documentation\n");
    printf("\nUsage: cppip [options] [file(s)...]\n");
    printf("\nIndexing:\n");
    printf(" -i index_mode:index_level index.cppip pcap.gz\n");
    printf("\t\t\tindex a bgzip compressed pcap.gz file using `index_mode`\n");
    printf("\t\t\tindex.cppip will be created or overwritten and packets\n");
    printf("\t\t\twill be indexed at every `index_level` mark.\n");
    printf("\t\t\tinvoke with -I for more information/help on indexing\n");
    printf(" -I\t\t\tprint supported index/extract modes/format guidelines\n");
    printf(" -v index.cppip\t\tverify index file\n");
    printf(" -d index.cppip\t\tdump index file\n");
    printf("\nExtracting:\n");
    printf(" -e index_mode:n|n-m index.cppip pcap.gz new.pcap\n");
    printf("\t\t\textract using `index_mode` the nth packet or n-m packets\n");
    printf("\t\t\tfrom pcap.gz into new.pcap\n");
    printf("\t\t\tinvoke with -I for more information/help on extracting\n");
    printf(" -f\t\t\tenable fuzzy matching (timestamp extraction only)\n");
    printf("\t\t\tthis is useful if you don't want to specify exact\n");
    printf("\t\t\toffsets\n");
    printf("\nGeneral Options:\n");
    printf(" -D\t\t\tenable debug messages\n");
    printf(" -V\t\t\tprogram version\n");
    printf(" -h\t\t\tthis message\n");

    return 1;
}

char *
lookup_index_mode(int mode)
{
    return index_modes[mode];
}

int
index_dump_modes()
{
    int i;

    fprintf(stderr, "\n");
    for (i = 0; index_help[i]; i++)
    {
        fprintf(stderr, "%s", index_help[i]);
    }
    
    return 1;
}


int
version()
{
    fprintf(stderr, "version: %d.%d.%d\n", CPPIP_VERSION_MAJOR, 
                                        CPPIP_VERSION_MINOR,
                                        CPPIP_VERSION_PATCH);
    return 1;
}


int
bgzf_skip(BGZF *f, int skip_bytes)
{
    for (; skip_bytes; skip_bytes--)
    {
        if (bgzf_getc(f) == -1)
        {
            return -1;
        }
    }
    return 1;
}

int
opt_parse_extract(char *opt_s, cppip_t *c)
{
    char *s, *q;
    int i, n;
    struct tm tm_s, tm_e;
    uint32_t year_s, mth_s, day_s, hr_s, min_s, sec_s, usec_s;
    uint32_t year_e, mth_e, day_e, hr_e, min_e, sec_e, usec_e;
    
    /** expects a string of the form: 
     *  "index_mode:{packetrange,daterange}\n\0"
     */

    q = strdup(opt_s);
    s = strsep(&opt_s, ":");
    if (s == NULL || opt_s == NULL)
    {
        snprintf(c->errbuf, BUFSIZ, "empty extract string\n");
        return -1;
    }

    /** validate the indexing mode */
    for (c->index_mode = -1, i = 0; index_modes[i]; i++)
    {
        if (strncmp(index_modes[i], s, strlen(index_modes[i])) == 0)
        {
            c->index_mode = index_types[i];
            break;
        }
    }
    if (c->index_mode == -1)
    {
        snprintf(c->errbuf, BUFSIZ, "invalid extract string: %s\n", q);
        free(q);
        return -1;
    }
    switch (c->index_mode)
    {
        case CPPIP_INDEX_PN:
            return pkt_range_check(opt_s, &(c->e_pkts.pkt_start), 
                        &(c->e_pkts.pkt_stop));
        case CPPIP_INDEX_TS:
            memset(&tm_s, 0, sizeof (struct tm));
            memset(&tm_e, 0, sizeof (struct tm));
            n = sscanf(opt_s, "%d-%d-%d:%d:%d:%d-%d-%d-%d:%d:%d:%d", 
                &tm_s.tm_year, &tm_s.tm_mon, &tm_s.tm_mday, 
                &tm_s.tm_hour, &tm_s.tm_min, &tm_s.tm_sec,
                &tm_e.tm_year, &tm_e.tm_mon, &tm_e.tm_mday, 
                &tm_e.tm_hour, &tm_e.tm_min, &tm_e.tm_sec);
            if (n != 12)
            {
                /** check if user supplied usec */
                n = sscanf(opt_s, "%d-%d-%d:%d:%d:%d.%d-%d-%d-%d:%d:%d:%d.%d", 
                    &tm_s.tm_year, &tm_s.tm_mon, &tm_s.tm_mday, 
                    &tm_s.tm_hour, &tm_s.tm_min, &tm_s.tm_sec, &usec_s,
                    &tm_e.tm_year, &tm_e.tm_mon, &tm_e.tm_mday, 
                    &tm_e.tm_hour, &tm_e.tm_min, &tm_e.tm_sec, &usec_e);
                c->e_pkts.ts_start.tv_usec = usec_s;
                c->e_pkts.ts_stop.tv_usec  = usec_e;
                if (n != 14)
                {
                    snprintf(c->errbuf, BUFSIZ, 
                            "invalid extract string: %s\n", q);
                free(q);
                return -1;
                }
            }
            /** tm structs index from 0 so adjust these (year is -1900) */
            tm_s.tm_hour -= 1;
            tm_e.tm_hour -= 1; 
            tm_s.tm_mon  -= 1; 
            tm_e.tm_mon  -= 1;
            tm_s.tm_year -= 1900;
            tm_e.tm_year -= 1900;
            c->e_pkts.ts_start.tv_sec = mktime(&tm_s);       
            c->e_pkts.ts_stop.tv_sec  = mktime(&tm_e);

            /** sanity check */
            if (timercmp(&c->e_pkts.ts_start, &c->e_pkts.ts_stop, >))
            {
                snprintf(c->errbuf, BUFSIZ, 
                "invalid extract string: start ts > stop ts (%s > %s)\n",
                ctime_usec(&c->e_pkts.ts_start), 
                ctime_usec(&c->e_pkts.ts_stop));
                return -1;
            }
    }
    return 1;
}


int
opt_parse_index(char *opt_s, cppip_t *c)
{
    int i;
    char *s, *q;

    /** expects a string of the form: "index_mode:index_level\n\0" */
    q = strdup(opt_s);
    s = strsep(&opt_s, ":");
    if (s == NULL || opt_s == NULL)
    {
        snprintf(c->errbuf, BUFSIZ, "empty index string\n");
        return -1;
    }

    /** validate the indexing mode */
    for (c->index_mode = -1, i = 0; index_modes[i]; i++)
    {
        if (strncmp(index_modes[i], s, strlen(index_modes[i])) == 0)
        {
            c->index_mode = index_types[i];
            break;
        }
    }
    if (c->index_mode == -1 || strlen(opt_s) < 1)
    {
        snprintf(c->errbuf, BUFSIZ, "invalid index string: %s\n", q);
        free(q);
        return -1;
    }
    switch (c->index_mode)
    {
        case CPPIP_INDEX_PN:
            for (i = 0; opt_s[i]; i++)
            {
                if (isdigit(opt_s[i]) == 0)
                {
                    snprintf(c->errbuf, BUFSIZ, "invalid index string: %s\n", 
                            q);
                    free(q);
                    return -1;
                }
            }
            c->index_level.num = strtol(opt_s, NULL, 10);
            break;
        case CPPIP_INDEX_TS:
            switch (opt_s[strlen(opt_s) - 1])
            {
                /** days */
                case 'd':
                    c->index_level.ts.tv_sec  = 60 * 60 * 24 * 
                                                strtol(opt_s, NULL, 10);
                    c->index_level.ts.tv_usec = 0;
                    break;
                /** hours */
                case 'h':
                    c->index_level.ts.tv_sec = 60 * 60 * 
                                               strtol(opt_s, NULL, 10);
                    c->index_level.ts.tv_usec = 0;
                    break;
                /** minutes */
                case 'm':
                    c->index_level.ts.tv_sec = 60 * strtol(opt_s, NULL, 10);
                    c->index_level.ts.tv_usec = 0;
                    break;
                /** seconds */
                case 's':
                    c->index_level.ts.tv_sec  = strtol(opt_s, NULL, 10);
                    c->index_level.ts.tv_usec = 0;
                    break;
                /** microseconds */
                case 'u': 
                    c->index_level.ts.tv_sec  = 0;
                    c->index_level.ts.tv_usec = strtol(opt_s, NULL, 10);
                    break;
                default:
                    snprintf(c->errbuf, BUFSIZ, 
                            "invalid index specifier: `%c`\n", 
                            opt_s[strlen(opt_s) - 1]);
                    free(q);
                    return -1;
            }
            break;
    }
    return 1;
}

char *
ctime_usec(struct timeval *ts)
{
    time_t time;
    struct tm *timetm;
    char *s, tmbuf[64];
    static uint32_t which;
    static char buf2[64];
    static char buf[64];

    which++;

    s = (which % 2) ? buf : buf2;

    time = ts->tv_sec;
    timetm = localtime(&time);
    strftime(tmbuf, sizeof (tmbuf), "%Y-%m-%d %H:%M:%S", timetm);
    snprintf(s, 64, "%s.%06d", tmbuf, ts->tv_usec);
    return s;
}

void
convert_timeval(struct timeval *ts, uint32_t *d, uint32_t *h, uint32_t *m,
uint32_t *s, uint32_t *u)
{
    int64_t d1, s1;

    d1 = floor(ts->tv_sec / 86400);
    s1 = ts->tv_sec - 86400 * d1;

    if (s1 < 0)
    {
        d1 -= 1;
        s1 += 86400;
    }

    *d = d1;
    *s = s1;

    *h = floor((*s) / 3600);
    *s -= 3600 * (*h);

    *m = floor((*s) / 60);
    *s -= 60 * (*m);

    *u = ts->tv_usec;
}

int
pkt_range_check(char *pkt_range, uint32_t *pkt_start, uint32_t *pkt_stop)
{
    uint8_t legal_tokens[] = "0123456789-";
    char buf[BUFSIZ], *p;
    int i, j, valid_token;

    /** ensure we have legal tokens, pkt_range needs to NULL terminated */
    for (i = 0; pkt_range[i]; i++)
    {
        for (j = 0, valid_token = 0; legal_tokens[j]; j++)
        {
            if (legal_tokens[j] == pkt_range[i])
            {
                valid_token = 1;
                break;
            }
        }
        if (!valid_token)
        {
            return -1;
        }
    }
    memset(&buf, 0, sizeof (buf));
    p = buf;

    /** still subject to some abuse, this works for most cases */
    *pkt_start = strtol(pkt_range, &p, 10);
    if (*pkt_start == 0)
    {
        return -1;
    }
    if (p[0] == '-')
    {
        p++;
        *pkt_stop = strtol(p, NULL, 10);
    }
    else
    {
        *pkt_stop = *pkt_start;
    }
    /** well that won't work! */
    if (*pkt_start > *pkt_stop)
    {
        return -1;
    }
    return 1;
}

/** EOF */
