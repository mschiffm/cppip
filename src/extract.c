/**
 * Compressed pcap packet indexing program (CPPIP)
 * extract.c: extraction routines
 *
 * Copyright (c) 2013 - 2014, Mike Schiffman <themikeschiffman@gmail.com>
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

/** XXX this whole thing is a mess and needs a re-write */

int
extract(cppip_t *c)
{
    uint8_t buf[BUFSIZ];

    /** extract and write original pcap file header to new pcap */
    if (bgzf_read(c->pcap, buf, 24) != 24)
    {
        snprintf(c->errbuf, BUFSIZ, "bgzf_read() error: can't read pcap\n");
        return (-1);
    }
    if (write(c->pcap_new, buf, 24) != 24)
    {
        snprintf(c->errbuf, BUFSIZ, "write() error: %s\n", strerror(errno));
        return (-1);
    }

    switch (c->index_mode)
    {
        case CPPIP_INDEX_PN:
            return (extract_by_pn(c));
        case CPPIP_INDEX_TS:
            return (extract_by_ts(c));
        default:
            snprintf(c->errbuf, BUFSIZ, "unknown extract mode\n");
            return (-1);
    }
    return (1);
}

int
extract_by_pn(cppip_t *c)
{
    cppip_record_pn_t rec;
    cppip_index_pn_hdr_t *pn_h;
    uint32_t i, j, pkt_caplen;
    pcap_offline_pkthdr_t pcap_h;
    uint8_t buf[BUFSIZ * 2], buf2[BUFSIZ * 2 + 16];


    /** sanity check only checks stop, we verified earlier stop > start */
    if (c->e_pkts.pkt_stop  > c->cppip_h.pkt_cnt)
    {
        snprintf(c->errbuf, BUFSIZ, 
            "extraction would exceed packet count, %d and/or %d > %d\n", 
            c->e_pkts.pkt_start, c->e_pkts.pkt_stop, c->cppip_h.pkt_cnt);
        return (-1);
    }

    /** 
     * We need to locate the offset of pkt_start and then we can 
     * extract in a linear fashion until we hit pkt_last.
     */

    /** 
     * If the indexing is too coarse the pkt_start will lie before the 
     * first index. If this is the case we have to do a linear search from
     * the very first packet until we find pkt_first...
     */
    if (c->e_pkts.pkt_start < c->cppip_index_pn_hdr.index_level)
    {
        if (linear_search(c, 1, c->e_pkts.pkt_start) == -1)
        {
            return (-1);
        }
    }
    /** seek to index, obtain closest offset, linear search from there */
    else
    {
        /** 
         * pkt_start / index_level will give us the closest index record to our
         * starting packet. We lseek to 1 before this location so we don't
         * step past the record we need.
         */
        if (lseek(c->index, 
            (((c->e_pkts.pkt_start / c->cppip_index_pn_hdr.index_level) - 1)
            * CPPIP_REC_PN_SIZ) + CPPIP_FH_SIZ + CPPIP_INDEX_PN_H_SIZ, 
            SEEK_SET) == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "lseek() error: %s\n", strerror(errno));
            return (-1);
        }
        if (read(c->index, (cppip_record_pn_t *)&rec, CPPIP_REC_PN_SIZ) 
            != CPPIP_REC_PN_SIZ)
        {
            snprintf(c->errbuf, BUFSIZ, "read() error: %s\n", strerror(errno));
            return (-1);
        }
        if (bgzf_seek(c->pcap, rec.bgzf_offset, SEEK_SET) == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "bgzf_seek() error.\n");
            return (-1);
        }
        if (linear_search(c, rec.pkt_num, c->e_pkts.pkt_start) == -1)
        {
            return (-1);
        }
    }
    /** we've got pkt_first, do extraction until we hit pkt_last */
    for (c->e_pkts.pkts_w = 0, i = c->e_pkts.pkt_start; 
            i < (c->e_pkts.pkt_stop + 1); i++, c->e_pkts.pkts_w++)
    {
        if (bgzf_read(c->pcap, (pcap_offline_pkthdr_t *)&pcap_h, PCAP_PKTH_SIZ)
            != PCAP_PKTH_SIZ)
        {
            snprintf(c->errbuf, BUFSIZ, 
                "bgzf_read() error: cant read pcap hdr\n");
            return (-1);
        }
        pkt_caplen = pcap_h.caplen;
        if (bgzf_read(c->pcap, buf, pkt_caplen) != pkt_caplen)
        {
            snprintf(c->errbuf, BUFSIZ, 
                "bgzf_read() error: can't read packet\n");
            return (-1);
        }
        memcpy(&buf2, &pcap_h, PCAP_PKTH_SIZ);
        memcpy(&buf2[PCAP_PKTH_SIZ], &buf, pkt_caplen);
        if (write(c->pcap_new, buf2, PCAP_PKTH_SIZ + pkt_caplen) != 
                PCAP_PKTH_SIZ + pkt_caplen)
        {
            snprintf(c->errbuf, BUFSIZ, "write() error: %s\n", strerror(errno));
            return (-1);
        }
    }
    return (1);
}

int
linear_search(cppip_t *c, int start, int pkt_start)
{
    int i;
    pcap_offline_pkthdr_t pcap_h;

    if (c->flags & CPPIP_CTRL_DEBUG)
    {
        fprintf(stderr, "DBG: entered at pkt num:\t%d\n", start);
    }
    for (i = start; i < pkt_start; i++)
    {
        if (bgzf_read(c->pcap, (pcap_offline_pkthdr_t *)&pcap_h, 
                PCAP_PKTH_SIZ) != PCAP_PKTH_SIZ)
        {
            snprintf(c->errbuf, BUFSIZ, 
                "bgzf_read() error: cant read pcap hdr\n");
            return (-1);
        }

        /** skip past the packet */
        if (bgzf_skip(c->pcap, pcap_h.caplen) == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "bgzf_skip() error.\n");
            return (-1);
        }
    }
    if (c->flags & CPPIP_CTRL_DEBUG)
    {
        fprintf(stderr, "DBG: match at iteration:\t%d\n", i);
    }
    return (1);
}

int
extract_by_ts(cppip_t *c)
{
    int n;
    cppip_record_ts_t rec;
    cppip_index_ts_hdr_t *ts_h;
    uint32_t i, pkt_caplen;
    pcap_offline_pkthdr_t pcap_h;
    uint8_t buf[BUFSIZ * 2], buf2[BUFSIZ * 2 + 16];
    struct timeval cur;
    uint32_t mul, dif;

    /**
     * start ts: timestamp of the packet to start the extraction
     * stop ts:  timestamp of the packet to stop the extraction
     * first ts: timestamp of the first packet in the pcap.gz
     */

    /** 
     * Read the first entry in the index file and obtain first timestamp so
     * we have a frame of reference to work with... 
     */
    if (read(c->index, (cppip_record_ts_t *)&rec, CPPIP_REC_TS_SIZ) 
        != CPPIP_REC_TS_SIZ)
    {
        snprintf(c->errbuf, BUFSIZ, "read() error: %s\n", strerror(errno));
        return (-1);
    }
    if (c->flags & CPPIP_CTRL_DEBUG)
    {
        fprintf(stderr, "DBG: first pkt ts:\t\t(%ld) %s\n",
                rec.pkt_ts.tv_sec, ctime_usec(&rec.pkt_ts));
        fprintf(stderr, "DBG: start pkt ts:\t\t(%ld) %s\n", 
                c->e_pkts.ts_start.tv_sec, ctime_usec(&c->e_pkts.ts_start)); 
        fprintf(stderr, "DBG: stop pkt ts\t\t(%ld) %s\n", 
                c->e_pkts.ts_stop.tv_sec, ctime_usec(&c->e_pkts.ts_stop));
        fprintf(stderr, "DBG: index level:\t\t%ld %u\n", 
                c->cppip_index_ts_hdr.index_level.tv_sec, 
                (uint32_t)c->cppip_index_ts_hdr.index_level.tv_usec);
    }
    if (!(c->flags & CPPIP_CTRL_TS_FM))
    {
        /** 
         * sanity check if we're not fuzzy matching:
         * We already know stop ts > start ts --
         * make sure start ts > first ts.
         */
        if (timercmp(&c->e_pkts.ts_start, &rec.pkt_ts, <))
        {
            snprintf(c->errbuf, BUFSIZ, 
                "start timestamp < first packet's timestamp (%s < %s)\n",
                ctime_usec(&c->e_pkts.ts_start), ctime_usec(&rec.pkt_ts));
            return (-1);
        }
    }

    /**
     * subtract first packet's ts from the starting packet's ts to obtain a
     * differential which we then divide by the index_level to obtain
     * a multiplier to use to advance to the correct packet.
     *
     * Currently all of this only works for second level resolution.
     */
    dif = c->e_pkts.ts_start.tv_sec - rec.pkt_ts.tv_sec;
    mul = dif / c->cppip_index_ts_hdr.index_level.tv_sec;
    mul = (mul == 0 ? 1 : mul);

    if (mul > c->cppip_index_ts_hdr.rec_cnt)
    {
        snprintf(c->errbuf, BUFSIZ, 
        "tried to seek too many records (%d > %d) start ts too far in future for %s?\n", mul, c->cppip_index_ts_hdr.rec_cnt, c->pcap_fname);
        return (-1);
    }
    if (c->flags & CPPIP_CTRL_DEBUG)
    {
        fprintf(stderr, "DBG: difference:\t\t(%ld - %ld) is %u\n", 
                c->e_pkts.ts_start.tv_sec, rec.pkt_ts.tv_sec, dif);
        fprintf(stderr, "DBG: multiplier:\t\t%d\n", mul);
    }
    /** seek to index, obtain closest offset, linear search from there */
    if (lseek(c->index, (mul * CPPIP_REC_TS_SIZ) + CPPIP_FH_SIZ,
                SEEK_SET) == -1)
    {
        snprintf(c->errbuf, BUFSIZ, "lseek() error: %s\n", strerror(errno));
        return (-1);
    }
    if (read(c->index, (cppip_record_ts_t *)&rec, CPPIP_REC_TS_SIZ) 
                != CPPIP_REC_TS_SIZ)
    {
        snprintf(c->errbuf, BUFSIZ, "read() error: %s\n", strerror(errno));
        return (-1);
    }
    if (c->flags & CPPIP_CTRL_DEBUG)
    {
        fprintf(stderr, "DBG: pkt ts:\t\t\t%s\n", ctime_usec(&rec.pkt_ts));
        fprintf(stderr, "DBG: pkt off:\t\t\t%llx\n", rec.bgzf_offset);
    }
    if (bgzf_seek(c->pcap, rec.bgzf_offset, SEEK_SET) == -1)
    {
        snprintf(c->errbuf, BUFSIZ, "bgzf_seek() error.\n");
        return (-1);
    }
    /** linear search will return with the first packet we need to write */
    n = linear_search_ts(c, &c->e_pkts.ts_start, &pcap_h);
    switch (n)
    {
        case -1:
            return (-1);
        case 2:
            cur.tv_sec  = pcap_h.tv_sec;
            cur.tv_usec = pcap_h.tv_usec;
            fprintf(stderr, 
                    "start ts: %s not found, instead fuzzy matched on %s\n",
                    ctime_usec(&c->e_pkts.ts_start), ctime_usec(&cur));
        default:
            break;
    }
    if (bgzf_read(c->pcap, buf, pcap_h.caplen) != pcap_h.caplen)
    {
        snprintf(c->errbuf, BUFSIZ, "bgzf_read() error: can't read packet\n");
        return (-1);
    }

    memcpy(&buf2, &pcap_h, PCAP_PKTH_SIZ);
    memcpy(&buf2[PCAP_PKTH_SIZ], &buf,  pcap_h.caplen);
    if (write(c->pcap_new, buf2, PCAP_PKTH_SIZ + pcap_h.caplen) 
            != PCAP_PKTH_SIZ + pcap_h.caplen)
    {
        snprintf(c->errbuf, BUFSIZ, "write() error: %s\n", strerror(errno));
        return (-1);
    }

    cur.tv_sec  = 0;
    cur.tv_usec = 0;
    for (c->e_pkts.pkts_w = 1; timercmp(&c->e_pkts.ts_stop, &cur, !=); 
                c->e_pkts.pkts_w++)
    {
        if (bgzf_read(c->pcap, (pcap_offline_pkthdr_t *)&pcap_h, PCAP_PKTH_SIZ)
                != PCAP_PKTH_SIZ)
        {
            if (bgzf_check_EOF(c->pcap))
            {
                snprintf(c->errbuf, BUFSIZ, 
                        "bgzf_read(): hit EOF, stop ts: %s not found\n",
                        ctime_usec(&c->e_pkts.ts_stop));
                return (-1);
            }
            snprintf(c->errbuf, BUFSIZ, 
                "bgzf_read() error: cant read pcap hdr\n");
            return (-1);
        }
        /** if fuzzy matching is enabled, find the closest possible stop ts */
        if (c->flags & CPPIP_CTRL_TS_FM)
        {
            if timercmp(&c->e_pkts.ts_stop, &cur, <)
            {
                fprintf(stderr, 
                    "stop ts: %s not found, instead fuzzy matched on %s\n",
                    ctime_usec(&c->e_pkts.ts_stop), ctime_usec(&cur));
                break;
            }
        }
        pkt_caplen = pcap_h.caplen;
        if (bgzf_read(c->pcap, buf, pkt_caplen) != pkt_caplen)
        {
            snprintf(c->errbuf, BUFSIZ, 
                "bgzf_read() error: can't read packet\n");
            return (-1);
        }
        memcpy(&buf2, &pcap_h, PCAP_PKTH_SIZ);
        memcpy(&buf2[PCAP_PKTH_SIZ], &buf, pkt_caplen);
        if (write(c->pcap_new, buf2, PCAP_PKTH_SIZ + pkt_caplen) != 
                PCAP_PKTH_SIZ + pkt_caplen)
        {
            snprintf(c->errbuf, BUFSIZ, "write() error: %s\n", strerror(errno));
            return (-1);
        }
        cur.tv_sec  = pcap_h.tv_sec;
        cur.tv_usec = pcap_h.tv_usec;
    }
    
    return (1);
}

int
linear_search_ts(cppip_t *c, struct timeval *ts_start, 
        pcap_offline_pkthdr_t *pcap_h)
{
    int i;
    struct timeval cur;

    if (c->flags & CPPIP_CTRL_DEBUG)
    {
        fprintf(stderr, "DBG: entered at pkt ts:\t\t%s\n", 
                ctime_usec(ts_start));
    }
    for (i = 1; i ; i++)
    {
        if (bgzf_read(c->pcap, (pcap_offline_pkthdr_t *)pcap_h, PCAP_PKTH_SIZ) 
            != PCAP_PKTH_SIZ)
        {
            /** if we get here we ran out of file without finding a match */
            if (bgzf_check_EOF(c->pcap))
            {
                snprintf(c->errbuf, BUFSIZ, 
                        "bgzf_read(): hit EOF, start ts not found\n");
                return (-1);
            }
            snprintf(c->errbuf, BUFSIZ, 
                "bgzf_read() error: cant read pcap hdr\n");
            return (-1);
        }
        cur.tv_sec  = pcap_h->tv_sec;
        cur.tv_usec = pcap_h->tv_usec;
        /** check for match */
        if (timercmp(ts_start, &cur, ==))
        {
            if (c->flags & CPPIP_CTRL_DEBUG)
            {
                fprintf(stderr, "DBG: match at iteration:\t%d\n", i);
            }
            return (1);
        }
        /** check to see if current ts has exceed start ts */
        if (timercmp(ts_start, &cur, <))
        {
            /** if fuzzy matching enabled, we'll use this timestamp */
            if (c->flags & CPPIP_CTRL_TS_FM)
            {
                if (c->flags & CPPIP_CTRL_DEBUG)
                {
                    fprintf(stderr, "DBG: fuzzy match at iteration:\t%d\n", i);
                }
                /** at some point we should inform the user we made a FM */
                return (2);
            }
            snprintf(c->errbuf, BUFSIZ, 
                "%s not found, closest is %s (try -f)\n",
                ctime_usec(ts_start), ctime_usec(&cur));
            return (-1);
        }
        /** skip past the packet */
        if (bgzf_skip(c->pcap, pcap_h->caplen) == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "bgzf_skip() error.\n");
            return (-1);
        }
    }
    return (1);
}


/** EOF */
