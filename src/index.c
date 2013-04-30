/**
 * Compressed pcap packet indexing program (CPPIP)
 * index.c: index creation routines
 * Mike Schiffman <mschiffm@cisco.com>
 * March 2013
 */
#include "../include/cppip.h"


/** XXX this whole module needs a lot of clean up and optimization */

int
index_dump(cppip_t *c, int mode)
{
    int i, n;
    char time_buf[27];
    cppip_record_pn_t rec_pn;
    cppip_record_ts_t rec_ts;

    switch (mode)
    {
        case CPPIP_INDEX_PN:
            for (i = 0; (n = read(c->index, &rec_pn, CPPIP_REC_PN_SIZ)); i++)
            {
                if (n == -1)
                {
                    snprintf(c->errbuf, BUFSIZ, "read() error: %s\n",
                            strerror(errno));
                    return (-1);
                }
                printf("pkt num:%d\n", rec_pn.pkt_num);
                printf("offset: %llx\n", rec_pn.bgzf_offset);
            }
            break;
        case CPPIP_INDEX_TS:
            for (i = 0; (n = read(c->index, &rec_ts, CPPIP_REC_TS_SIZ)); i++)
            {
                if (n == -1)
                {
                    snprintf(c->errbuf, BUFSIZ, "read() error: %s\n",
                            strerror(errno));
                    return (-1);
                }
                printf("timestamp:\t%s\n", ctime_usec(&rec_ts.pkt_ts));
                printf("offset:\t\t%llx\n", rec_ts.bgzf_offset);
            }
            break;
    }
    return (1);
}


void
index_print_info(cppip_t *c, int mode)
{
    uint32_t d, h, m, s, u;

    printf("valid cppip index file\n");
    printf("version:\t%d.%d\n", c->cppip_h.version_major,
                                         c->cppip_h.version_minor);
    printf("created:\t%s\n", ctime_usec(&c->cppip_h.ts_created));
    printf("packets in pcap:%d\n", c->cppip_h.pkt_cnt);
    
    switch (mode)
    {
        case CPPIP_INDEX_PN:
            printf("indexing mode:\tpacket-number\n");
            printf("index level:\t%d\n", c->cppip_index_pn_hdr.index_level);
            printf("record count:\t%d\n", c->cppip_index_pn_hdr.rec_cnt);
            break;
        case CPPIP_INDEX_TS:
            printf("indexing mode:\ttimestamp\n");
            convert_timeval(&c->cppip_index_ts_hdr.index_level, 
                &d, &h, &m, &s, &u);
            //printf("index level:\t%d:%d:%d:%d:%d\n", d, h, m, s, u);
            printf("index level:\t%d:%d:%d:%d\n", d, h, m, s);
            printf("record count:\t%d\n", c->cppip_index_ts_hdr.rec_cnt);
            break;
    }
}

int
index_dispatch(cppip_t *c)
{
    switch (c->index_mode)
    {
        case CPPIP_INDEX_PN:
            /** ensure index_level is valid */
            if (c->index_level.num <= 0)
            {
                snprintf(c->errbuf, BUFSIZ, "index_level too small: %d\n", 
                c->index_level.num);
                return (-1);
            }
            return (index_create(c));
        case CPPIP_INDEX_TS:
            return (index_create(c));
        default:
            snprintf(c->errbuf, BUFSIZ, "unknown packet indexing mode: %d\n", 
                c->index_mode);
            return (-1);
    }
}


int 
index_open(char *index_fname, int mode, cppip_t *c, char *errbuf)
{
    switch (mode)
    {
        case INDEX:
            c->index = open(index_fname, O_RDWR   | O_CREAT | O_TRUNC, 
                                         S_IRUSR  | S_IWUSR | S_IRGRP | 
                                         S_IWGRP  | S_IROTH | S_IWOTH);
            if (c->index == -1)
            {
                snprintf(errbuf, BUFSIZ, "can't create index file %s: %s\n",
                    strerror(errno), index_fname);
            }
            break;
        case DUMP:
        case EXTRACT:
        case VERIFY:
            c->index = open(index_fname, O_RDWR);
            if (c->index == -1)
            {
                snprintf(errbuf, BUFSIZ, "can't open index file %s: %s\n",
                    strerror(errno), index_fname);
            }
            break;
        default:
            snprintf(errbuf, BUFSIZ, "unknown mode: %d\n", mode);
            return (-1);
    }
    c->index_fname = index_fname;
    return (c->index);
}

int
index_create(cppip_t *c)
{
    int n;
    cppip_file_hdr_t cppip_hdr;
    off_t cppip_hdr_index_pn_offset;
    off_t cppip_hdr_index_ts_offset;
    cppip_index_pn_hdr_t cppip_hdr_index_pn;
    cppip_index_ts_hdr_t cppip_hdr_index_ts;

    /** build/write cppip file header */
    if (gettimeofday(&cppip_hdr.ts_created, NULL) == -1)
    {
        snprintf(c->errbuf, BUFSIZ, "gettimeofday(): %s", strerror(errno));
        return (-1);
    }
    cppip_hdr.magic         = CPPIP_MAGIC;
    cppip_hdr.version_major = CPPIP_VERSION_MAJOR;
    cppip_hdr.version_minor = CPPIP_VERSION_MINOR;
    cppip_hdr.index_mode    = c->index_mode;
    cppip_hdr.hdr_size      = CPPIP_FH_SIZ / 4;

    /** prepare index record headers */
    if ((c->index_mode) & CPPIP_INDEX_PN)
    {
        cppip_hdr.hdr_size += (CPPIP_INDEX_PN_H_SIZ / 4);
        memset(&cppip_hdr_index_pn, 0, CPPIP_INDEX_PN_H_SIZ);
    }
    if ((c->index_mode) & CPPIP_INDEX_TS)
    {
        cppip_hdr.hdr_size += (CPPIP_INDEX_TS_H_SIZ / 4);
        memset(&cppip_hdr_index_ts, 0, CPPIP_INDEX_TS_H_SIZ);
    }
    if (write(c->index, &cppip_hdr, CPPIP_FH_SIZ) == -1)
    {
        snprintf(c->errbuf, BUFSIZ, "write() error: %s", strerror(errno));
        return (-1);
    }
    /** 
     *  Write index headers -- as placeholders for now, fill in the goods
     *  shortly when we have the data we need. To do this we'll save the
     *  position of the file pointer via lseek() and re-write the header again
     *  later, this time with the data. Seems inefficient, wam -- better idea?
     */
    if ((c->index_mode) & CPPIP_INDEX_PN)
    {
        cppip_hdr_index_pn_offset = lseek(c->index, 0, SEEK_CUR);
        if (cppip_hdr_index_pn_offset == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "lseek(): %s", strerror(errno));
            return (-1);
        }
        if (write(c->index, &cppip_hdr_index_pn, CPPIP_INDEX_PN_H_SIZ) == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "write() error: %s", strerror(errno));
            return (-1);
        }
    }
    if ((c->index_mode) & CPPIP_INDEX_TS)
    {
        cppip_hdr_index_ts_offset = lseek(c->index, 0, SEEK_CUR);
        if (cppip_hdr_index_ts_offset == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "lseek(): %s", strerror(errno));
            return (-1);
        }
        if (write(c->index, &cppip_hdr_index_ts, CPPIP_INDEX_TS_H_SIZ) == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "write() error: %s", strerror(errno));
            return (-1);
        }
    }

    /** skip past the pcap file header of pcap we're indexing */
    if (bgzf_skip(c->pcap, 24) == -1)
    {
        snprintf(c->errbuf, BUFSIZ, "bgzf_skip() error\n");
        return (-1);
    }

    /** handle packet number index header and data */
    if ((c->index_mode) & CPPIP_INDEX_PN)
    {
        n = index_by_pn(c);
        if (n == -1)
        {
            return (-1);
        }
        cppip_hdr_index_pn.index_mode    = CPPIP_INDEX_PN;
        cppip_hdr_index_pn.reserved1     = 0;
        cppip_hdr_index_pn.reserved2     = 0;
        cppip_hdr_index_pn.rec_cnt       = n;
        cppip_hdr_index_pn.index_level   = c->index_level.num;

        lseek(c->index, cppip_hdr_index_pn_offset, SEEK_SET);
        if (write(c->index, &cppip_hdr_index_pn, 
                        CPPIP_INDEX_PN_H_SIZ) == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "write() error: %s", strerror(errno));
            return (-1);
        }
        /** XXX clean this up */
        cppip_hdr.pkt_cnt = c->cppip_h.pkt_cnt;
        lseek(c->index, 0, SEEK_SET);
        write(c->index, &cppip_hdr, CPPIP_FH_SIZ);
    }
    if ((c->index_mode) & CPPIP_INDEX_TS)
    {
        n = index_by_ts(c);
        if (n == -1)
        {
            return (-1);
        }
        cppip_hdr_index_ts.index_mode    = CPPIP_INDEX_TS;
        cppip_hdr_index_ts.reserved1     = 0;
        cppip_hdr_index_ts.reserved2     = 0;
        cppip_hdr_index_ts.rec_cnt       = n;
        cppip_hdr_index_ts.index_level.tv_sec  = c->index_level.ts.tv_sec;
        cppip_hdr_index_ts.index_level.tv_usec = c->index_level.ts.tv_usec;

        lseek(c->index, cppip_hdr_index_ts_offset, SEEK_SET);
        if (write(c->index, &cppip_hdr_index_ts, 
                        CPPIP_INDEX_TS_H_SIZ) == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "write() error: %s", strerror(errno));
            return (-1);
        }
        /** XXX clean this up */
        cppip_hdr.pkt_cnt = c->cppip_h.pkt_cnt;
        lseek(c->index, 0, SEEK_SET);
        write(c->index, &cppip_hdr, CPPIP_FH_SIZ);
    }
    return (n);
}

int
index_by_pn(cppip_t *c)
{
    int done, rec_cnt;
    uint32_t pkt_cnt;
    uint64_t offset;
    uint8_t buf[BUFSIZ * 2];
    cppip_record_pn_t cppip_rec;
    pcap_offline_pkthdr_t *pcap_h;

    memset(&buf, 0, sizeof (buf));
    for (rec_cnt = 0, pkt_cnt = 1, done = 0; !done; pkt_cnt++)
    {
        /**  ...[pcap packet header][packet]...
         *      ^
         *      bgzf fp is pointing here, the BGZF offset to this 
         *      packet.. This is
         *      the offset we will record in our index
         */
        offset = bgzf_tell(c->pcap);
        switch (bgzf_read(c->pcap, buf, PCAP_PKTH_SIZ))
        {
            case -1:
                snprintf(c->errbuf, BUFSIZ, "bgzf_read() error\n");
                return (-1);
            case 0:
                /* all done */
                done = 1;
                break;
            default:
                pcap_h = (pcap_offline_pkthdr_t *)buf;
                /** write first packet then write as per index_level */
                if (pkt_cnt == 1 || pkt_cnt % c->index_level.num == 0)
                {
                    cppip_rec.pkt_num     = pkt_cnt;
                    cppip_rec.bgzf_offset = offset;
                    if (write(c->index, &cppip_rec, CPPIP_REC_PN_SIZ) == -1)
                    {
                        snprintf(c->errbuf, BUFSIZ, "write(): %s", 
                                strerror(errno));
                        return (-1);
                    }
                    rec_cnt++;
                    if (c->flags & CPPIP_CTRL_DEBUG)
                    {
                        fprintf(stderr, "DBG: add> [%d]: %d @ %llx\n",
                                rec_cnt, pkt_cnt, offset);
                    }
                }
                /** 
                 *  we don't care about the contents -- we skip past the 
                 *  packet
                 */
                if (bgzf_skip(c->pcap, pcap_h->caplen) == -1)
                {
                    snprintf(c->errbuf, BUFSIZ, "bgzf_skip() error\n");
                    return (-1);
                }
        }
    }
    if (rec_cnt == 0)
    {
        snprintf(c->errbuf, BUFSIZ, 
                "wrote 0 records, index_level too large for this pcap?\n");
        return (-1);
    }
    c->cppip_h.pkt_cnt = pkt_cnt;
    return (rec_cnt);
}

int
index_by_ts(cppip_t *c)
{
    int pkt_cnt, done, rec_cnt;
    uint64_t offset;
    uint8_t buf[BUFSIZ * 2];
    cppip_record_ts_t cppip_rec;
    pcap_offline_pkthdr_t *pcap_h;
    struct timeval ts_dif, ts_prev;

    memset(&buf, 0, sizeof (buf));
    memset(&ts_prev, 0, sizeof (struct timeval));
    for (rec_cnt = 0, pkt_cnt = 1, done = 0; !done; pkt_cnt++)
    {
        /**  ...[pcap packet header][packet]...
         *      ^
         *      bgzf fp is pointing here, the BGZF offset to this 
         *      packet.. This is
         *      the offset we will record in our index
         */
        offset = bgzf_tell(c->pcap);
        switch (bgzf_read(c->pcap, buf, PCAP_PKTH_SIZ))
        {
            case -1:
                snprintf(c->errbuf, BUFSIZ, "bgzf_read() error\n");
                return (-1);
            case 0:
                /* all done */
                done = 1;
                break;
            default:
                pcap_h = (pcap_offline_pkthdr_t *)buf;
                cppip_rec.pkt_ts.tv_sec  = pcap_h->tv_sec;
                cppip_rec.pkt_ts.tv_usec = pcap_h->tv_usec;

                /**
                 *  we want to check if: ts(pkt_cur) - ts(pkt_prev) > index
                 *  we'll always write at least the first packet to the index
                 */
                timersub(&cppip_rec.pkt_ts, &ts_prev, &ts_dif);

                /** write to the index as per index */
                if (timercmp(&ts_dif, &c->index_level.ts, >))
                {
                    cppip_rec.bgzf_offset = offset;
                    if (write(c->index, &cppip_rec, CPPIP_REC_TS_SIZ) == -1)
                    {
                        snprintf(c->errbuf, BUFSIZ, "write(): %s",
                                strerror(errno));
                        return (-1);
                    }
                    rec_cnt++;
                    if (c->flags & CPPIP_CTRL_DEBUG)
                    {
                        fprintf(stderr, "DBG: add> [%d]: %s @ %llx\n", rec_cnt, 
                                ctime_usec(&cppip_rec.pkt_ts), offset);
                    }

                    /** remember the last written packet's timestamp */
                    memcpy(&ts_prev, &cppip_rec.pkt_ts, 
                        sizeof (struct timeval));
                }
                /** 
                 *  we don't care about the contents -- we skip past the 
                 *  packet
                 */
                if (bgzf_skip(c->pcap, pcap_h->caplen) == -1)
                {
                    snprintf(c->errbuf, BUFSIZ, "bgzf_skip() error\n");
                    return (-1);
                }
        }
    }
    c->cppip_h.pkt_cnt = pkt_cnt;
    return (rec_cnt);
}

/** EOF */
