/**
 * Compressed pcap packet indexing program (CPPIP)
 * verify.c: verification routines
 * Mike Schiffman <mschiffm@cisco.com>
 * March 2013
 */
#include "../include/cppip.h"

int
index_verify(cppip_t *c, int mode)
{
    int n;
    uint8_t type;
    struct stat stat_buf;

    /** sanity check */
    if (fstat(c->index, &stat_buf) == -1)
    {
        snprintf(c->errbuf, BUFSIZ, 
            "can't stat %s: %s\n", c->index_fname, strerror(errno));
        return (-1);
    }
    if (stat_buf.st_size <= CPPIP_FH_SIZ + CPPIP_INDEX_PN_H_SIZ + 
                            CPPIP_REC_PN_SIZ)
    {
        snprintf(c->errbuf, BUFSIZ, 
            "%s is too small to be a valid cppip index\n", c->index_fname);
        return (-1);
    }

    /** make sure we're at the beggining of the file and peel the header */
    lseek(c->index, 0L, SEEK_SET);
    
    if (read(c->index, &c->cppip_h, CPPIP_FH_SIZ) != CPPIP_FH_SIZ)
    {
        snprintf(c->errbuf, BUFSIZ, "read() error: %s\n", strerror(errno));
        return (-1);
    }

    if (c->cppip_h.magic != CPPIP_MAGIC)
    {
        snprintf(c->errbuf, BUFSIZ, 
            "bad magic: %0x. Is `%s` a cppip index file?\n", c->cppip_h.magic, 
            c->index_fname);
        return (-1);
    }

    /** iterate over file header options */
    for (n = c->cppip_h.hdr_size - (CPPIP_FH_SIZ / 4); n; )
    {
        /** we use peek-read so we don't have to rewind to read the header */
        if (pread(c->index, &type, 1, lseek(c->index, 0, SEEK_CUR)) == -1)
        {
            snprintf(c->errbuf, BUFSIZ, "read() error: %s\n", strerror(errno));
            return (-1);
        }
        switch (type)
        {
            case CPPIP_INDEX_PN:
                if (read(c->index, &c->cppip_index_pn_hdr, 
                    CPPIP_INDEX_PN_H_SIZ) != CPPIP_INDEX_PN_H_SIZ)
                {
                    snprintf(c->errbuf, BUFSIZ, "read() error: %s\n",
                        strerror(errno));
                    return (-1);
                }
                n -= CPPIP_INDEX_PN_H_SIZ / 4;
                if (n < 0)
                {
                    snprintf(c->errbuf, BUFSIZ, 
                        "header size mismatch: %d\n", n);
                    return (-1);
                }
                break;
            case CPPIP_INDEX_TS:
                if (read(c->index, &c->cppip_index_ts_hdr, 
                    CPPIP_INDEX_TS_H_SIZ) != CPPIP_INDEX_TS_H_SIZ)
                {
                    snprintf(c->errbuf, BUFSIZ, "read() error: %s\n",
                        strerror(errno));
                    return (-1);
                }
                n -= CPPIP_INDEX_TS_H_SIZ / 4;
                if (n < 0)
                {
                    snprintf(c->errbuf, BUFSIZ, 
                        "header size mismatch: %d\n", n);
                    return (-1);
                }
                break;
            default:
                snprintf(c->errbuf, BUFSIZ, 
                    "unknown index mode: %d\n", type);
                return (-1);
        }
    }
    if (mode & V_DETAILED)
    {
        index_print_info(c, type);
    }
    if (mode & V_DUMP)
    {
        return (index_dump(c, type));
    }
    return (1);
}


/** EOF */
