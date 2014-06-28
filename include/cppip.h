/**
 * Compressed pcap packet indexing program (CPPIP)
 * cppip.h: interface
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

#ifndef CPPIP_H
#define CPPIP_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include "bgzf.h"

/** mode symbolics */
#define INDEX         0x01
#define INDEX_DISPLAY 0x03
#define EXTRACT       0x05
#define VERIFY        0x06
#define DUMP          0x07

#define V_DETAILED    0x01
#define V_DUMP        0x02

#define CPPIP_VERSION_MAJOR  1
#define CPPIP_VERSION_MINOR  3

/**
 * Pcap savefiles utilize 16-byte headers. However, depending on the OS, the
 * struct pcap_pkthdr may support 64-bit tv_sec in struct timeval or even 
 * have additional cruft after len. The result is we can't rely on the
 * OS-supplied pcap_pkthdr for a cast as it might not be 16 bytes. We
 * declare one here.
 */ 
struct pcap_offline_pkthdr
{
    uint32_t tv_sec;
    uint32_t tv_usec;
    uint32_t caplen;
    uint32_t len;
};
typedef struct pcap_offline_pkthdr pcap_offline_pkthdr_t;
#define PCAP_PKTH_SIZ sizeof(struct pcap_offline_pkthdr)

/*
 * File Header:
 *
 *   0                   1                   2                   3   
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Magic Number                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Maj Version  |  Min Version  |  Index Mode   |  Header Size  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                          Packet Count                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Index Creation Timestamp                   |
 *  |                                                               |
 *  |                                                               |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct cppip_file_hdr
{
    uint32_t magic;            /** magic number (poached at random) */
#define CPPIP_MAGIC   0xa1b2c3ff
    uint8_t version_major;     /** major version number */
    uint8_t version_minor;     /** minor version number */
    uint8_t index_mode;        /** index mode(s) */
#define CPPIP_INDEX_PN  0x01   /** indexed by packet number */
#define CPPIP_INDEX_TS  0x02   /** indexed by packet timestamp */
    uint8_t hdr_size;          /** number of 32 bit words ala IPv4 */
    uint32_t pkt_cnt;          /** number of packets in pcap.gz */
    struct timeval ts_created; /** timestamp of when this index was created */
    /** should add endian info */
};
typedef struct cppip_file_hdr cppip_file_hdr_t;
#define CPPIP_FH_SIZ sizeof(struct cppip_file_hdr)

/* 
 *  Packet Number Index Header:
 *
 *   0                   1                   2                   3   
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Index Type   |   Reserved    |           Reserved            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                          Record Count                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           Index Level                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct cppip_index_pn_hdr
{
    uint8_t  index_mode;        /** index mode as defined above */
    uint8_t  reserved1;         /** future growth */
    uint16_t reserved2;         /** future growth */
    uint32_t rec_cnt;           /** number of records */
    uint32_t index_level;       /** indexing level */
};
typedef struct cppip_index_pn_hdr cppip_index_pn_hdr_t;
#define CPPIP_INDEX_PN_H_SIZ sizeof(struct cppip_index_pn_hdr)

/*
 *  Timestamp Index Header:
 *
 *   0                   1                   2                   3   
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Index Type   |   Reserved    |           Reserved            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                          Record Count                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Timestamp Index Level                    |
 *  |                                                               |
 *  |                                                               |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
struct cppip_index_ts_hdr
{
    uint8_t  index_mode;        /** index mode as defined above */
    uint8_t  reserved1;         /** future growth */
    uint16_t reserved2;         /** future growth */
    uint32_t rec_cnt;           /** number of records */
    struct timeval index_level; /** indexing level */
};
typedef struct cppip_index_ts_hdr cppip_index_ts_hdr_t;
#define CPPIP_INDEX_TS_H_SIZ sizeof(struct cppip_index_ts_hdr)

/*
 * Packet Number Index Record:
 *
 *   0                   1                   2                   3   
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Packet Number                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              Virtual BGZF Virtual Record Locator              |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct cppip_record_pn
{
    uint32_t pkt_num;           /** the packet number */
    uint64_t bgzf_offset;       /** its offset into bgzf file */
};
typedef struct cppip_record_pn cppip_record_pn_t;
#define CPPIP_REC_PN_SIZ sizeof(struct cppip_record_pn)

/*
 * Timestamp Indexing Record:
 *
 *   0                   1                   2                   3   
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Timestamp                             |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              Virtual BGZF Virtual Record Locator              |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct cppip_record_ts
{
    struct timeval pkt_ts;      /** packet timestamp */
    uint64_t bgzf_offset;       /** its offset into bgzf file */
};
typedef struct cppip_record_ts cppip_record_ts_t;
#define CPPIP_REC_TS_SIZ sizeof(struct cppip_record_ts)

struct indexing_level
{
    uint32_t num;               /** used for pkt-num indexing */
    struct timeval ts;          /** used for timestamp indexing */
};
typedef struct indexing_level index_level_t;

struct extract_packets
{
    uint32_t pkt_start;         /** pkt-num: starting packet to extract */
    uint32_t pkt_stop;          /** pkt-num: last packet to extract */
    struct timeval ts_start;    /** timestamp: starting packet to extract */
    struct timeval ts_stop;     /** timestamp: last packet to extract */
    uint32_t pkts_w;            /** number of packets written to pcap_new */
};
typedef struct extract_packets extract_pkts_t;

/** monolithic opaque control context */
struct cppip_control_context
{
    uint8_t flags;              /** control flags */
#define CPPIP_CTRL_DEBUG    0x01
#define CPPIP_CTRL_TS_FM    0x02/** timestamp: fuzzy matching enabled */
    BGZF *pcap;                 /** BGZF compressed pcap file */
    int index;                  /** index file */
    int pcap_new;               /** new pcap file */
    char *index_fname;          /** filename of indez file */
    char *pcap_fname;           /** filename of BGZF compressed pcap file */
    char *pcap_new_fname;       /** filename of new pcap file */
    int index_mode;             /** index mode as defined above */
    extract_pkts_t e_pkts;      /** first and last pkts marked for extract */
    index_level_t index_level;  /** indexing level (as per mode) */
    cppip_file_hdr_t cppip_h;   /** the CPPIP file header */
    cppip_index_pn_hdr_t cppip_index_pn_hdr;  /** index hdr: pkt-num */
    cppip_index_ts_hdr_t cppip_index_ts_hdr;  /** index hdr: timestamp */
    char errbuf[BUFSIZ];        /** errors go here */
};
typedef struct cppip_control_context cppip_t;


/** FUNCTION PROTOTYPES */

/**
 * Create an index file
 * c        pointer to the cppip control context
 *
 * Returns: number of records written on success, -1 on error
 *
 * Function creates a cppip index file for use in subsequent extractions.
 */
int
index_create(cppip_t *c);

int
index_by_pn(cppip_t *c);

int
index_by_ts(cppip_t *c);

/** 
 * Verify an index file
 * c            pointer to the cppip control context
 * mode:        mode of verification: PREEXTRACT or DETAILED
 * index_mode:  mode to use for subsequent extraction
 * 
 * Returns:     a pointer to the index header (which should be ignored if
 *              not called during PREEXTRACT) or NULL on error
 *
 * Function verfies a cppip index file. QUICK mode is used internally by cppip
 * logic to verify an index file before attempting to use it. DETAILED mode is
 * invoked by the user and, upon verification, will dump details about the
 * index file to stderr.
 */
int
index_verify(cppip_t *c, int mode);

/**
 * Extract packet(s)
 * in:          BGZF file handle
 * out:         fd for output file, already opened
 * index:       fd for index file, already opened
 * index_hdr:   pointer to the index header
 * pkt_first:   number of first packet to extract
 * pkt_last:    number of last packet to extract
 * errbuf:      errors if any go here
 * returns:     1 on success, -1 on failure
 *
 * Function extracts one or more packets from a bgzip compressed file and
 * writes output to a previously opened file. Function is a wrapper that calls
 * a specific extraction function based off of extract_mode;
 */
int
extract(cppip_t *c);

/**
 * Simple help blurb 
 */
int
usage();

/** 
 * Skip BGZF bytes
 * f:           BGZF file pointer
 * skip_bytes:  number of bytes to skip
 * returns: 1 on success, -1 if bgzf_getc() fails
 *
 * Skip over portions of bgzf file we're not interested in 
 */
int
bgzf_skip(BGZF *f, int skip_bytes);

/**
 * Linear search for start packet
 * in:          BGZF compressed pcap file
 * start:       starting packet
 * pkt_first:   first packet we're looking for to kick off the extraction
 * errbuf:      errors if any go here
 * returns:     1 on success, -1 on error
 *
 * Given a starting point it will sequentially step through the pcap until
 * finding the starting packet.
 */
int
linear_search(cppip_t *c, int start, int pkt_first);

int
linear_search_ts(cppip_t *c, struct timeval *, pcap_offline_pkthdr_t *pcap_h);

/**
 * Verify packet range from command line
 * pkt_range:   User supplied packet range
 * pkt_first:   will hold the first packet
 * pkt_last:    will hold the ending packet
 * returns:     1 on success, -1 on error
 *
 * Function will ensure user supplied packet range is legal and conforming (ie:
 * all numerics of the form: "n or n-m", first packet is less than second packet).
 */
int
pkt_range_check(char *pkt_range, uint32_t *pkt_first, uint32_t *pkt_last);

int
opt_parse_extract(char *opt_s, cppip_t *c);

int
opt_parse_index(char *opt_s, cppip_t *c);

int
extract_by_pn(cppip_t *c);

int
extract_by_ts(cppip_t *c);

cppip_t *
control_context_init(uint8_t flags, char *index_fname, char *pcap, char *pcap_new, 
char *opt_s, int mode, char *errbuf);

void
control_context_destroy(cppip_t *c);

int
cppip_dispatch(int mode, cppip_t *c);

int 
index_open(char *index_fname, int mode, cppip_t *c, char *errbuf);

int
index_dump_modes();

int
index_dispatch(cppip_t *c);

void
convert_timeval(struct timeval *ts, uint32_t *d, uint32_t *h, uint32_t *m,
uint32_t *s, uint32_t *u);

int
index_dump(cppip_t *c, int mode);

void
index_print_info(cppip_t *c, int mode);

char *
ctime_usec(struct timeval *ts);

char *
lookup_index_mode(int mode);

int
version();

#endif
/** EOF */
