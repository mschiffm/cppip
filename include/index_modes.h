/**
 * Compressed pcap packet indexing program (CPPIP)
 * index-modes.h: interface
 * Mike Schiffman <mschiffm@cisco.com>
 * March 2013
 */

#ifndef INDEX_MODES_H
#define INDEX_MODES_H

/**
 * These need to be updated and kept in sync as new indexing modes are added.
 */
char *index_modes[] = 
{
    "pkt-num",
    "timestamp",
    NULL
};

char *index_help[]  = 
{
    "pkt-num:\t\tindex_level should be a single integer from:\n\
\t\t\t1 - (total number of packets - 1)\n\
\t\t\tTo index every 1000 packets:\t-i pkt-num:1000\n\n",
    "timestamp:\t\tindex_level should be a number indicating the index\n\
\t\t\tfollowed by a timerange specifier which can be one of\n\
\t\t\tfollowing:\n\
\t\t\td - days\n\t\t\th - hours\n\t\t\tm - minutes\n\t\t\ts - seconds\n\
\t\t\tTo index every 100 seconds:\t-i timestamp:100s\n",
    NULL
};

char *extract_help[] =
{
    "pkt-num: extract string should be a range of integers from:\n\
1 - total number of packets\n\
To extract packets "

};
int index_types[] = 
{
    CPPIP_INDEX_PN,
    CPPIP_INDEX_TS,
    0
};

#endif
