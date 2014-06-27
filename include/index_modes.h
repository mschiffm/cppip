/**
 * Compressed pcap packet indexing program (CPPIP)
 * index-modes.h: interface
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
