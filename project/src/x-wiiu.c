
/***************************************************************************
 *                    __            __ _ ___________                       *
 *                    \ \          / /| |____   ____|                      *
 *                     \ \        / / | |    | |                           *
 *                      \ \  /\  / /  | |    | |                           *
 *                       \ \/  \/ /   | |    | |                           *
 *                        \  /\  /    | |    | |                           *
 *                         \/  \/     |_|    |_|                           *
 *                                                                         *
 *                           Wiimms ISO Tools                              *
 *                         https://wit.wiimm.de/                           *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 *   This file is part of the WIT project.                                 *
 *   Visit https://wit.wiimm.de/ for project details and sources.          *
 *                                                                         *
 *   Copyright (c) 2009-2021 by Dirk Clemens <wiimm@wiimm.de>              *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   See file gpl-2.0.txt or http://www.gnu.org/licenses/gpl-2.0.txt       *
 *                                                                         *
 ***************************************************************************/

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "x-formats.h"
#include "lib-wux.h"

//
///////////////////////////////////////////////////////////////////////////////
///////////////			   Wii U images			///////////////
///////////////////////////////////////////////////////////////////////////////

// A Wii U disc image is a 25 GB blob whose partitions are AES encrypted with
// a per disc key that is not stored on the disc.  Everything below therefore
// works on the raw image only: WUX and WUD are two encodings of the very same
// bytes, and converting between them needs no key at all.  Extraction, which
// does need the key, is the part that is still missing.

#define WIIU_DISC_MAGIC		0xcc549eb9
#define WIIU_ID_LEN		0x16	// "WUP-P-XXXX-01-" plus padding
#define WIIU_XFER_SIZE		( 8 * MiB )

//
///////////////////////////////////////////////////////////////////////////////
///////////////			  source access			///////////////
///////////////////////////////////////////////////////////////////////////////
// [[wiiu_src_t]]

// Reads a Wii U image sequentially, hiding whether it is stored as WUD or
// WUX.  For a WUD this is a plain file read; for a WUX the sector indirection
// is resolved by lib-wux.

typedef struct wiiu_src_t
{
    FILE	*f;		// open source file
    u64		image_size;	// size of the decoded image
    u64		offset;		// current read position in the image
    bool	is_wux;		// true: read through 'wux'
    WUX_t	wux;		// valid if 'is_wux'
}
wiiu_src_t;

///////////////////////////////////////////////////////////////////////////////

static enumError open_src ( wiiu_src_t *src, ccp fname, xformat_t format )
{
    memset(src,0,sizeof(*src));

    src->f = fopen(fname,"rb");
    if (!src->f)
	return ERROR1(ERR_CANT_OPEN,"Can't open file: %s\n",fname);

    if ( format == XF_WUX )
    {
	src->is_wux = true;
	const enumError err = OpenReadWUX(&src->wux,src->f,fname);
	if (err)
	{
	    fclose(src->f);
	    src->f = 0;
	    return err;
	}
	src->image_size = src->wux.image_size;
    }
    else
    {
	struct stat st;
	if (fstat(fileno(src->f),&st))
	{
	    fclose(src->f);
	    src->f = 0;
	    return ERROR1(ERR_READ_FAILED,"Can't stat file: %s\n",fname);
	}
	src->image_size = st.st_size;
    }
    return ERR_OK;
}

///////////////////////////////////////////////////////////////////////////////

static enumError read_src ( wiiu_src_t *src, void *buf, size_t count )
{
    if (src->is_wux)
    {
	const enumError err = ReadWUX(&src->wux,src->offset,buf,count);
	if (err)
	    return err;
    }
    else
    {
	if ( fseeko(src->f,(off_t)src->offset,SEEK_SET)
	  || fread(buf,1,count,src->f) != count )
	    return ERROR1(ERR_READ_FAILED,"Read failed at %llu\n",src->offset);
    }
    src->offset += count;
    return ERR_OK;
}

///////////////////////////////////////////////////////////////////////////////

static void close_src ( wiiu_src_t *src )
{
    if (src->is_wux)
	ResetWUX(&src->wux);
    if (src->f)
	fclose(src->f);
    memset(src,0,sizeof(*src));
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////			    XINFO			///////////////
///////////////////////////////////////////////////////////////////////////////

enumError XInfoWiiU ( ccp source, xformat_t format )
{
    wiiu_src_t src;
    enumError err = open_src(&src,source,format);
    if (err)
	return err;

    printf("      image size: %llu bytes (%llu MiB)\n",
		src.image_size, src.image_size/MiB );

    if (src.is_wux)
    {
	// The stored sector count is what the format actually buys: the
	// difference to the index size is the deduplicated padding.
	printf("      WUX sectors: %u of %u stored (0x%x bytes each)\n",
		src.wux.n_stored ? src.wux.n_stored : 0,
		src.wux.n_index, src.wux.sector_size );
    }

    u8 head[0x20];
    err = read_src(&src,head,sizeof(head));
    if (!err)
    {
	if (!memcmp(head,"WUP-",4))
	{
	    // The identifier is blank padded; trim it for the report.
	    char id[WIIU_ID_LEN+1];
	    memcpy(id,head,WIIU_ID_LEN);
	    id[WIIU_ID_LEN] = 0;
	    char *end = id + strlen(id);
	    while ( end > id && ( end[-1] == ' ' || end[-1] == '-' ) )
		*--end = 0;
	    printf("      disc id:  %s\n",id);
	}
	else if ( be32(head) == WIIU_DISC_MAGIC )
	    printf("      disc magic ok (first sector still encrypted)\n");
	else
	    printf("      unexpected disc header 0x%08x\n",be32(head));
    }

    close_src(&src);
    return err;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////			   XCONVERT			///////////////
///////////////////////////////////////////////////////////////////////////////

enumError XConvertWiiU
(
    ccp			source,		// source container
    xformat_t		src_format,	// XF_WUD or XF_WUX
    ccp			dest,		// destination container
    xformat_t		dest_format	// XF_WUD or XF_WUX
)
{
    wiiu_src_t src;
    enumError err = open_src(&src,source,src_format);
    if (err)
	return err;

    // Writing a WUX reads sectors back to confirm a deduplication candidate,
    // so the destination has to be readable too.
    FILE *out = fopen(dest,"w+b");
    if (!out)
    {
	close_src(&src);
	return ERROR1(ERR_CANT_CREATE,"Can't create file: %s\n",dest);
    }

    WUX_t wux;
    InitializeWUX(&wux);
    const bool dest_wux = dest_format == XF_WUX;
    if (dest_wux)
    {
	// Keep the source geometry when there is one, so a WUX -> WUD -> WUX
	// round trip reproduces the original file rather than a re-chunked
	// equivalent of it.
	err = OpenWriteWUX(&wux,out,dest,src.image_size,
			src.is_wux ? src.wux.sector_size : 0 );
	if (err)
	    goto abort;
    }

    u8 *buf = MALLOC(WIIU_XFER_SIZE);
    u64 done = 0;
    uint chunk = 0;
    while ( done < src.image_size )
    {
	const u64 rest = src.image_size - done;
	const size_t now = rest < WIIU_XFER_SIZE ? (size_t)rest : WIIU_XFER_SIZE;

	err = read_src(&src,buf,now);
	if (err)
	    break;

	if (dest_wux)
	    err = WriteWUX(&wux,buf,now);
	else if ( fwrite(buf,1,now,out) != now )
	    err = ERROR1(ERR_WRITE_FAILED,"Write failed: %s\n",dest);
	if (err)
	    break;

	done += now;
	if ( verbose >= 0 && !( ++chunk % 128 ) )	// about every GiB
	{
	    printf("  %llu of %llu MiB\r",done/MiB,src.image_size/MiB);
	    fflush(stdout);
	}
    }
    FREE(buf);

    if ( !err && dest_wux )
	err = TermWriteWUX(&wux);

    const u64 image_size = src.image_size;	// close_src() clears it

 abort:
    ResetWUX(&wux);
    fclose(out);
    close_src(&src);

    if (err)
	unlink(dest);
    else if ( verbose >= 0 )
    {
	struct stat st;
	if (!stat(dest,&st))
	    printf("  %s created: %llu MiB (image %llu MiB)\n",
		xformat_info[dest_format].name,
		(u64)st.st_size/MiB, image_size/MiB );
    }
    return err;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////                          END                    ///////////////
///////////////////////////////////////////////////////////////////////////////
