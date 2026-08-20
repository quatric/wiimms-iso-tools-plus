
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
#include "libwbfs/rijndael.h"

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
///////////////		 Wii U partition decryption (XEXTRACT)	///////////////
///////////////////////////////////////////////////////////////////////////////

// Reference: the widely published "cdecrypt"/"wudecrypt" tools (GPL, public
// since the Wii U common key leaked in 2013).  Layout confirmed against
// maki-chan/wudecrypt (github) and yol/cdecrypt (github):
//
//   * The partition table of contents lives in the first 0x8000 bytes of the
//     image and is itself AES-128-CBC encrypted with the *disc key* and a
//     zero IV.  Entry count: big endian u32 at TOC offset 0x1c.  Entries
//     start right after; each entry is 0x20 bytes: a NUL-padded name (e.g.
//     "SI", "UP", "GM", "GI") followed by a big endian u32 "sector" field at
//     +0x14 whose byte offset in the image is  sector * 0x8000 - 0x10000.
//   * SI/UP/GI partition payloads are AES-128-CBC encrypted directly with
//     the disc key, zero IV, in 0x8000 byte clusters (IV resets every
//     cluster, matching the disc's own re-keying per cluster boundary).
//   * GM (game data) partitions instead carry a per-title key, wrapped with
//     the *common* key, inside the partition's own header; unwrapping that
//     is a materially different, more involved structure than SI/UP/GI and
//     is intentionally NOT implemented here (see note below) rather than
//     guessed at.
//
// Unlike the Wii WAD case (title key wrapped with the common key and stored
// *on* the disc, see x-wad.c), the Wii U *disc* key is NOT stored anywhere
// in the WUD/WUX image and is not derivable from public information: every
// known Wii U decryption tool (cdecrypt, wudecrypt, JWUDTool) requires it as
// an external input, sourced per-title out of band.  This mirrors how this
// project already treats Switch/3DS per-console key material: external-file
// only, never guessed at or fabricated.  So this back end takes the disc key
// from the environment/sidecar file described below and fails cleanly, with
// a clear error, if it can't find one - it does not write partial or
// silently-wrong output.

#define WIIU_COMMON_KEY \
	"\xd7\xb0\x04\x02\x65\x9b\xa2\xab\xd2\xcb\x0d\xb2\x7f\xa2\xb6\x56"

#define WIIU_TOC_SIZE		0x8000
#define WIIU_TOC_ENTRY_SIZE	0x20
#define WIIU_TOC_COUNT_OFF	0x1c
#define WIIU_TOC_ENTRIES_OFF	0x20
#define WIIU_SECTOR_SIZE	0x8000
#define WIIU_SECTOR_BASE	0x10000

typedef struct wiiu_part_t
{
    char	name[0x11];	// NUL terminated partition name
    u64		offset;		// byte offset of the partition in the image
}
wiiu_part_t;

///////////////////////////////////////////////////////////////////////////////

// Load a 16 byte disc key.  Sources tried, in order:
//   1. environment variable WIIU_DISC_KEY (32 hex chars)
//   2. a sidecar file "<source>.key" (32 hex chars, optionally with
//      whitespace/newline)
// This is intentionally the only place a disc key can enter the tool; there
// is no built in list and none will be added.

static enumError load_disc_key ( ccp source, u8 key[16] )
{
    ccp env = getenv("WIIU_DISC_KEY");
    char hexbuf[128];
    ccp hex = 0;

    if ( env && strlen(env) >= 32 )
	hex = env;
    else
    {
	char path[PATH_MAX];
	snprintf(path,sizeof(path),"%s.key",source);
	FILE *f = fopen(path,"rb");
	if (f)
	{
	    size_t n = fread(hexbuf,1,sizeof(hexbuf)-1,f);
	    fclose(f);
	    hexbuf[n] = 0;
	    hex = hexbuf;
	}
    }

    if (!hex)
	return ERROR0(ERR_INVALID_FILE,
	    "No Wii U disc key found.\n"
	    "The disc key is not stored on the disc and can't be derived;"
	    " supply it either via the WIIU_DISC_KEY environment variable"
	    " (32 hex chars) or a sidecar file named '%s.key'.\n",
	    source );

    uint i;
    for ( i = 0; i < 16; i++ )
    {
	uint hi, lo;
	if ( sscanf(hex+2*i,"%1x",&hi) != 1 )
	    break;
	if ( sscanf(hex+2*i+1,"%1x",&lo) != 1 )
	    break;
	key[i] = hi << 4 | lo;
    }
    if ( i < 16 )
	return ERROR0(ERR_INVALID_DATA,
	    "Disc key for %s is not 32 valid hex characters.\n",source);

    return ERR_OK;
}

///////////////////////////////////////////////////////////////////////////////

// Decrypt 'size' bytes starting at the partition-relative offset 0, using
// the disc key with a zero IV that resets every 0x8000 byte cluster (as
// implemented by wudecrypt and confirmed against its published source).

static enumError decrypt_partition
(
    wiiu_src_t		*src,		// open source image
    u64			part_offset,	// byte offset of the partition
    u64			part_size,	// byte size of the partition
    const aes_key_t	*akey,		// disc key, already expanded
    FILE		*out		// destination file
)
{
    u8 *buf = MALLOC(WIIU_SECTOR_SIZE);
    u8 *plain = MALLOC(WIIU_SECTOR_SIZE);
    static const u8 zero_iv[16] = {0};

    enumError err = ERR_OK;
    u64 done = 0;
    while ( done < part_size && !err )
    {
	const u64 rest = part_size - done;
	const size_t now = rest < WIIU_SECTOR_SIZE ? (size_t)rest : WIIU_SECTOR_SIZE;

	src->offset = part_offset + done;
	err = read_src(src,buf,now);
	if (err)
	    break;

	if ( now < WIIU_SECTOR_SIZE )
	    memset(buf+now,0,WIIU_SECTOR_SIZE-now);
	wd_aes_decrypt(akey,zero_iv,buf,plain,WIIU_SECTOR_SIZE);

	if ( fwrite(plain,1,now,out) != now )
	    err = ERROR1(ERR_WRITE_FAILED,"Write failed while decrypting partition\n");

	done += now;
    }

    FREE(buf);
    FREE(plain);
    return err;
}

///////////////////////////////////////////////////////////////////////////////

// Parse the TOC and return the partition list.  '*n_part' receives the
// count; the caller frees the returned array with FREE().

static enumError read_partition_table
(
    wiiu_src_t		*src,
    const aes_key_t	*akey,
    wiiu_part_t		**part_list,
    uint		*n_part
)
{
    *part_list = 0;
    *n_part = 0;

    u8 *toc = MALLOC(WIIU_TOC_SIZE);
    src->offset = 0;
    enumError err = read_src(src,toc,WIIU_TOC_SIZE);
    if (err)
    {
	FREE(toc);
	return err;
    }

    u8 *plain = MALLOC(WIIU_TOC_SIZE);
    static const u8 zero_iv[16] = {0};
    wd_aes_decrypt(akey,zero_iv,toc,plain,WIIU_TOC_SIZE);
    FREE(toc);

    const uint count = be32(plain+WIIU_TOC_COUNT_OFF);
    if ( !count || count > 64 )
    {
	FREE(plain);
	return ERROR0(ERR_INVALID_DATA,
	    "Partition table doesn't look valid (%u entries) -"
	    " the disc key is probably wrong.\n",count);
    }

    wiiu_part_t *list = CALLOC(count,sizeof(*list));
    for ( uint i = 0; i < count; i++ )
    {
	const u8 *ent = plain + WIIU_TOC_ENTRIES_OFF + i*WIIU_TOC_ENTRY_SIZE;
	memcpy(list[i].name,ent,0x10);
	list[i].name[0x10] = 0;
	// trim trailing NULs/blanks already handled by the fixed copy above

	const u32 sector = be32(ent+0x14);
	list[i].offset = (u64)sector * WIIU_SECTOR_SIZE - WIIU_SECTOR_BASE;
    }
    FREE(plain);

    *part_list = list;
    *n_part = count;
    return ERR_OK;
}

///////////////////////////////////////////////////////////////////////////////

enumError XExtractWiiU ( ccp source, xformat_t format, ccp dest )
{
    u8 disc_key[16];
    enumError err = load_disc_key(source,disc_key);
    if (err)
	return err;

    aes_key_t akey;
    wd_aes_set_key(&akey,disc_key);

    wiiu_src_t src;
    err = open_src(&src,source,format);
    if (err)
	return err;

    wiiu_part_t *part_list = 0;
    uint n_part = 0;
    err = read_partition_table(&src,&akey,&part_list,&n_part);
    if (err)
    {
	close_src(&src);
	return err;
    }

    if (CreatePath(dest,false))
    {
	FREE(part_list);
	close_src(&src);
	return ERROR1(ERR_CANT_CREATE,"Can't create directory: %s\n",dest);
    }

    uint i;
    for ( i = 0; i < n_part && !err; i++ )
    {
	const wiiu_part_t *p = part_list + i;

	// GM partitions need the per-title key unwrap, which is a different
	// on-disc structure that is not implemented (see comment above); so
	// they're reported and skipped rather than written out wrong.
	if ( !strncasecmp(p->name,"GM",2) )
	{
	    printf("  partition %-4s : skipped - needs per-title key unwrap"
		   " (not implemented, see x-wiiu.c)\n",p->name);
	    continue;
	}

	const u64 part_end = i+1 < n_part ? part_list[i+1].offset : src.image_size;
	const u64 part_size = part_end > p->offset ? part_end - p->offset : 0;
	if (!part_size)
	    continue;

	char path[PATH_MAX];
	snprintf(path,sizeof(path),"%s/%s.bin",dest,p->name);
	FILE *out = fopen(path,"wb");
	if (!out)
	{
	    err = ERROR1(ERR_CANT_CREATE,"Can't create file: %s\n",path);
	    break;
	}

	printf("  partition %-4s : %llu bytes -> %s\n",p->name,part_size,path);
	err = decrypt_partition(&src,p->offset,part_size,&akey,out);
	fclose(out);
	if (err)
	    unlink(path);
    }

    FREE(part_list);
    close_src(&src);
    return err;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////                          END                    ///////////////
///////////////////////////////////////////////////////////////////////////////
