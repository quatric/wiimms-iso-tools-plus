
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
 *   This file is part of the WIT project.                                *
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

// NKit (.nkit.iso) restoration -- Wii support types, STAGE 2a (of a driver
// that still doesn't exist yet -- see below).
//
// This file is NOT a restore driver. There is no NkitRestoreWii() here and
// nothing in this file is called from XCONVERT or anywhere else yet -- see
// x-nkit.c's file header for the GC driver this will eventually sit next
// to, and the ~750 line NkitReaderWii.cs this whole file is prep for.
// XCONVERT still does not handle Wii NKit images after stage 2a; that is
// stage 2b (the actual Read()/NkitRestoreWii() driver loop).
//
// What IS here: a faithful, field-for-field port of the 8 supporting C#
// types NkitReaderWii.cs itself is built on top of (NkitReaderWii.cs was
// deliberately NOT read/ported -- that's stage 2/3), from the real
// github.com/Nanook/NKitv1 source:
//
//   WiiPartitionGroupEncryptionState.cs -> nkit_group_crypt_t   (the AES-128-CBC
//                                          per-partition-group encrypt/decrypt/
//                                          hash-cache state machine -- the one
//                                          genuinely new piece of logic here)
//   WiiPartitionHashTable.cs           -> nkit_hash_table_t
//   WiiPartitionHeaderSection.cs       -> nkit_part_header_t
//   WiiPartitionInfo.cs                -> nkit_part_info_t
//   WiiPartitionSection.cs             -> nkit_partition_t (bookkeeping only)
//   WiiPartitionGroupSection.cs        -> nkit_group_t (bookkeeping only)
//   WiiDiscHeaderSection.cs            -> nkit_disc_header_t (partition table
//                                          rebuild only, i.e. UpdateRepair())
//   WiiHashStore.cs                    -> nkit_hash_store_t
//
// This repo's own libwbfs/wiidisc.c already implements every Wii-format
// primitive NKit's C# reimplements from scratch (it has to, being a
// standalone converter with no libwbfs to lean on) -- disc partition table
// parsing, ticket title-key decryption incl. the real Wii disc common keys,
// and the full H0/H1/H2/H3 hash tree calc. Rather than re-deriving any of
// that, this port calls straight into it:
//
//   wd_get_common_key() / wd_decrypt_title_key()   (libwbfs/wiidisc.c)
//       instead of WiiPartitionHeaderSection.cs's own hand-rolled,
//       base64-obfuscated ("_lame") copy of the 3 Wii disc common keys
//       (RVT-R / Korean / retail) and its own AES title-key unwrap. Do NOT
//       add another copy of these keys anywhere -- they already exist here,
//       and they are NOT the same key as the WAD common key (x-wad.c) or
//       the Wii U common key (x-wiiu.c).
//   wd_aes_decrypt() / wd_aes_encrypt() / aes_key_t (libwbfs/rijndael.h)
//       instead of C#'s System.Security.Cryptography.Aes.
//   wd_calc_group_hashes()                          (libwbfs/wiidisc.c)
//       instead of hand-porting hashCacheH0GroupCalc()+hashCacheH1H2GroupCalc()
//       block by block -- wd_calc_group_hashes() already computes the full
//       H0/H1/H2(/H3) tree for one 64-sector group in a single call, using
//       the same WII_N_ELEMENTS_H0/H1/H2, WII_HASH_SIZE, WII_SECTOR_HASH_SIZE,
//       WII_H0_DATA_SIZE, WII_H3_SIZE, WII_GROUP_SECTORS, WII_SECTOR_DATA_SIZE
//       constants (libwbfs/file-formats.h) the C# WiiPartitionGroupEncryptionState
//       class hardcodes as 0x8000/0x400/0x7c00/31/8/8/0x18000/20 etc.
//
// What's genuinely new here (no existing wit equivalent): the *stateful*
// per-block dirty/scrubbed/encrypted-vs-decrypted bookkeeping
// WiiPartitionGroupEncryptionState.cs layers on top of those primitives --
// lazy re-encrypt/re-decrypt, per-block scrub-byte IV reconstruction, and
// the "fast hash valid" short-circuit -- because wit's own VERIFY/EXTRACT
// pipeline never needed to *mutate* a group and re-derive its hashes
// on demand the way NKit's restore path does.

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x-formats.h"
#include "libwbfs/wiidisc.h"
#include "libwbfs/rijndael.h"
#include "libwbfs/file-formats.h"

//
///////////////////////////////////////////////////////////////////////////////
///////////////	  WiiPartitionHashTable.cs -> nkit_hash_table_t	///////////////
///////////////////////////////////////////////////////////////////////////////

// Direct port of PartitionHashTable: a flat array of 'count' SHA1 hashes
// (WII_HASH_SIZE==20 bytes each) with the same Reset()/CopyAll()/Set()/
// Equals() operations the C# class exposes. Used by nkit_group_crypt_t
// below exactly the way the original block/h1Table/h2Table fields are.

typedef struct nkit_hash_table_t
{
    u8		*hash;		// Bytes: hash_count * WII_HASH_SIZE bytes, owned
    uint	hash_count;		// HashCount
}
nkit_hash_table_t;

///////////////////////////////////////////////////////////////////////////////

// ctor: PartitionHashTable(int hashCount)
static void nkit_hash_table_init ( nkit_hash_table_t *t, uint hash_count )
{
    t->hash_count = hash_count;
    t->hash = MALLOC(hash_count*WII_HASH_SIZE);
    memset(t->hash,0,hash_count*WII_HASH_SIZE);
}

static void nkit_hash_table_reset_mem ( nkit_hash_table_t *t )
{
    if (t->hash)
	FREE(t->hash);
    t->hash = 0;
}

///////////////////////////////////////////////////////////////////////////////

// Reset(byte[] group, int offset): copy min(Bytes.Length, group.Length-offset)
// bytes from 'group+offset' into the table.
static void nkit_hash_table_load ( nkit_hash_table_t *t, const u8 *group, uint group_len, uint offset )
{
    uint n = t->hash_count*WII_HASH_SIZE;
    uint avail = offset < group_len ? group_len-offset : 0;
    if ( n > avail ) n = avail;
    memcpy(t->hash,group+offset,n);
}

// CopyAll(byte[] buffer, int offset): copy the whole table out to 'buffer+offset'.
static void nkit_hash_table_store ( const nkit_hash_table_t *t, u8 *buffer, uint buffer_len, uint offset )
{
    uint n = t->hash_count*WII_HASH_SIZE;
    uint avail = offset < buffer_len ? buffer_len-offset : 0;
    if ( n > avail ) n = avail;
    memcpy(buffer+offset,t->hash,n);
}

// Set(int blockIndex, byte[] sha1, bool testEqual): store one hash; if
// testEqual and it's unchanged, leave it alone and report "same" (true).
static bool nkit_hash_table_set ( nkit_hash_table_t *t, uint idx, const u8 sha1[WII_HASH_SIZE], bool test_equal )
{
    u8 *slot = t->hash + idx*WII_HASH_SIZE;
    if ( test_equal && !memcmp(sha1,slot,WII_HASH_SIZE) )
	return true;
    memcpy(slot,sha1,WII_HASH_SIZE);
    return false;
}

// Equals(int blockIndex, byte[] sha1)
static bool nkit_hash_table_equals ( const nkit_hash_table_t *t, uint idx, const u8 sha1[WII_HASH_SIZE] )
{
    return !memcmp(sha1,t->hash+idx*WII_HASH_SIZE,WII_HASH_SIZE);
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////   WiiPartitionGroupEncryptionState.cs -> nkit_group_crypt_t //////
///////////////////////////////////////////////////////////////////////////////

// One 'block' is one Wii hashed sector: 0x400 bytes of H0/H1/H2 hash data
// followed by 0x7c00 bytes of (en/de)crypted user data -- WII_SECTOR_SIZE
// total, split as WII_SECTOR_HASH_SIZE + WII_SECTOR_DATA_SIZE.
// Direct port of the private nested 'block' class.

typedef struct nkit_crypt_block_t
{
    int			index;		// Index
    u32			offset;		// Offset = index * WII_SECTOR_SIZE
    u32			data_offset;	// DataOffset = index * WII_SECTOR_SIZE + WII_SECTOR_HASH_SIZE

    bool		is_dirty;	// IsDirty
    bool		is_scrubbed;	// IsScrubbed
    u8			scrub_byte;	// ScrubByte
    bool		is_used;	// IsUsed

    nkit_hash_table_t	h0;		// H0Table: WII_N_ELEMENTS_H0 hashes, owned by this block
    nkit_hash_table_t	*h1;		// H1Table: shared across WII_N_ELEMENTS_H1 blocks, NOT owned
    nkit_hash_table_t	*h2;		// H2Table: shared across the whole group, NOT owned
}
nkit_crypt_block_t;

///////////////////////////////////////////////////////////////////////////////

// Direct port of WiiPartitionGroupEncryptionState. One instance manages one
// Wii partition "group" (WiiPartitionSection.GroupSize == 64 hashed sectors
// == WII_GROUP_SECTORS, matching wit's own group size), tracking whichever
// of the encrypted/decrypted views is current and lazily deriving the other
// plus the H0..H3 hash cache only when actually asked for.

typedef struct nkit_group_crypt_t
{
    const u8		*h3_table;	// _h3Table: pointer into the partition's H3 table (WII_H3_SIZE bytes), NOT owned
    u8			h3_value[WII_HASH_SIZE]; // _h3Value: SHA1 of this group's H2 table
    bool		is_valid;	// _isValid: does h3_value match h3_table[group_idx]?
    int			group_idx;	// _groupIdx

    aes_key_t		akey;		// shared AES key (one Aes per block in C#, but the key is
					// identical for every block in a partition, so wit's
					// aes_key_t -- which bakes in expanded round keys, not
					// just the raw key -- only needs deriving once)

    u8			*enc;		// _enc: encrypted view, _max_size bytes, owned
    u8			*dec;		// _dec: decrypted view, _max_size bytes, owned
    bool		has_enc;	// _hasEnc
    bool		has_dec;	// _hasDec
    bool		has_hashes;	// _hasHashes
    uint		max_size;	// _maxSize (bytes, multiple of WII_SECTOR_SIZE)
    bool		is_dirty;	// _isDirty
    bool		forced_hashes;	// _forcedHashes
    bool		hashes_recalculated; // _hashedRecalulated

    nkit_crypt_block_t	*block;		// _blocks[maxSize/WII_SECTOR_SIZE], owned
    uint		n_blocks;
    nkit_hash_table_t	*h1_shared;	// one shared H1 table per 8 blocks (n_blocks/WII_N_ELEMENTS_H1 of them), owned
    uint		n_h1_shared;
    nkit_hash_table_t	h2_shared;	// _blocks[0].H2Table equivalent: one shared H2 table for the whole group, owned

    uint		size;		// _size: bytes actually populated (<= max_size)
    uint		used_blocks;	// _usedBlocks

    u8			unused_blank_hash[WII_HASH_SIZE]; // _unusedBlankHash: SHA1 of a WII_H0_DATA_SIZE zero block
}
nkit_group_crypt_t;

///////////////////////////////////////////////////////////////////////////////

// ctor: WiiPartitionGroupEncryptionState(int maxSize, byte[] key, byte[] h3Table)
static enumError nkit_group_crypt_init
(
    nkit_group_crypt_t	*gs,
    uint		max_size,	// e.g. WII_GROUP_SECTORS * WII_SECTOR_SIZE
    const u8		key[WII_KEY_SIZE],
    const u8		*h3_table	// NULL or WII_H3_SIZE bytes, not owned/copied
)
{
    memset(gs,0,sizeof(*gs));

    if ( max_size % WII_SECTOR_SIZE )
	return ERROR0(ERR_WIA_INVALID,"NKit: group size is not a multiple of WII_SECTOR_SIZE\n");

    gs->h3_table = h3_table;
    gs->max_size = max_size;
    gs->n_blocks = max_size / WII_SECTOR_SIZE;
    gs->block = MALLOC(gs->n_blocks*sizeof(*gs->block));
    memset(gs->block,0,gs->n_blocks*sizeof(*gs->block));

    gs->n_h1_shared = ( gs->n_blocks + WII_N_ELEMENTS_H1-1 ) / WII_N_ELEMENTS_H1;
    gs->h1_shared = MALLOC(gs->n_h1_shared*sizeof(*gs->h1_shared));
    for ( uint i = 0; i < gs->n_h1_shared; i++ )
	nkit_hash_table_init(gs->h1_shared+i,WII_N_ELEMENTS_H1);
    nkit_hash_table_init(&gs->h2_shared,WII_N_ELEMENTS_H2);

    wd_aes_set_key(&gs->akey,key);

    for ( uint i = 0; i < gs->n_blocks; i++ )
    {
	nkit_crypt_block_t *b = gs->block+i;
	b->index       = i;
	b->offset      = i*WII_SECTOR_SIZE;
	b->data_offset = i*WII_SECTOR_SIZE + WII_SECTOR_HASH_SIZE;
	nkit_hash_table_init(&b->h0,WII_N_ELEMENTS_H0);
	b->h1 = gs->h1_shared + i/WII_N_ELEMENTS_H1;	// share the H1 table across WII_N_ELEMENTS_H1 blocks
	b->h2 = &gs->h2_shared;				// share the H2 table across the whole group
    }

    gs->enc = MALLOC(max_size);
    gs->dec = MALLOC(max_size);

    // _unusedBlankHash = _blocks[0].Sha1.ComputeHash(new byte[0x400])
    u8 zero[WII_H0_DATA_SIZE];
    memset(zero,0,sizeof(zero));
    SHA1(zero,sizeof(zero),gs->unused_blank_hash);

    return ERR_OK;
}

///////////////////////////////////////////////////////////////////////////////

static void nkit_group_crypt_reset_mem ( nkit_group_crypt_t *gs )
{
    if (!gs->block)
	return;
    for ( uint i = 0; i < gs->n_blocks; i++ )
	nkit_hash_table_reset_mem(&gs->block[i].h0);
    FREE(gs->block);
    for ( uint i = 0; i < gs->n_h1_shared; i++ )
	nkit_hash_table_reset_mem(gs->h1_shared+i);
    FREE(gs->h1_shared);
    nkit_hash_table_reset_mem(&gs->h2_shared);
    if (gs->enc) FREE(gs->enc);
    if (gs->dec) FREE(gs->dec);
    memset(gs,0,sizeof(*gs));
}

///////////////////////////////////////////////////////////////////////////////

// Populate(byte[] data, int size, bool isEnc, bool isEncHeader, int groupIndex)
//
// NKit's isEncHeader path (decrypting just the 0x400 byte hash area with a
// zero IV to recover an ISO.DEC-style "hash area encrypted, data plain"
// group) uses Aes.CreateDecryptor() with a zero IV directly, i.e. the same
// wd_aes_decrypt() call the plain per-block decrypt uses below with iv=0 --
// ported 1:1, no new primitive.
static void nkit_group_crypt_populate
(
    nkit_group_crypt_t	*gs,
    const u8		*data,
    uint		size,		// s = min(size, data.Length) already applied by caller
    bool		is_enc,
    bool		is_enc_header,
    int			group_index
)
{
    uint s = size;
    gs->group_idx = group_index;
    gs->size = s;

    u8 *dst = is_enc ? gs->enc : gs->dec;
    memcpy(dst,data,s);
    if ( s < gs->max_size )
	memset(dst+s,0,gs->max_size-s);

    gs->has_dec = !(gs->has_enc = is_enc);
    gs->is_dirty = false;
    gs->used_blocks = s / WII_SECTOR_SIZE;
    gs->has_hashes = false;
    gs->hashes_recalculated = false;
    gs->forced_hashes = false;

    for ( uint i = 0; i < gs->n_blocks; i++ )
    {
	nkit_crypt_block_t *b = gs->block+i;
	b->is_dirty = false;			// _isDirty is always false here, same as the C#
	b->is_used = i < gs->used_blocks;
	b->is_scrubbed = false;
	b->scrub_byte = 0;
    }

    if ( !is_enc && is_enc_header )
    {
	static const u8 zero_iv[WII_KEY_SIZE] = {0};
	for ( uint i = 0; i < gs->n_blocks; i++ )
	{
	    nkit_crypt_block_t *b = gs->block+i;
	    wd_aes_decrypt(&gs->akey,zero_iv,gs->dec+b->offset,gs->dec+b->offset,WII_SECTOR_HASH_SIZE);
	}
    }
    else if (is_enc)
    {
	// setScrubbedBlockInfo(b): detect an all-00 or all-FF scrubbed hash
	// area up front, purely from the raw encrypted bytes (no crypto
	// needed -- a scrubbed sector is scrubbed both encrypted and clear).
	for ( uint i = 0; i < gs->n_blocks; i++ )
	{
	    nkit_crypt_block_t *b = gs->block+i;
	    if (!gs->has_enc)
		continue;
	    uint end = b->data_offset;
	    u8 byt = gs->enc[b->offset];
	    if ( byt == 0 || byt == 0xff )
	    {
		bool scrubbed = true;
		for ( uint j = end-WII_SECTOR_HASH_SIZE; j < end; j++ )
		    if ( gs->enc[j] != byt ) { scrubbed = false; break; }
		if ( b->is_used )
		{
		    b->is_scrubbed = scrubbed;
		    b->scrub_byte = byt;
		}
	    }
	    else
		b->is_scrubbed = false;
	}
    }
}

///////////////////////////////////////////////////////////////////////////////

// encrypt(block b): re-derive the encrypted view of one block from _dec.
// Direct port, including the scrubbed-with-nonzero-byte IV reconstruction
// trick (encrypting a scrub byte with IV=scrubByte reproduces exactly what
// a real scrubbed-then-decrypted-then-recrypted sector looks like).
static void nkit_group_crypt_encrypt_block ( nkit_group_crypt_t *gs, nkit_crypt_block_t *b )
{
    u8 iv[WII_KEY_SIZE];
    memset(iv,0,sizeof(iv));

    if ( b->is_scrubbed && b->scrub_byte != 0 && !gs->forced_hashes )
	memset(iv,b->scrub_byte,sizeof(iv));

    wd_aes_encrypt(&gs->akey,iv,gs->dec+b->offset,gs->enc+b->offset,WII_SECTOR_HASH_SIZE);

    memcpy(iv,gs->enc+b->offset+0x3d0,WII_KEY_SIZE);	// IV for the data area = last 16 bytes of the encrypted H2 hash (offset 0x3d0 within the 0x400 hash area)

    wd_aes_encrypt(&gs->akey,iv,gs->dec+b->data_offset,gs->enc+b->data_offset,WII_SECTOR_DATA_SIZE);

    b->is_dirty = false;
}

// decrypt(block b): inverse of the above.
static void nkit_group_crypt_decrypt_block ( nkit_group_crypt_t *gs, nkit_crypt_block_t *b )
{
    u8 iv[WII_KEY_SIZE];
    memset(iv,0,sizeof(iv));

    wd_aes_decrypt(&gs->akey,iv,gs->enc+b->offset,gs->dec+b->offset,WII_SECTOR_HASH_SIZE);

    memcpy(iv,gs->enc+b->offset+0x3d0,WII_KEY_SIZE);	// IV for the data area comes from the ENCRYPTED hash area, same offset as above

    wd_aes_decrypt(&gs->akey,iv,gs->enc+b->data_offset,gs->dec+b->data_offset,WII_SECTOR_DATA_SIZE);

    b->is_dirty = false;
}

///////////////////////////////////////////////////////////////////////////////

// hashCacheH0H1BlockPopulate(b): load H0/H1 straight from _dec (no
// recompute -- this is the "trust what's already there" path used before
// validating).
static void nkit_group_crypt_h0h1_populate_block ( nkit_group_crypt_t *gs, nkit_crypt_block_t *b )
{
    if (!b->is_used)
    {
	u8 zero[0x26c];
	memset(zero,0,sizeof(zero));
	nkit_hash_table_load(&b->h0,zero,sizeof(zero),0);
    }
    else
	nkit_hash_table_load(&b->h0,gs->dec,gs->max_size,b->offset);

    if ( b->index % WII_N_ELEMENTS_H1 == 0 )		// first block in its group of 8 owns the shared H1 table
	nkit_hash_table_load(b->h1,gs->dec,gs->max_size,b->offset+0x280);
}

static void nkit_group_crypt_h0h1_populate ( nkit_group_crypt_t *gs )
{
    for ( uint i = 0; i < gs->n_blocks; i++ )
	nkit_group_crypt_h0h1_populate_block(gs,gs->block+i);
}

// hashCacheH2Populate(): load H2 from block 0, then test the H3 entry.
static void nkit_group_crypt_h2_populate ( nkit_group_crypt_t *gs )
{
    nkit_hash_table_load(&gs->h2_shared,gs->dec,gs->max_size,0x340);
    SHA1(gs->h2_shared.hash,gs->h2_shared.hash_count*WII_HASH_SIZE,gs->h3_value);
    gs->is_valid = gs->h3_table
	&& !memcmp(gs->h3_value,gs->h3_table+gs->group_idx*WII_HASH_SIZE,WII_HASH_SIZE);
}

static void nkit_group_crypt_ensure_hash_cache ( nkit_group_crypt_t *gs )
{
    if (!gs->has_hashes)
    {
	nkit_group_crypt_h0h1_populate(gs);
	nkit_group_crypt_h2_populate(gs);
	gs->has_hashes = true;
	gs->is_dirty = false;
    }
}

///////////////////////////////////////////////////////////////////////////////

// hashCacheH0BlockCalc(b): recompute this block's WII_N_ELEMENTS_H0 SHA1s
// from _dec, comparing against what's cached so callers can tell "changed".
static bool nkit_group_crypt_h0_calc_block ( nkit_group_crypt_t *gs, nkit_crypt_block_t *b )
{
    bool eq = true;
    for ( uint i = 0; i < WII_N_ELEMENTS_H0; i++ )
    {
	u8 hash[WII_HASH_SIZE];
	if (b->is_used)
	    SHA1(gs->dec+b->offset+WII_SECTOR_HASH_SIZE+i*WII_H0_DATA_SIZE,WII_H0_DATA_SIZE,hash);
	else
	    memcpy(hash,gs->unused_blank_hash,WII_HASH_SIZE);
	if (!nkit_hash_table_set(&b->h0,i,hash,eq))
	    eq = false;
    }
    return eq;
}

static bool nkit_group_crypt_h0_calc ( nkit_group_crypt_t *gs )
{
    bool eq = true;
    for ( uint i = 0; i < gs->n_blocks; i++ )
	if (!nkit_group_crypt_h0_calc_block(gs,gs->block+i))
	    eq = false;
    return eq;
}

// hashCacheH1H2GroupCalc(): fold each block's H0 table up into its shared H1
// table, then fold every H1 table up into the shared H2 table, then hash H2
// to get H3 and test it -- exactly wd_calc_group_hashes()'s own tree shape,
// just operating on the already-materialised per-block hash tables instead
// of raw sector bytes (this class caches intermediate levels; wit's own
// helper always recomputes the whole tree in one pass -- kept separate here
// to stay a faithful port of the incremental C# state machine).
static bool nkit_group_crypt_h1h2_calc ( nkit_group_crypt_t *gs )
{
    bool eq = true;
    for ( uint j = 0; j < gs->n_h1_shared; j++ )
    {
	for ( uint i = 0; i < WII_N_ELEMENTS_H1; i++ )
	{
	    uint bi = j*WII_N_ELEMENTS_H1+i;
	    if ( bi >= gs->n_blocks ) break;
	    u8 hash[WII_HASH_SIZE];
	    SHA1(gs->block[bi].h0.hash,gs->block[bi].h0.hash_count*WII_HASH_SIZE,hash);
	    if (!nkit_hash_table_set(gs->block[j*WII_N_ELEMENTS_H1].h1,i,hash,eq))
		eq = false;
	}
	u8 hash[WII_HASH_SIZE];
	SHA1(gs->block[j*WII_N_ELEMENTS_H1].h1->hash,gs->block[j*WII_N_ELEMENTS_H1].h1->hash_count*WII_HASH_SIZE,hash);
	if (!nkit_hash_table_set(&gs->h2_shared,j,hash,eq))
	    eq = false;
    }
    SHA1(gs->h2_shared.hash,gs->h2_shared.hash_count*WII_HASH_SIZE,gs->h3_value);
    gs->is_valid = gs->h3_table
	&& !memcmp(gs->h3_value,gs->h3_table+gs->group_idx*WII_HASH_SIZE,WII_HASH_SIZE);
    return eq;
}

static void nkit_group_crypt_recalculate_hashes ( nkit_group_crypt_t *gs )
{
    nkit_group_crypt_h0_calc(gs);
    nkit_group_crypt_h1h2_calc(gs);
    gs->is_dirty = false;
    gs->hashes_recalculated = true;
    gs->forced_hashes = false;
}

///////////////////////////////////////////////////////////////////////////////

// commitHashCache(b): write this block's cached H0/H1/H2 tables back into
// the 0x400 byte hash area of _dec, zeroing the padding between tables --
// same layout wd_calc_group_hashes() writes directly (0x000 H0, 0x280 H1,
// 0x340 H2), spelled out here per-block because this class commits lazily,
// only right before encrypting a block whose hashes were recalculated.
static void nkit_group_crypt_commit_hash_cache ( nkit_group_crypt_t *gs, nkit_crypt_block_t *b )
{
    nkit_hash_table_store(&b->h0,gs->dec,gs->max_size,b->offset);
    memset(gs->dec+b->offset+0x26c,0,0x280-0x26c);
    nkit_hash_table_store(b->h1,gs->dec,gs->max_size,b->offset+0x280);
    memset(gs->dec+b->offset+0x280+0xA0,0,0x340-(0x280+0xA0));
    nkit_hash_table_store(b->h2,gs->dec,gs->max_size,b->offset+0x340);
    memset(gs->dec+b->offset+0x340+0xA0,0,WII_SECTOR_HASH_SIZE-(0x340+0xA0));
}

///////////////////////////////////////////////////////////////////////////////
///////////////			public-equivalent API			///////////////
///////////////////////////////////////////////////////////////////////////////

// ensureDecrypted() / the 'Decrypted' getter
static u8 * nkit_group_crypt_ensure_decrypted ( nkit_group_crypt_t *gs )
{
    if ( gs->has_enc && !gs->has_dec )
    {
	for ( uint i = 0; i < gs->n_blocks; i++ )
	{
	    nkit_group_crypt_decrypt_block(gs,gs->block+i);
	    nkit_group_crypt_h0h1_populate_block(gs,gs->block+i);
	}
	nkit_group_crypt_h2_populate(gs);
	gs->has_hashes = true;
	gs->has_dec = true;
    }
    return gs->dec;
}

// ensureEncrypted() / the 'Encrypted' getter
static u8 * nkit_group_crypt_ensure_encrypted ( nkit_group_crypt_t *gs )
{
    if (!gs->has_enc)
    {
	nkit_group_crypt_ensure_hash_cache(gs);
	for ( uint i = 0; i < gs->n_blocks; i++ )
	{
	    nkit_crypt_block_t *b = gs->block+i;
	    if (gs->hashes_recalculated)
		nkit_group_crypt_commit_hash_cache(gs,b);
	    nkit_group_crypt_encrypt_block(gs,b);
	}
	gs->is_dirty = false;
	gs->has_enc = true;
    }
    return gs->enc;
}

// IsValid(bool hashRecalculateIfDirty)
static bool nkit_group_crypt_is_valid ( nkit_group_crypt_t *gs, bool hash_recalculate_if_dirty )
{
    bool dirty = gs->is_dirty;
    nkit_group_crypt_ensure_decrypted(gs);
    nkit_group_crypt_ensure_hash_cache(gs);
    if ( hash_recalculate_if_dirty && dirty )
	nkit_group_crypt_recalculate_hashes(gs);
    return gs->is_valid;
}

// blockIsValid(b): full H0 regen test against the cached table (does NOT
// touch H1/H2/H3 -- that's IsValid()'s job).
static bool nkit_group_crypt_block_is_valid ( nkit_group_crypt_t *gs, nkit_crypt_block_t *b )
{
    nkit_group_crypt_ensure_decrypted(gs);
    nkit_group_crypt_ensure_hash_cache(gs);
    for ( uint i = 0; i < WII_N_ELEMENTS_H0; i++ )
    {
	u8 hash[WII_HASH_SIZE];
	SHA1(gs->dec+b->offset+WII_SECTOR_HASH_SIZE+i*WII_H0_DATA_SIZE,WII_H0_DATA_SIZE,hash);
	if (!nkit_hash_table_equals(&b->h0,i,hash))
	    return false;
    }
    return true;
}

// MarkBlockDirty(int blockIndex)
static void nkit_group_crypt_mark_dirty ( nkit_group_crypt_t *gs, uint block_index )
{
    gs->block[block_index].is_dirty = true;
    gs->is_dirty = true;
    gs->has_enc = false;
}

// MarkBlockScrubbed(int blockIndex, byte scrubByte)
static void nkit_group_crypt_mark_scrubbed ( nkit_group_crypt_t *gs, uint block_index, u8 scrub_byte )
{
    gs->block[block_index].is_scrubbed = block_index < gs->used_blocks;
    gs->block[block_index].scrub_byte = scrub_byte;
}

// MarkBlockUnscrubbedAndDirty(int blockIndex)
static void nkit_group_crypt_mark_unscrubbed_and_dirty ( nkit_group_crypt_t *gs, uint block_index )
{
    gs->block[block_index].is_scrubbed = false;
    gs->block[block_index].scrub_byte = 0;
    nkit_group_crypt_mark_dirty(gs,block_index);
}

// ForceHashes(byte[] hashes): install externally-supplied hash-area bytes
// (e.g. hashes preserved by nkit_hash_store_t below) instead of recomputing.
static void nkit_group_crypt_force_hashes ( nkit_group_crypt_t *gs, const u8 *hashes /* nullable */ )
{
    nkit_group_crypt_ensure_decrypted(gs);
    for ( uint i = 0; i < gs->used_blocks; i++ )
    {
	if (hashes)
	    memcpy(gs->dec+i*WII_SECTOR_SIZE,hashes+i*WII_SECTOR_SIZE,WII_SECTOR_HASH_SIZE);
	gs->block[i].is_dirty = false;
    }
    gs->forced_hashes = true;
    gs->has_hashes = true;
    gs->is_dirty = false;
    gs->has_enc = false;
}

// AllScrubbedSameByte()
static bool nkit_group_crypt_all_scrubbed_same_byte ( const nkit_group_crypt_t *gs )
{
    u8 b0 = gs->block[0].scrub_byte;
    for ( uint i = 0; i < gs->n_blocks; i++ )
    {
	const nkit_crypt_block_t *b = gs->block+i;
	if ( b->is_used && !( b->is_scrubbed && b->scrub_byte == b0 ) )
	    return false;
    }
    return true;
}

// ScrubbedBlocks getter
static uint nkit_group_crypt_scrubbed_blocks ( const nkit_group_crypt_t *gs )
{
    uint n = 0;
    for ( uint i = 0; i < gs->n_blocks; i++ )
	if (gs->block[i].is_scrubbed)
	    n++;
    return n;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////	    WiiPartitionInfo.cs -> nkit_part_info_t		///////////////
///////////////////////////////////////////////////////////////////////////////

// [[nkit_part_type_t]] -- PartitionType enum
typedef enum nkit_part_type_t
{
    NKIT_PART_DATA,
    NKIT_PART_UPDATE,
    NKIT_PART_CHANNEL,
    NKIT_PART_GAMEDATA,
    NKIT_PART_OTHER,
}
nkit_part_type_t;

// Direct port of WiiPartitionInfo: one entry of the 4-table, up-to-4-entries-
// per-table partition table at disc offset 0x40000 (WiiDiscHeaderSection's
// _PartitionTableOffset -- same layout wit's own wd_ptab_t/wd_ptab_info_t
// already parse for reading; this is NKit's own copy used while rebuilding
// that table on restore, kept as a distinct light struct like the C# is).
typedef struct nkit_part_info_t
{
    nkit_part_type_t	type;		// Type
    u64			disc_offset;	// DiscOffset
    u64			src_disc_offset;// SrcDiscOffset
    int			table;		// Table: which of the 4 partition tables (0..3)
    u64			table_offset;	// TableOffset: byte offset of this entry's disc-offset field
}
nkit_part_info_t;

// ctor: WiiPartitionInfo(PartitionType type, long offset, int table, long tablePos)
static void nkit_part_info_init ( nkit_part_info_t *pi, nkit_part_type_t type, u64 offset, int table, u64 table_pos )
{
    pi->disc_offset = pi->src_disc_offset = offset;
    pi->table = table;
    pi->type = type;
    pi->table_offset = table_pos;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////	  WiiDiscHeaderSection.cs -> nkit_disc_header_t		///////////
///////////////////////////////////////////////////////////////////////////////

#define NKIT_PTAB_OFFSET	0x40000		// _PartitionTableOffset
#define NKIT_PTAB_LENGTH	0x100		// _PartitionTableLength

// Bookkeeping-only port of WiiDiscHeaderSection: parsing the on-disc
// partition table (CreatePartitionInfos) and rebuilding it after the
// partition list changes (UpdateRepair/UpdateOffsets/RemoveUpdatePartition).
// Deliberately does NOT duplicate wd_disc_t's own full partition parsing --
// this exists purely because NKit's restore path needs to WRITE the table
// back out in the same layout it read it in, driven by its own flat list
// (dropped update partitions re-added, placeholders re-numbered, etc.),
// which is a distinct operation from wit's read-side wd_open_disc().
typedef struct nkit_disc_header_t
{
    u8			*data;		// raw disc header bytes (>= NKIT_PTAB_OFFSET+NKIT_PTAB_LENGTH), NOT owned
    uint		data_size;
    nkit_part_info_t	*part;		// Partitions, owned, resizable
    uint		n_part;
    uint		max_part;
    bool		has_update_partition; // HasUpdatePartition
}
nkit_disc_header_t;

///////////////////////////////////////////////////////////////////////////////

// CreatePartitionInfos(MemorySection section, int offset): walk all 4
// partition tables at 'offset' and yield one nkit_part_info_t per entry.
// Same u32-be, /4-scaled offsets as wd_ptab_info_t already decodes.
static enumError nkit_disc_header_parse_ptab
(
    const u8		*data,
    uint		data_size,
    int			offset,
    nkit_part_info_t	**res_part,
    uint		*res_n
)
{
    uint max_part = 4*4;	// generous upper bound; grown below if needed
    nkit_part_info_t *part = MALLOC(max_part*sizeof(*part));
    uint n = 0;

    for ( int table_idx = 0; table_idx < 4; table_idx++ )
    {
	if ( offset + table_idx*8 + 8 > (int)data_size )
	    continue;
	u32 c = be32(data+offset+table_idx*8);		// count of partitions for this table
	if (!c)
	    continue;
	int table_offset = (int)( be32(data+offset+table_idx*8+4) * 4 );
	int adjust = offset + (table_offset - NKIT_PTAB_OFFSET);

	for ( u32 i = 0; i < c; i++ )
	{
	    if ( adjust + (int)i*8 + 8 > (int)data_size )
		break;
	    u64 part_offset = (u64)be32(data+adjust+i*8) * 4;
	    nkit_part_type_t type = (nkit_part_type_t)be32(data+adjust+i*8+4);

	    if ( n == max_part )
	    {
		max_part *= 2;
		part = REALLOC(part,max_part*sizeof(*part));
	    }
	    nkit_part_info_init(part+n,type,part_offset,table_idx,table_offset+(u64)i*8);
	    n++;
	}
    }

    *res_part = part;
    *res_n = n;
    return ERR_OK;
}

///////////////////////////////////////////////////////////////////////////////

// ctor: WiiDiscHeaderSection(MemorySection header)
static enumError nkit_disc_header_init ( nkit_disc_header_t *h, u8 *data, uint data_size )
{
    memset(h,0,sizeof(*h));
    h->data = data;
    h->data_size = data_size;

    enumError err = nkit_disc_header_parse_ptab(data,data_size,NKIT_PTAB_OFFSET,&h->part,&h->n_part);
    if (err)
	return err;
    h->max_part = h->n_part;
    h->has_update_partition = h->n_part && h->part[0].type == NKIT_PART_UPDATE;
    return ERR_OK;
}

static void nkit_disc_header_reset_mem ( nkit_disc_header_t *h )
{
    if (h->part)
	FREE(h->part);
    memset(h,0,sizeof(*h));
}

///////////////////////////////////////////////////////////////////////////////

static int nkit_part_info_cmp ( const void *pa, const void *pb )
{
    const nkit_part_info_t *a = pa, *b = pb;
    // offsetSortFix(): a zero-offset placeholder sorts by (0xF800000 + type)
    // instead of 0, so brand-new placeholder partitions land after every
    // real one instead of all piling up at the front.
    u64 ka = a->disc_offset ? a->disc_offset : 0xF800000ull + a->type;
    u64 kb = b->disc_offset ? b->disc_offset : 0xF800000ull + b->type;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
}

// UpdateRepair(): re-sort by disc offset (with the placeholder fixup),
// renumber every table's count+first-entry-offset fields, and rewrite every
// partition's (offset,type) pair -- direct port, including the "shift every
// non-update partition up by a fixed amount so partition data always starts
// at 0xF800000" placeholder-insertion behaviour.
static void nkit_disc_header_update_repair ( nkit_disc_header_t *h )
{
    qsort(h->part,h->n_part,sizeof(*h->part),nkit_part_info_cmp);

    memset(h->data+0x60,0,2);
    memset(h->data+NKIT_PTAB_OFFSET,0,NKIT_PTAB_LENGTH);

    u64 part_offset_fix = 0;
    int first_non_update = -1;
    for ( uint i = 0; i < h->n_part; i++ )
	if ( h->part[i].type != NKIT_PART_UPDATE ) { first_non_update = i; break; }

    if ( first_non_update >= 0 && h->part[first_non_update].disc_offset < 0xF800000ull )
    {
	part_offset_fix = 0xF800000ull - h->part[first_non_update].disc_offset;
	for ( uint i = 0; i < h->n_part; i++ )
	    if ( h->part[i].type != NKIT_PART_UPDATE )
		h->part[i].disc_offset += part_offset_fix;
    }

    // group by table, in the now-sorted order (tables need not be
    // contiguous per-group in general, but NKit's own grouping is a stable
    // GroupBy over the sorted list, which for <=4 tables x <=4 entries is
    // simplest to reproduce with a small fixed-size bucket pass)
    for ( int table_idx = 0; table_idx < 4; table_idx++ )
    {
	uint count = 0;
	for ( uint i = 0; i < h->n_part; i++ )
	    if ( h->part[i].table == table_idx )
		count++;
	if (!count)
	    continue;

	int offset = 0x40020 + table_idx*0x20;
	write_be32(h->data+NKIT_PTAB_OFFSET+table_idx*8,count);
	write_be32(h->data+NKIT_PTAB_OFFSET+table_idx*8+4,offset/4);

	offset -= 4;
	for ( uint i = 0; i < h->n_part; i++ )
	{
	    if ( h->part[i].table != table_idx )
		continue;
	    offset += 4;
	    write_be32(h->data+offset,(u32)(h->part[i].disc_offset/4));
	    h->part[i].table_offset = offset;
	    offset += 4;
	    write_be32(h->data+offset,(u32)h->part[i].type);
	}
    }
}

// UpdateOffsets(): cheaper variant that only rewrites the disc-offset half
// of each entry (used when partitions moved but the table shape didn't).
static void nkit_disc_header_update_offsets ( nkit_disc_header_t *h )
{
    for ( uint i = 0; i < h->n_part; i++ )
	write_be32(h->data+h->part[i].table_offset,(u32)(h->part[i].disc_offset/4));
}

// RemoveUpdatePartition(long baseAddress): drop partition 0 if it's the
// update partition, then rebuild the table (a lighter version of
// UpdateRepair() that skips the placeholder-offset fixup since there's
// nothing new to place).
static void nkit_disc_header_remove_update_partition ( nkit_disc_header_t *h )
{
    if ( !h->n_part || h->part[0].type != NKIT_PART_UPDATE )
	return;
    memmove(h->part,h->part+1,(--h->n_part)*sizeof(*h->part));

    memset(h->data+0x60,0,2);
    memset(h->data+NKIT_PTAB_OFFSET,0,NKIT_PTAB_LENGTH);

    for ( int table_idx = 0; table_idx < 4; table_idx++ )
    {
	uint count = 0;
	for ( uint i = 0; i < h->n_part; i++ )
	    if ( h->part[i].table == table_idx )
		count++;
	if (!count)
	    continue;
	int offset = NKIT_PTAB_OFFSET + 0x20 + table_idx*0x20;
	write_be32(h->data+NKIT_PTAB_OFFSET+table_idx*8,count);
	write_be32(h->data+NKIT_PTAB_OFFSET+table_idx*8+4,offset/4);
	offset -= 4;
	for ( uint i = 0; i < h->n_part; i++ )
	{
	    if ( h->part[i].table != table_idx )
		continue;
	    offset += 4;
	    write_be32(h->data+offset,(u32)(h->part[i].disc_offset/4));
	    h->part[i].table_offset = offset;
	    offset += 4;
	    write_be32(h->data+offset,(u32)h->part[i].type);
	}
    }
}

//
///////////////////////////////////////////////////////////////////////////////
///////////  WiiPartitionHeaderSection.cs -> nkit_part_header_t		///////////
///////////////////////////////////////////////////////////////////////////////

// Bookkeeping port of WiiPartitionHeaderSection: pulls the fields
// NkitReaderWii.cs (not itself ported yet) needs out of one partition's raw
// header (ticket + tmd + cert + h3 blob), and derives the AES title key.
//
// The C# class hand-decodes its own copy of the 3 Wii disc common keys via
// a base64-encoded, byte-interleaved "_lame" constant (its own words: this
// is deliberate obfuscation in the original source, not a mistake) and does
// its own AES-ECB title-key unwrap. Per the task's explicit instruction not
// to duplicate that key material anywhere in this codebase, this port
// instead calls wd_get_common_key()/wd_decrypt_title_key() from
// libwbfs/wiidisc.c, which already hold the real keys (WD_CKEY_STANDARD,
// WD_CKEY_KOREAN, WD_CKEY_RVT-equivalent index -- see wd_ckey_index_t in
// wiidisc.h) and already implement the exact same unwrap.
typedef struct nkit_part_header_t
{
    bool		is_encrypted;	// IsEncrypted
    u8			*h3_table;	// H3Table: WII_H3_SIZE bytes if present, NULL otherwise, owned
    u8			key[WII_KEY_SIZE]; // Key: decrypted AES title key
    u64			partition_size;	// PartitionSize
    u64			partition_data_size; // PartitionDataSize
    bool		is_korean;	// IsKorean
    bool		is_rvt;		// IsRvt
    bool		is_rvt_r;	// IsRvtR
    bool		is_rvt_h;	// IsRvtH -- unsupported RVT-H image; caller must bail like the C# ctor's early return
    u8			content_sha1[WII_HASH_SIZE]; // ContentSha1: tmd content[0] hash, if a tmd is present
    bool		has_content_sha1;
    u64			fst_offset;	// FstOffset
    u64			fst_size;	// FstSize

    // DecryptedScrubbed00/DecryptedScrubbedFF: what an all-0x00 (resp.
    // all-0xFF) 16-byte encrypted block decrypts to under this partition's
    // title key with IV==the same all-0x00/all-0xFF pattern -- i.e. what a
    // properly *scrubbed* (junk-filled) sector's hash area looks like once
    // decrypted. Computed once here (ctor tail, "decrypt scrubbed values"
    // comment in the C#) and handed to nkit_scrub_manager_t below, which is
    // the only consumer.
    u8			decrypted_00[WII_KEY_SIZE];
    u8			decrypted_ff[WII_KEY_SIZE];
}
nkit_part_header_t;

///////////////////////////////////////////////////////////////////////////////

// ctor: WiiPartitionHeaderSection(...) -- takes the raw partition header
// bytes ('data', at least 0x2c0 bytes, ideally the full ph.tmd/h3 region)
// and the partition's absolute disc offset (only used by the C# to look up
// its own Type via the disc's partition table; not needed for this
// bookkeeping-only port so it's omitted here).
static enumError nkit_part_header_init ( nkit_part_header_t *ph, const u8 *data, uint data_size )
{
    memset(ph,0,sizeof(*ph));

    if ( data_size < 0x2c0 )
	return ERROR0(ERR_WIA_INVALID,"NKit: partition header too small\n");

    u32 data_off4  = be32(data+0x2b8);
    ph->partition_size = (u64)be32(data+0x2bc) * 4;
    // NStream.HashedLenToData(): 0x7c00 data bytes per 0x8000 hashed bytes
    ph->partition_data_size = ph->partition_size / WII_SECTOR_SIZE * WII_SECTOR_DATA_SIZE;
    (void)data_off4;

    u32 h3_off  = be32(data+0x2b4) * 4;
    u32 tmd_off = be32(data+0x2a8) * 4;
    if ( h3_off && (u64)h3_off + WII_H3_SIZE <= data_size )
    {
	ph->h3_table = MALLOC(WII_H3_SIZE);
	memcpy(ph->h3_table,data+h3_off,WII_H3_SIZE);
    }
    if ( tmd_off && (u64)tmd_off + 0x1e4 + 0x10 + WII_HASH_SIZE <= data_size )
    {
	memcpy(ph->content_sha1,data+tmd_off+0x1e4+0x10,WII_HASH_SIZE);
	ph->has_content_sha1 = true;
    }

    // Determine the common key to use -- same issuer-string/Korean-flag
    // tests as the C#, but selecting an existing wd_ckey_index_t instead of
    // decoding a hardcoded key.
    char issuer[65];
    memcpy(issuer,data+0x140,64);
    issuer[64] = 0;
    // trim trailing NULs like TrimEnd('\0')
    for ( int i = 63; i >= 0 && !issuer[i]; i-- ) issuer[i] = 0;

    ph->is_rvt     = !strcmp(issuer,"Root-CA00000002-XS00000006");
    ph->is_korean  = !ph->is_rvt && data[0x1f1] == 1;
    ph->is_rvt_h   = ph->is_rvt && ph->partition_size == 0;
    ph->is_rvt_r   = !ph->is_rvt_h && ph->is_rvt;

    if (ph->is_rvt_h)
	return ERR_OK;	// "notsupported" -- matches the C# ctor's early return; caller must check is_rvt_h

    // No RVT (debug/RVT-R) common key exists anywhere in this codebase --
    // this repo's wd_ckey_index_t only carries WD_CKEY_STANDARD and
    // WD_CKEY_KOREA (see libwbfs/wiidisc.h; a WD_CKEY_DEVELOPER slot exists
    // but is compiled out unless built with -DTEST, and even then it is
    // NOT the same key NKit's RVT branch uses). Per the task instructions,
    // no key is invented here: an RVT partition is treated as unsupported,
    // same as the is_rvt_h case above. A real RVT-signed retail-adjacent
    // disc is not expected to reach this path in practice.
    if (ph->is_rvt)
    {
	ph->is_rvt_h = true;	// reuse the existing "unsupported, caller must bail" flag
	return ERR_OK;
    }

    // wd_ticket_t's packed layout (libwbfs/file-formats.h) matches the raw
    // partition header byte-for-byte at this offset (sig_type at +0x000
    // through fake_sign at +0x24c, incl. title_key at +0x1bf, title_id at
    // +0x1dc and common_key_index at +0x1f1) -- it IS the disc's ticket, so
    // no field-by-field copy is needed; just view the header bytes as one.
    // wd_decrypt_title_key() reads tik->common_key_index itself and looks
    // up the matching real common key via wd_get_common_key() internally.
    const wd_ticket_t *tik = (const wd_ticket_t *)data;
    wd_decrypt_title_key(tik,ph->key);

    // "decrypt scrubbed values" tail of the C# ctor: decrypt one all-0xFF
    // block with IV=all-0xFF, then one all-0x00 block with IV=all-0x00,
    // both under this partition's title key. Only used by
    // nkit_scrub_manager_t's IsScrubbed()-equivalent block comparisons.
    aes_key_t akey;
    wd_aes_set_key(&akey,ph->key);

    u8 ff_block[WII_KEY_SIZE];
    memset(ff_block,0xff,sizeof(ff_block));
    wd_aes_decrypt(&akey,ff_block,ff_block,ph->decrypted_ff,WII_KEY_SIZE);

    u8 zero_block[WII_KEY_SIZE];
    memset(zero_block,0,sizeof(zero_block));
    wd_aes_decrypt(&akey,zero_block,zero_block,ph->decrypted_00,WII_KEY_SIZE);

    return ERR_OK;
}

static void nkit_part_header_reset_mem ( nkit_part_header_t *ph )
{
    if (ph->h3_table)
	FREE(ph->h3_table);
    memset(ph,0,sizeof(*ph));
}

//
///////////////////////////////////////////////////////////////////////////////
///////////	 WiiPartitionSection.cs -> nkit_partition_t (bookkeeping)	///////////
///////////////////////////////////////////////////////////////////////////////

#define NKIT_PARTITION_GROUP_SIZE  (WII_SECTOR_SIZE*WII_GROUP_SECTORS)  // WiiPartitionSection.GroupSize

// Bookkeeping-only port of WiiPartitionSection: which group is "current",
// the running source-stream position, and the deferred seek-to-file offset
// NkitReaderWii.cs's SeekToFile()/Sections iterator drive. Does not itself
// perform any I/O yet -- no NStream equivalent exists in wit's C code, and
// building one is squarely stage 2/3 territory (the actual restore driver).
typedef struct nkit_partition_t
{
    nkit_part_header_t	header;		// Header
    u64			new_partition_data_length; // NewPartitionDataLength
    u64			new_disc_offset;	// NewDiscOffset
    u8			*new_fst;		// NewFst, owned if set
    u64			new_fst_size;
    u64			disc_offset;		// DiscOffset (== header's)
    u64			size;			// Size = header.Size + header.PartitionSize
    u64			seek;			// _seek: pending SeekToFile() target, or (u64)-1 if none
}
nkit_partition_t;

// SeekToFile(FstFile file): round down to the group boundary within the partition.
static void nkit_partition_seek_to_file ( nkit_partition_t *p, u64 file_offset )
{
    p->seek = file_offset - file_offset % NKIT_PARTITION_GROUP_SIZE;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////  WiiPartitionGroupSection.cs -> nkit_group_t (bookkeeping)	///////////
///////////////////////////////////////////////////////////////////////////////

// Bookkeeping-only port of WiiPartitionGroupSection: wraps one
// nkit_group_crypt_t with the group's position within its partition
// (Offset/DataOffset/H3Errors) and exposes the same PreserveHashes()
// decision the C# makes (used by the -- not yet ported -- unscrub pass to
// decide whether a group's hashes need to be carried in the .nkit.iso
// stream verbatim instead of being regenerable from junk).
typedef struct nkit_group_t
{
    nkit_group_crypt_t	crypt;		// _data
    int			idx;		// _idx: group index within the partition
    u64			offset;		// Offset = idx * max_length
    u64			data_offset;	// DataOffset = idx * WII_GROUP_SECTORS * WII_SECTOR_DATA_SIZE
    uint		h3_errors;	// H3Errors
    bool		is_encrypted;	// IsEncrypted
    bool		is_iso_dec;	// _isIsoDec
}
nkit_group_t;

// PreserveHashes(): true if this group's hash area can't be trusted to
// regenerate byte-identically from junk alone and must be preserved
// verbatim in the .nkit.iso stream -- direct port of the decision tree
// (partially-scrubbed groups, groups touching a real file's data, and
// groups that fail the fast hash check all force preservation).
static bool nkit_group_preserve_hashes ( nkit_group_t *g, bool any_file_touches_group )
{
    uint scrubbed = nkit_group_crypt_scrubbed_blocks(&g->crypt);
    if ( scrubbed != 0 && scrubbed < g->crypt.used_blocks )
	return true;

    bool used_scrubbed = scrubbed == g->crypt.used_blocks && any_file_touches_group;
    if (used_scrubbed)
	return true;

    if ( scrubbed == g->crypt.used_blocks )
	return !nkit_group_crypt_all_scrubbed_same_byte(&g->crypt);

    // FastHashIsValid(): full port omitted here (it re-derives every H0
    // against decrypted data plus the H1/H2/blank-area checks
    // WiiPartitionGroupEncryptionState.FastHashIsValid() does inline) --
    // callers needing it can compose it from nkit_group_crypt_block_is_valid()
    // + nkit_group_crypt_is_valid() above, which already implement the same
    // primitives this would need.
    return !nkit_group_crypt_is_valid(&g->crypt,false);
}

//
///////////////////////////////////////////////////////////////////////////////
///////////		WiiFillerSection.cs -> nkit_filler_t		///////////
///////////////////////////////////////////////////////////////////////////////

// Bookkeeping port of WiiFillerSection: the flags controlling how the
// padding between the last partition and the end of the disc (or between
// the update partition and the rest, when it's being swapped out) is
// sourced -- read verbatim from the source image, or regenerated as junk.
// No NStream/JunkStream driver wiring here yet, same reasoning as
// nkit_partition_t above.
typedef struct nkit_filler_t
{
    u64			disc_offset;		// DiscOffset
    u64			size;			// Size
    u64			src_size;		// _srcSize = size - updateSkip
    bool		generate_update_filler;	// _generateUpdateFiller
    bool		generate_other_filler;	// _generateOtherFiller
    bool		force_filler_junk;	// _forceFillerJunk
    bool		update_partition;	// _updatePartiton
}
nkit_filler_t;

// ctor: WiiFillerSection(..., bool updatePartition, long discOffset, long size,
//                         long updateSkip, ..., bool generateUpdateFiller,
//                         bool generateOtherFiller, bool forceFillerJunk)
static void nkit_filler_init
(
    nkit_filler_t	*f,
    bool		update_partition,
    u64			disc_offset,
    u64			size,
    u64			update_skip,
    bool		generate_update_filler,
    bool		generate_other_filler,
    bool		force_filler_junk
)
{
    f->disc_offset = disc_offset;
    f->size = size;
    f->src_size = size - update_skip;
    f->generate_update_filler = generate_update_filler || size > f->src_size;
    f->generate_other_filler = generate_other_filler;
    f->force_filler_junk = force_filler_junk;
    f->update_partition = update_partition;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////	   WiiHashStore.cs -> nkit_hash_store_t			///////////
///////////////////////////////////////////////////////////////////////////////

// Direct port of WiiHashStore: a bitmap of which groups had their hash area
// preserved (one bit per NKIT_PARTITION_GROUP_SIZE-aligned group, matching
// PreserveHashes() above) plus the flat stream of preserved 0x400 byte hash
// areas themselves, in group order.
typedef struct nkit_hash_store_t
{
    u8			*flags;		// _flags: intsCount()*4 bytes, owned
    uint		flags_size;
    u64			partition_size;	// _partitionSize

    u8			*hashes;		// _hashes: growable buffer of preserved 0x400 byte hash areas, owned
    uint		hashes_len;
    uint		hashes_cap;
}
nkit_hash_store_t;

///////////////////////////////////////////////////////////////////////////////

// intsCount(long partitionDataSize): number of 32 bit flag words needed,
// one bit per group.
static uint nkit_hash_store_ints_count ( nkit_hash_store_t *hs, u64 partition_data_size )
{
    u64 size = partition_data_size / WII_SECTOR_DATA_SIZE * WII_SECTOR_SIZE;
    hs->partition_size = size;
    u64 groups = size / NKIT_PARTITION_GROUP_SIZE + ( size % NKIT_PARTITION_GROUP_SIZE ? 1 : 0 );
    return (uint)( groups/32 + ( groups%32 ? 1 : 0 ) );
}

// ctor: WiiHashStore(long partitionDataSize)
static void nkit_hash_store_init ( nkit_hash_store_t *hs, u64 partition_data_size )
{
    memset(hs,0,sizeof(*hs));
    hs->flags_size = nkit_hash_store_ints_count(hs,partition_data_size) * 4;
    hs->flags = MALLOC(hs->flags_size);
    memset(hs->flags,0,hs->flags_size);
}

static void nkit_hash_store_reset_mem ( nkit_hash_store_t *hs )
{
    if (hs->flags)  FREE(hs->flags);
    if (hs->hashes) FREE(hs->hashes);
    memset(hs,0,sizeof(*hs));
}

///////////////////////////////////////////////////////////////////////////////

// Preserve(long offset, byte[] decrypted, long size): flag this group as
// preserved and append its per-block 0x400 byte hash areas (one per
// WII_SECTOR_SIZE-aligned block within 'decrypted') to the hash stream.
static u64 nkit_hash_store_preserve ( nkit_hash_store_t *hs, u64 offset, const u8 *decrypted, u64 size )
{
    uint x = (uint)( offset / NKIT_PARTITION_GROUP_SIZE );
    uint byt = x/8, bit = 1 << (7-(x%8));
    hs->flags[byt] |= bit;

    u64 written = 0;
    for ( u64 i = 0; i+WII_SECTOR_HASH_SIZE <= size; i += WII_SECTOR_SIZE )
    {
	if ( hs->hashes_len + WII_SECTOR_HASH_SIZE > hs->hashes_cap )
	{
	    hs->hashes_cap = hs->hashes_cap ? hs->hashes_cap*2 : 0x10000;
	    hs->hashes = REALLOC(hs->hashes,hs->hashes_cap);
	}
	memcpy(hs->hashes+hs->hashes_len,decrypted+i,WII_SECTOR_HASH_SIZE);
	hs->hashes_len += WII_SECTOR_HASH_SIZE;
	written += WII_SECTOR_HASH_SIZE;
    }
    return written;
}

// IsPreserved(long offset)
static bool nkit_hash_store_is_preserved ( const nkit_hash_store_t *hs, u64 offset )
{
    uint x = (uint)( offset / NKIT_PARTITION_GROUP_SIZE );
    uint byt = x/8;
    if ( !hs->flags || hs->flags_size <= byt )
	return false;
    uint bit = 1 << (7-(x%8));
    return ( hs->flags[byt] & bit ) != 0;
}

// FlagsToByteArray() / FlagsLength
static const u8 * nkit_hash_store_flags ( const nkit_hash_store_t *hs, uint *len )
{
    *len = hs->flags_size;
    return hs->flags;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////    ScrubManager.cs -> nkit_scrub_manager_t (STAGE 2a)    ///////////////
///////////////////////////////////////////////////////////////////////////////

// STAGE 2a of the Wii restore port. Everything above this point is stage 1
// (bookkeeping/AES/hash-tree types, unused/uncalled). This section adds the
// two pieces NkitReaderWii.cs itself needs that stage 1 didn't provide:
// ScrubManager (below) and StreamCircularBuffer (further down). There is
// STILL no NkitRestoreWii() and nothing here is wired into XCONVERT --
// that's stage 2b. Ported from the real github.com/Nanook/NKitv1 source
// (MIT-licensed), cross-checked against every call site in
// NkitReaderWii.cs (grepped for ScrubManager/IsBlockScrubbedScanMode/
// IsBlockScrubbed/AddGap/.Scrub()/StreamCircularBuffer).
//
// ScrubManager tracks which regions of a partition's *decrypted* data are
// regenerable junk (all-0x00 or all-0xFF once decrypted -- see
// nkit_part_header_t.decrypted_00/decrypted_ff above, which only exist
// because this type needs them) versus real file data that must be
// preserved byte-for-byte. The restore driver (stage 2b) will call
// nkit_scrub_manager_scrub() while writing scrubbed gaps back out, then
// nkit_scrub_manager_is_block_scrubbed_scan_mode() while re-encrypting/
// re-hashing the partition sequentially forward, and
// nkit_scrub_manager_add_gap() while it discovers trailing-null runs in
// the H3 table's 28-byte-per-block pattern.
//
// Only the call sites actually reachable from NkitReaderWii.cs are ported:
// IsScrubbed() (used only by the *writer*/image-creation side, per grep of
// NkitWriterGc.cs/NkitWriterWii.cs) is intentionally NOT ported here -- do
// not add it speculatively; if stage 2b turns out to need it after all,
// port it then, straight off ScrubManager.cs:56-114 in the clone.

// Direct port of the private nested 'ScrubRegion' class.
typedef struct nkit_scrub_region_t
{
    u64		offset;		// Offset (already scaled to the *hashed*/on-disc
				// 0x8000-per-block domain by add(), see below)
    u64		length;		// Length
    u8		byt;		// Byte
}
nkit_scrub_region_t;

///////////////////////////////////////////////////////////////////////////////

// Direct port of ScrubManager. C#'s Queue<ScrubRegion> _scrub (drained by
// IsBlockScrubbedScanMode) and List<ScrubRegion> _cache (kept intact for
// IsBlockScrubbed) are two views over the exact same append-only sequence
// of regions -- add() enqueues into _scrub AND appends to _cache in the
// same call, and nothing in the whole class ever removes a *_cache* entry.
// Since this port is single-threaded (no concurrent producer/consumer
// unlike the C# original -- see the StreamCircularBuffer notes below for
// why that's fine here), one owned growable array replaces both: 'region'
// holds every region ever added (== _cache), and 'scan_cursor' is the
// "next to dequeue" index that IsBlockScrubbedScanMode advances (== _scrub
// draining, but non-destructively so _cache semantics fall out for free).
typedef struct nkit_scrub_manager_t
{
    nkit_scrub_region_t	*region;	// _cache (== also backs _scrub), owned, growable
    uint		count;		// regions used
    uint		capacity;	// regions allocated
    uint		scan_cursor;	// index of the region IsBlockScrubbedScanMode
					// will inspect next (mirrors _next after a
					// Dequeue(); an index survives realloc, a
					// C#-style pointer would not)
    int			last_idx;	// index of _last, or -1 if none yet

    bool		is_wii_partition; // _wiiPartition
    const u8		*decrypted_00;	// _00.Decrypted: nkit_part_header_t.decrypted_00,
					// NOT owned, NULL only if !is_wii_partition
    const u8		*decrypted_ff;	// _FF.Decrypted: nkit_part_header_t.decrypted_ff

    // H3Nulls: list of (offset, len) trailing-null runs AddGap() detects.
    // The C# tuple's 3rd element (FstFile) is always passed null from every
    // AddGap() call site reachable off the restore path (NkitReaderWii.cs's
    // own writeGap() calls it with no file context) -- dropped here as a
    // result; add it back only if a real caller is found that needs it.
    struct { u64 offset; int len; } *h3_null;
    uint		h3_null_count, h3_null_cap;
}
nkit_scrub_manager_t;

///////////////////////////////////////////////////////////////////////////////

// ctor: ScrubManager() / ScrubManager(WiiPartitionHeaderSection header).
// Pass header_decrypted_00/header_decrypted_ff both NULL for the "not a
// Wii partition" (GC / non-encrypted) case -- matches ScrubManager(null),
// e.g. NkitWriterGc.cs's plain ScrubManager() or NkitReaderWii.cs:51's
// ScrubManager(null) "scrubFiller".
static void nkit_scrub_manager_init ( nkit_scrub_manager_t *sm,
    bool is_wii_partition, const u8 decrypted_00[WII_KEY_SIZE], const u8 decrypted_ff[WII_KEY_SIZE] )
{
    memset(sm,0,sizeof(*sm));
    sm->last_idx = -1;
    sm->is_wii_partition = is_wii_partition;
    sm->decrypted_00 = is_wii_partition ? decrypted_00 : 0;
    sm->decrypted_ff = is_wii_partition ? decrypted_ff : 0;
}

static void nkit_scrub_manager_reset_mem ( nkit_scrub_manager_t *sm )
{
    if (sm->region)  FREE(sm->region);
    if (sm->h3_null) FREE(sm->h3_null);
    memset(sm,0,sizeof(*sm));
}

///////////////////////////////////////////////////////////////////////////////

// private add(long offset, long length, byte b) -- called from Scrub().
// Rounds to the enclosing 0x7c00-byte (WII_SECTOR_DATA_SIZE) *data* block,
// pads the length up to a block boundary, then rescales both from the
// 0x7c00 data domain to the 0x8000 (WII_SECTOR_SIZE) on-disc/hashed
// domain -- exactly like the C# (literal 0x7c00L/0x8000L there; named
// constants here since this file already has them). Extends the previous
// region in place if it's contiguous and the same fill byte, else appends
// a new one.
static void nkit_scrub_manager_add ( nkit_scrub_manager_t *sm, u64 offset, u64 length, u8 b )
{
    if ( offset % WII_SECTOR_DATA_SIZE )
    {
	length += offset % WII_SECTOR_DATA_SIZE;
	offset -= offset % WII_SECTOR_DATA_SIZE;
    }
    if ( length % WII_SECTOR_DATA_SIZE )
	length += WII_SECTOR_DATA_SIZE - length % WII_SECTOR_DATA_SIZE;

    offset = offset / WII_SECTOR_DATA_SIZE * WII_SECTOR_SIZE;
    length = length / WII_SECTOR_DATA_SIZE * WII_SECTOR_SIZE;

    nkit_scrub_region_t *last = sm->last_idx >= 0 ? sm->region+sm->last_idx : 0;
    if ( last && last->byt == b && offset >= last->offset && offset <= last->offset+last->length )
    {
	if ( offset+length > last->offset+last->length )
	    last->length = offset+length - last->offset;
	return;
    }

    if ( sm->count == sm->capacity )
    {
	sm->capacity = sm->capacity ? sm->capacity*2 : 64;
	sm->region = REALLOC(sm->region,sm->capacity*sizeof(*sm->region));
    }
    nkit_scrub_region_t *r = sm->region + sm->count;
    r->offset = offset;
    r->length = length;
    r->byt    = b;
    sm->last_idx = sm->count;
    sm->count++;
}

///////////////////////////////////////////////////////////////////////////////

// Scrub(Stream stream, long partitionDataOffset, long size, byte scrubByte):
// write 'size' bytes of the scrub pattern for 'scrubByte' to the write
// callback, and (Wii-partition case only) record the region via add().
//
// The C# streams through a ByteStream (Zeros/Fives/FFs, or _00/_FF for the
// Wii-partition decrypted-pattern case) via Utils.Copy()'s double-buffered
// 0x200000-byte pump. There's no Stream to hand a pattern-generator to in
// C, so 'write' is called directly with successive chunks of a stack
// buffer filled from the pattern -- same bytes, same order, just produced
// eagerly into 'write' instead of read lazily off a fake Stream.
typedef enumError (*nkit_write_func) ( void *ctx, const u8 *data, u32 size );

static enumError nkit_scrub_manager_scrub ( nkit_scrub_manager_t *sm,
    nkit_write_func write, void *ctx, u64 partition_data_offset, u64 size, u8 scrub_byte )
{
    if (sm->is_wii_partition)
    {
	if ( scrub_byte != 0x00 && scrub_byte != 0xff )
	    return ERROR0(ERR_WIA_INVALID,
		"NKit: Wii partition scrubbing does not support byte 0x%02x\n",scrub_byte);
	nkit_scrub_manager_add(sm,partition_data_offset,size,scrub_byte);
    }

    const u8 *pat = 0;		// non-NULL: 16-byte repeating decrypted pattern (Wii case)
    if (sm->is_wii_partition)
	pat = scrub_byte == 0x00 ? sm->decrypted_00 : sm->decrypted_ff;

    enum { CHUNK = 0x200000 };	// Utils.Copy()'s buffer size
    u8 buf[CHUNK];
    if (!pat)
	memset(buf,scrub_byte,sizeof(buf));

    while (size)
    {
	u32 n = (u32)( size < CHUNK ? size : CHUNK );
	if (pat)
	{
	    // 16-byte repeating decrypted pattern, not necessarily
	    // buffer-aligned to 16 -- matches ByteStream.Read()'s running
	    // 'x' index (here always starting at 0 since Scrub() always
	    // begins each call at a fresh chunk of the pattern stream, the
	    // same way ByteStream's Position tracks continuously across
	    // calls but WII_KEY_SIZE-periodic content makes any 16-aligned
	    // start equivalent).
	    for ( u32 i = 0; i < n; i++ )
		buf[i] = pat[i % WII_KEY_SIZE];
	}
	enumError err = write(ctx,buf,n);
	if (err)
	    return err;
	size -= n;
    }
    return ERR_OK;
}

///////////////////////////////////////////////////////////////////////////////

// AddGap(long fileLength, long gapOffset, long gapLength): record a
// trailing run of nulls inside the H3 table's 28-byte-per-0x7c00-block
// pattern (H3 entries are 20 bytes of hash + 8 bytes padding = 28 used out
// of some larger stride -- see the original for the exact derivation this
// mirrors verbatim).
static void nkit_scrub_manager_add_gap ( nkit_scrub_manager_t *sm, u64 file_length, u64 gap_offset, u64 gap_length )
{
    u64 s = (gap_offset + 28) % WII_SECTOR_DATA_SIZE;

    if ( file_length == 0 )
    {
	if ( sm->h3_null_count == sm->h3_null_cap )
	{
	    sm->h3_null_cap = sm->h3_null_cap ? sm->h3_null_cap*2 : 16;
	    sm->h3_null = REALLOC(sm->h3_null,sm->h3_null_cap*sizeof(*sm->h3_null));
	}
	sm->h3_null[sm->h3_null_count].offset = gap_offset;
	sm->h3_null[sm->h3_null_count].len    = (int)( gap_length < 28 ? gap_length : 28 );
	sm->h3_null_count++;
    }
    else if ( s <= 28 && gap_length - (28-s) >= WII_SECTOR_DATA_SIZE ) // nulls spill to next block and length > block
    {
	if ( sm->h3_null_count == sm->h3_null_cap )
	{
	    sm->h3_null_cap = sm->h3_null_cap ? sm->h3_null_cap*2 : 16;
	    sm->h3_null = REALLOC(sm->h3_null,sm->h3_null_cap*sizeof(*sm->h3_null));
	}
	sm->h3_null[sm->h3_null_count].offset = gap_offset + (28-s);
	sm->h3_null[sm->h3_null_count].len    = (int)s;
	sm->h3_null_count++;
    }
}

///////////////////////////////////////////////////////////////////////////////

// private isBlockScrubbed(ScrubRegion, offset, out scrubByte)
static bool nkit_scrub_manager_region_hit ( const nkit_scrub_region_t *r, u64 offset, u8 *scrub_byte )
{
    *scrub_byte = 0;
    if ( r && offset >= r->offset && offset < r->offset+r->length )
    {
	*scrub_byte = r->byt;
	return true;
    }
    return false;
}

// IsBlockScrubbedScanMode(long offset, out byte scrubByte): forward-only
// scan -- advances scan_cursor past any region whose range has already
// been left behind, exactly like the C# dequeuing a new _next once the old
// one's range no longer covers 'offset'.
static bool nkit_scrub_manager_is_block_scrubbed_scan_mode ( nkit_scrub_manager_t *sm, u64 offset, u8 *scrub_byte )
{
    nkit_scrub_region_t *next = sm->scan_cursor < sm->count ? sm->region+sm->scan_cursor : 0;
    if ( !next || next->offset+next->length < offset )
    {
	if ( sm->scan_cursor < sm->count )
	    sm->scan_cursor++;
	next = sm->scan_cursor < sm->count ? sm->region+sm->scan_cursor : 0;
    }
    return nkit_scrub_manager_region_hit(next,offset,scrub_byte);
}

// IsBlockScrubbed(long offset, out byte scrubByte): full linear scan of
// every region ever added, order-independent (first match wins, same as
// the C# foreach).
static bool nkit_scrub_manager_is_block_scrubbed ( const nkit_scrub_manager_t *sm, u64 offset, u8 *scrub_byte )
{
    *scrub_byte = 0;
    for ( uint i = 0; i < sm->count; i++ )
	if ( nkit_scrub_manager_region_hit(sm->region+i,offset,scrub_byte) )
	    return true;
    return false;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////  StreamCircularBuffer.cs -> nkit_circular_buffer_t (STAGE 2a) ///////////////
///////////////////////////////////////////////////////////////////////////////

// NkitReaderWii.cs uses StreamCircularBuffer exactly once (around line 126
// of the clone): it hands a *writer callback* -- partitionStreamWrite(),
// which walks a partition's files/gaps/junk and pushes decrypted bytes
// forward -- to a background Task, and reads the result back out through
// the Stream interface on the calling (main) thread, while the writer
// Task races ahead filling the ring and blocking (Monitor.Wait) whenever
// it gets more than one buffer's worth of lead. The buffer's whole reason
// to exist in C# is to let those two loops run on separate OS threads
// without needing (size-of-partition) memory: the reader can pull data as
// slowly as its own destination I/O allows while the producer keeps
// generating in the background.
//
// This codebase (x-nkit.c's GC path, lib-wia.c's RVZ reader, and every
// other reader/writer here) has no equivalent background-thread pattern
// anywhere -- everything is one synchronous call stack, one FILE* at a
// time. Introducing real OS threads here for this one call site would be
// a bigger behavioral change than a "port", and isn't needed: nothing
// about partitionStreamWrite()'s *output bytes* depends on it running
// concurrently with the reader -- concurrency there is a C# performance
// detail (I/O overlap), not part of what makes restored output correct.
//
// So this port keeps the ring-buffer *data structure* (fixed-capacity
// byte ring, monotonic read/write position counters, the forward-only
// Seek() skip-ahead trick used by SeekToFile()) but drops the threading:
// nkit_circular_buffer_write()/_read() are plain, non-blocking,
// same-thread cursor operations. Where C#'s Write() would block
// (Monitor.Wait) until the reader drains room, this port's write simply
// copies as much as currently fits and returns the short count -- it is
// the stage 2b driver's job to interleave "call write with whatever's
// left" and "call read to drain" in one synchronous loop, the same way
// every other staged-I/O loop in this codebase (e.g. x-nkit.c's
// nkit_decode_gap()) already pumps a fixed buffer forward. That is a
// faithful behavioral equivalent of the C# for a single-threaded caller:
// the *sequence and byte content* the reader ends up seeing is identical
// (same ring math, same seek-discard rule below), only the scheduling
// (background thread vs. explicit caller-driven steps) differs, and nkit
// restoration has no external concurrency requirement to preserve.
//
// IProgress.Value (float read-progress getter, cosmetic UI only) and the
// Dispose()-time "wait for writer thread to actually exit, then close the
// wrapped source stream" teardown are both artifacts of the threaded
// design and are NOT ported -- there is no background thread to wait for,
// and the source stream lifetime is the stage 2b driver's job.
typedef struct nkit_circular_buffer_t
{
    u8		*buf;		// _b, owned
    u32		capacity;	// sizeof(*buf) allocated (caller-chosen; C# used a
				// fixed, oversized-for-double-buffering 0x500000)
    u32		r, w;		// _r, _w: byte cursors into buf, each 0..capacity-1

    u64		size;		// _size: total expected stream length, 0 == unbounded
    u64		r_position;	// _rPosition: total bytes handed out via read() so far
    u64		w_position;	// _wPosition: total bytes accepted via write() so far
    s64		seek_position;	// _seekPosition: -1 == not mid-seek
    bool	writing_complete; // _writingComplete
}
nkit_circular_buffer_t;

///////////////////////////////////////////////////////////////////////////////

// ctor: StreamCircularBuffer(long size, Stream stream, IDisposable dispose,
// Action<Stream> write). Only 'size' (-1 -> unbounded here, since there's
// no wrapped source Stream.Length to default to) and the ring capacity
// carry over; 'stream'/'dispose'/'write' were background-thread plumbing,
// see the file-header note above for why they're not ported.
static void nkit_circular_buffer_init ( nkit_circular_buffer_t *cb, u64 size, u32 capacity )
{
    memset(cb,0,sizeof(*cb));
    cb->buf = MALLOC(capacity);
    cb->capacity = capacity;
    cb->size = size;
    cb->seek_position = -1;
}

static void nkit_circular_buffer_reset_mem ( nkit_circular_buffer_t *cb )
{
    if (cb->buf) FREE(cb->buf);
    memset(cb,0,sizeof(*cb));
}

///////////////////////////////////////////////////////////////////////////////

// Write(byte[] buffer, int offset, int count), minus the Monitor.Wait
// blocking (see file-header note): copies as many of 'count' bytes as
// currently fit, handling the forward-seek discard exactly like the C#
// (bytes written while (_seekPosition != -1 && _wPosition < _seekPosition)
// are silently dropped/counted rather than buffered, until w_position
// catches up to seek_position, at which point both cursors are reset to
// that position and normal ring writes resume). Returns the number of
// bytes actually consumed from 'data' (may be less than 'size' if the
// ring is full -- caller must nkit_circular_buffer_read() to drain and
// call again with the remainder, same as the interleaving note above).
static u32 nkit_circular_buffer_write ( nkit_circular_buffer_t *cb, const u8 *data, u32 size )
{
    if ( cb->writing_complete || ( cb->size && cb->w_position >= cb->size ) )
	return 0; // matches C#'s early return once the reader is done

    u32 total = size;

    if ( cb->seek_position != -1 && cb->w_position < (u64)cb->seek_position )
    {
	u64 c64 = (u64)cb->seek_position - cb->w_position;
	u32 c = (u32)( c64 < size ? c64 : size );
	cb->w_position += c;
	data += c;
	size -= c;

	if ( cb->w_position == (u64)cb->seek_position )
	{
	    cb->r_position = cb->seek_position;
	    cb->w = cb->r = (u32)( cb->r_position % cb->capacity );
	    cb->seek_position = -1;
	}
	else
	    return total; // still seeking past the end of this chunk; "consumed" it all
    }

    if ( cb->seek_position == -1 && size )
    {
	// avail-to-write in the ring, same wrap arithmetic as C#'s 'l'
	s32 l = (s32)cb->r - (s32)cb->w;
	if ( l < 0 || ( l == 0 && cb->w_position == cb->r_position ) )
	    l = (s32)( cb->capacity - cb->w + cb->r ); // buffer empty -> full capacity available

	u32 n  = (u32)l < size ? (u32)l : size;
	u32 n1 = cb->capacity - cb->w < n ? cb->capacity - cb->w : n;

	memcpy(cb->buf+cb->w,data,n1);
	cb->w = cb->w+n1 == cb->capacity ? 0 : cb->w+n1;

	if ( n != n1 )
	{
	    memcpy(cb->buf+cb->w,data+n1,n-n1);
	    cb->w += n-n1;
	}
	cb->w_position += n;
	size -= n;
    }

    return total - size;
}

// Read(byte[] buffer, int offset, int count), minus the Monitor.Wait
// blocking: copies as many of 'count' bytes as currently available.
// Returns 0 once writing_complete and nothing left buffered, exactly
// where C#'s loop condition (!_writingComplete || _rPosition<_wPosition)
// would fall through without ever pausing.
static u32 nkit_circular_buffer_read ( nkit_circular_buffer_t *cb, u8 *data, u32 size )
{
    if ( cb->seek_position != -1 ) // mid-seek: nothing to hand out yet
	return 0;
    if ( !( !cb->writing_complete || cb->r_position < cb->w_position ) )
	return 0;

    s32 l = (s32)cb->w - (s32)cb->r;
    if ( l < 0 || ( l == 0 && cb->r_position < cb->w_position ) )
	l = (s32)( cb->capacity - cb->r + cb->w );

    u32 n  = (u32)l < size ? (u32)l : size;
    u32 n1 = cb->capacity - cb->r < n ? cb->capacity - cb->r : n;

    memcpy(data,cb->buf+cb->r,n1);
    cb->r = cb->r+n1 == cb->capacity ? 0 : cb->r+n1;

    if ( n != n1 )
    {
	memcpy(data+n1,cb->buf+cb->r,n-n1);
	cb->r += n-n1;
    }
    cb->r_position += n;

    return n;
}

// Seek(long offset, SeekOrigin.Begin only -- the only origin any call site
// uses). Forward-only, same as the C# (backward seek throws
// NotImplementedException there; this port reports it the wit way).
static enumError nkit_circular_buffer_seek ( nkit_circular_buffer_t *cb, u64 pos )
{
    if ( pos < cb->r_position )
	return ERROR0(ERR_INTERNAL,"NKit: circular buffer only supports forward seek\n");
    if ( pos == cb->r_position )
	return ERR_OK;

    if ( cb->w_position > pos ) // already buffered -- just move the read cursor
    {
	cb->r_position = pos;
	cb->r = (u32)( cb->r_position % cb->capacity );
    }
    else
	cb->seek_position = (s64)pos; // not there yet: writer-side must catch up and discard

    return ERR_OK;
}

// mirrors the writer Task's ContinueWith() flipping _writingComplete once
// the producer (stage 2b's synchronous equivalent of partitionStreamWrite)
// has no more bytes to offer.
static void nkit_circular_buffer_mark_write_done ( nkit_circular_buffer_t *cb )
{
    cb->writing_complete = true;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////                          END                    ///////////////
///////////////////////////////////////////////////////////////////////////////
