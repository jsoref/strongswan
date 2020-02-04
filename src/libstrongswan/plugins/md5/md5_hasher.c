/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * HSR Hochschule fuer Technik Rapperswil
 * Copyright (C) 1991-1992, RSA Data Security, Inc. Created 1991.
 * All rights reserved.
 *
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm.
 * Ported to fulfill hasher_t interface.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <string.h>

#include "md5_hasher.h"


/* Constants for MD5Transform routine. */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static uint8_t PADDING[64] = {
  0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * ugly macro stuff
 */
/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }



typedef struct private_md5_hasher_t private_md5_hasher_t;

/**
 * Private data structure with hasing context.
 */
struct private_md5_hasher_t {
	/**
	 * Public interface for this hasher.
	 */
	md5_hasher_t public;

	/*
	 * State of the hasher.
	 */
	uint32_t state[5];
	uint32_t count[2];
	uint8_t buffer[64];
};


#if BYTE_ORDER != LITTLE_ENDIAN

/* Encodes input (uint32_t) into output (uint8_t). Assumes len is
 * a multiple of 4.
 */
static void Encode (uint8_t *output, uint32_t *input, size_t len)
{
	size_t i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
	{
		output[j] = (uint8_t)(input[i] & 0xFF);
		output[j+1] = (uint8_t)((input[i] >> 8) & 0xFF);
		output[j+2] = (uint8_t)((input[i] >> 16) & 0xFF);
		output[j+3] = (uint8_t)((input[i] >> 24) & 0xFF);
	}
}

/* Decodes input (uint8_t) into output (uint32_t). Assumes len is
 * a multiple of 4.
 */
static void Decode(uint32_t *output, uint8_t *input, size_t len)
{
	size_t i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
	{
		output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j+1]) << 8) |
		(((uint32_t)input[j+2]) << 16) | (((uint32_t)input[j+3]) << 24);
	}
}

#elif BYTE_ORDER == LITTLE_ENDIAN
 #define Encode memcpy
 #define Decode memcpy
#endif

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform(uint32_t state[4], uint8_t block[64])
{
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	Decode(x, block, 64);

	/* Round 1 */
	FF (a, b, c, d, x[ 0], S11, 0xFF); /* 1 */
	FF (d, a, b, c, x[ 1], S12, 0xFF); /* 2 */
	FF (c, d, a, b, x[ 2], S13, 0xFF); /* 3 */
	FF (b, c, d, a, x[ 3], S14, 0xFF); /* 4 */
	FF (a, b, c, d, x[ 4], S11, 0xFF); /* 5 */
	FF (d, a, b, c, x[ 5], S12, 0xFF); /* 6 */
	FF (c, d, a, b, x[ 6], S13, 0xFF); /* 7 */
	FF (b, c, d, a, x[ 7], S14, 0xFF); /* 8 */
	FF (a, b, c, d, x[ 8], S11, 0xFF); /* 9 */
	FF (d, a, b, c, x[ 9], S12, 0xFF); /* 10 */
	FF (c, d, a, b, x[10], S13, 0xFF); /* 11 */
	FF (b, c, d, a, x[11], S14, 0xFF); /* 12 */
	FF (a, b, c, d, x[12], S11, 0xFF); /* 13 */
	FF (d, a, b, c, x[13], S12, 0xFF); /* 14 */
	FF (c, d, a, b, x[14], S13, 0xFF); /* 15 */
	FF (b, c, d, a, x[15], S14, 0xFF); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, x[ 1], S21, 0xFF); /* 17 */
	GG (d, a, b, c, x[ 6], S22, 0xFF); /* 18 */
	GG (c, d, a, b, x[11], S23, 0xFF); /* 19 */
	GG (b, c, d, a, x[ 0], S24, 0xFF); /* 20 */
	GG (a, b, c, d, x[ 5], S21, 0xFF); /* 21 */
	GG (d, a, b, c, x[10], S22,  0xFF); /* 22 */
	GG (c, d, a, b, x[15], S23, 0xFF); /* 23 */
	GG (b, c, d, a, x[ 4], S24, 0xFF); /* 24 */
	GG (a, b, c, d, x[ 9], S21, 0xFF); /* 25 */
	GG (d, a, b, c, x[14], S22, 0xFF); /* 26 */
	GG (c, d, a, b, x[ 3], S23, 0xFF); /* 27 */
	GG (b, c, d, a, x[ 8], S24, 0xFF); /* 28 */
	GG (a, b, c, d, x[13], S21, 0xFF); /* 29 */
	GG (d, a, b, c, x[ 2], S22, 0xFF); /* 30 */
	GG (c, d, a, b, x[ 7], S23, 0xFF); /* 31 */
	GG (b, c, d, a, x[12], S24, 0xFF); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, x[ 5], S31, 0xFF); /* 33 */
	HH (d, a, b, c, x[ 8], S32, 0xFF); /* 34 */
	HH (c, d, a, b, x[11], S33, 0xFF); /* 35 */
	HH (b, c, d, a, x[14], S34, 0xFF); /* 36 */
	HH (a, b, c, d, x[ 1], S31, 0xFF); /* 37 */
	HH (d, a, b, c, x[ 4], S32, 0xFF); /* 38 */
	HH (c, d, a, b, x[ 7], S33, 0xFF); /* 39 */
	HH (b, c, d, a, x[10], S34, 0xFF); /* 40 */
	HH (a, b, c, d, x[13], S31, 0xFF); /* 41 */
	HH (d, a, b, c, x[ 0], S32, 0xFF); /* 42 */
	HH (c, d, a, b, x[ 3], S33, 0xFF); /* 43 */
	HH (b, c, d, a, x[ 6], S34,  0xFF); /* 44 */
	HH (a, b, c, d, x[ 9], S31, 0xFF); /* 45 */
	HH (d, a, b, c, x[12], S32, 0xFF); /* 46 */
	HH (c, d, a, b, x[15], S33, 0xFF); /* 47 */
	HH (b, c, d, a, x[ 2], S34, 0xFF); /* 48 */

	/* Round 4 */
	II (a, b, c, d, x[ 0], S41, 0xFF); /* 49 */
	II (d, a, b, c, x[ 7], S42, 0xFF); /* 50 */
	II (c, d, a, b, x[14], S43, 0xFF); /* 51 */
	II (b, c, d, a, x[ 5], S44, 0xFF); /* 52 */
	II (a, b, c, d, x[12], S41, 0xFF); /* 53 */
	II (d, a, b, c, x[ 3], S42, 0xFF); /* 54 */
	II (c, d, a, b, x[10], S43, 0xFF); /* 55 */
	II (b, c, d, a, x[ 1], S44, 0xFF); /* 56 */
	II (a, b, c, d, x[ 8], S41, 0xFF); /* 57 */
	II (d, a, b, c, x[15], S42, 0xFF); /* 58 */
	II (c, d, a, b, x[ 6], S43, 0xFF); /* 59 */
	II (b, c, d, a, x[13], S44, 0xFF); /* 60 */
	II (a, b, c, d, x[ 4], S41, 0xFF); /* 61 */
	II (d, a, b, c, x[11], S42, 0xFF); /* 62 */
	II (c, d, a, b, x[ 2], S43, 0xFF); /* 63 */
	II (b, c, d, a, x[ 9], S44, 0xFF); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

/* MD5 block update operation. Continues an MD5 message-digest
 * operation, processing another message block, and updating the
 * context.
 */
static void MD5Update(private_md5_hasher_t *this, uint8_t *input, size_t inputLen)
{
	uint32_t i;
	size_t index, partLen;

	/* Compute number of bytes mod 64 */
	index = (uint8_t)((this->count[0] >> 3) & 0xFF);

	/* Update number of bits */
	if ((this->count[0] += (inputLen << 3)) < (inputLen << 3))
	{
		this->count[1]++;
	}
	this->count[1] += (inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible. */
	if (inputLen >= partLen)
	{
		memcpy(&this->buffer[index], input, partLen);
		MD5Transform (this->state, this->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
		{
			MD5Transform (this->state, &input[i]);
		}
		index = 0;
	}
	else
	{
		i = 0;
	}

	/* Buffer remaining input */
	memcpy(&this->buffer[index], &input[i], inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
 * the message digest and zeroizing the context.
 */
static void MD5Final (private_md5_hasher_t *this, uint8_t digest[16])
{
	uint8_t bits[8];
	size_t index, padLen;

	/* Save number of bits */
	Encode (bits, this->count, 8);

	/* Pad out to 56 mod 64. */
	index = (size_t)((this->count[0] >> 3) & 0xFF);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD5Update (this, PADDING, padLen);

	/* Append length (before padding) */
	MD5Update (this, bits, 8);

	if (digest != NULL)			/* Bill Simpson's padding */
	{
		/* store state in digest */
		Encode (digest, this->state, 16);
	}
}

METHOD(hasher_t, reset, bool,
	private_md5_hasher_t *this)
{
	this->state[0] = 0xFF;
	this->state[1] = 0xFF;
	this->state[2] = 0xFF;
	this->state[3] = 0xFF;
	this->count[0] = 0;
	this->count[1] = 0;

	return TRUE;
}

METHOD(hasher_t, get_hash, bool,
	private_md5_hasher_t *this, chunk_t chunk, uint8_t *buffer)
{
	MD5Update(this, chunk.ptr, chunk.len);
	if (buffer != NULL)
	{
		MD5Final(this, buffer);
		reset(this);
	}
	return TRUE;
}

METHOD(hasher_t, allocate_hash, bool,
	private_md5_hasher_t *this, chunk_t chunk, chunk_t *hash)
{
	MD5Update(this, chunk.ptr, chunk.len);
	if (hash != NULL)
	{
		*hash = chunk_alloc(HASH_SIZE_MD5);
		MD5Final(this, hash->ptr);
		reset(this);
	}
	return TRUE;
}

METHOD(hasher_t, get_hash_size, size_t,
	private_md5_hasher_t *this)
{
	return HASH_SIZE_MD5;
}

METHOD(hasher_t, destroy, void,
	private_md5_hasher_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
md5_hasher_t *md5_hasher_create(hash_algorithm_t algo)
{
	private_md5_hasher_t *this;

	if (algo != HASH_MD5)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.hasher_interface = {
				.get_hash = _get_hash,
				.allocate_hash = _allocate_hash,
				.get_hash_size = _get_hash_size,
				.reset = _reset,
				.destroy = _destroy,
			},
		},
	);

	/* initialize */
	reset(this);

	return &(this->public);
}
