/*
 * Copyright (C) 2013 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

#include "rc2_crypter.h"

typedef struct private_rc2_crypter_t private_rc2_crypter_t;

#define RC2_BLOCK_SIZE 8

#define ROL16(x, k)	({ uint16_t _x = (x); (_x << (k)) | (_x >> (16 - (k))); })
#define ROR16(x, k)	({ uint16_t _x = (x); (_x >> (k)) | (_x << (16 - (k))); })

#define GET16(x)	({ u_char *_x = (x); (uint16_t)_x[0] | ((uint16_t)_x[1] << 8); })
#define PUT16(x, v)	({ u_char *_x = (x); uint16_t _v = (v); _x[0] = _v, _x[1] = _v >> 8; })

/**
 * Private data of rc2_crypter_t
 */
struct private_rc2_crypter_t {

	/**
	 * Public interface
	 */
	rc2_crypter_t public;

	/**
	* The expanded key in 16-bit words
	*/
	uint16_t  K[64];

	/**
	* Key size in bytes
	*/
	size_t T;

	/**
	* Effective key size in bits
	*/
	size_t T1;
};

/**
 * PITABLE
 */
static const u_char PITABLE[256] =
{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

/**
 * Encrypt a single block of data
 */
static void encrypt_block(private_rc2_crypter_t *this, u_char R[])
{
	register uint16_t R0, R1, R2, R3, *Kj;
	int rounds = 3, mix = 5;

	R0 = GET16(R);
	R1 = GET16(R + 2);
	R2 = GET16(R + 4);
	R3 = GET16(R + 6);
	Kj = &this->K[0];

	/* 5 mix, mash, 6 mix, mash, 5 mix */
	while (TRUE)
	{
		/* mix */
		R0 = ROL16(R0 + *(Kj++) + (R3 & R2) + (~R3 & R1), 1);
		R1 = ROL16(R1 + *(Kj++) + (R0 & R3) + (~R0 & R2), 2);
		R2 = ROL16(R2 + *(Kj++) + (R1 & R0) + (~R1 & R3), 3);
		R3 = ROL16(R3 + *(Kj++) + (R2 & R1) + (~R2 & R0), 5);

		if (--mix == 0)
		{
			if (--rounds == 0)
			{
				break;
			}
			mix = (rounds == 2) ? 6 : 5;
			/* mash */
			R0 += this->K[R3 & 63];
			R1 += this->K[R0 & 63];
			R2 += this->K[R1 & 63];
			R3 += this->K[R2 & 63];
		}
	}

	PUT16(R, R0);
	PUT16(R + 2, R1);
	PUT16(R + 4, R2);
	PUT16(R + 6, R3);
}

/**
 * Decrypt a single block of data.
 */
static void decrypt_block(private_rc2_crypter_t *this, u_char R[])
{
	register uint16_t R0, R1, R2, R3, *Kj;
	int rounds = 3, mix = 5;

	R0 = GET16(R);
	R1 = GET16(R + 2);
	R2 = GET16(R + 4);
	R3 = GET16(R + 6);
	Kj = &this->K[63];

	/* 5 r-mix, r-mash, 6 r-mix, r-mash, 5 r-mix */
	while (TRUE)
	{
		/* r-mix */
		R3 = ROR16(R3, 5);
		R3 = R3 - *(Kj--) - (R2 & R1) - (~R2 & R0);
		R2 = ROR16(R2, 3);
		R2 = R2 - *(Kj--) - (R1 & R0) - (~R1 & R3);
		R1 = ROR16(R1, 2);
		R1 = R1 - *(Kj--) - (R0 & R3) - (~R0 & R2);
		R0 = ROR16(R0, 1);
		R0 = R0 - *(Kj--) - (R3 & R2) - (~R3 & R1);

		if (--mix == 0)
		{
			if (--rounds == 0)
			{
				break;
			}
			mix = (rounds == 2) ? 6 : 5;
			/* r-mash */
			R3 -= this->K[R2 & 63];
			R2 -= this->K[R1 & 63];
			R1 -= this->K[R0 & 63];
			R0 -= this->K[R3 & 63];
		}
	}

	PUT16(R, R0);
	PUT16(R + 2, R1);
	PUT16(R + 4, R2);
	PUT16(R + 6, R3);
}

METHOD(crypter_t, decrypt, bool,
	private_rc2_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *decrypted)
{
	uint8_t *in, *out, *prev;

	if (data.len % RC2_BLOCK_SIZE || iv.len != RC2_BLOCK_SIZE)
	{
		return FALSE;
	}

	in = data.ptr + data.len - RC2_BLOCK_SIZE;
	out = data.ptr;
	if (decrypted)
	{
		*decrypted = chunk_alloc(data.len);
		out = decrypted->ptr;
	}
	out += data.len - RC2_BLOCK_SIZE;

	prev = in;
	for (; in >= data.ptr; in -= RC2_BLOCK_SIZE, out -= RC2_BLOCK_SIZE)
	{
		if (decrypted)
		{
			memcpy(out, in, RC2_BLOCK_SIZE);
		}
		decrypt_block(this, out);
		prev -= RC2_BLOCK_SIZE;
		if (prev < data.ptr)
		{
			prev = iv.ptr;
		}
		memxor(out, prev, RC2_BLOCK_SIZE);
	}
	return TRUE;
}

METHOD(crypter_t, encrypt, bool,
	private_rc2_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *encrypted)
{
	uint8_t *in, *out, *end, *prev;

	if (data.len % RC2_BLOCK_SIZE || iv.len != RC2_BLOCK_SIZE)
	{
		return FALSE;
	}

	in = data.ptr;
	end = data.ptr + data.len;
	out = data.ptr;
	if (encrypted)
	{
		*encrypted = chunk_alloc(data.len);
		out = encrypted->ptr;
	}

	prev = iv.ptr;
	for (; in < end; in += RC2_BLOCK_SIZE, out += RC2_BLOCK_SIZE)
	{
		if (encrypted)
		{
			memcpy(out, in, RC2_BLOCK_SIZE);
		}
		memxor(out, prev, RC2_BLOCK_SIZE);
		encrypt_block(this, out);
		prev = out;
	}
	return TRUE;
}

METHOD(crypter_t, get_block_size, size_t,
	private_rc2_crypter_t *this)
{
	return RC2_BLOCK_SIZE;
}

METHOD(crypter_t, get_iv_size, size_t,
	private_rc2_crypter_t *this)
{
	return RC2_BLOCK_SIZE;
}

METHOD(crypter_t, get_key_size, size_t,
	private_rc2_crypter_t *this)
{
	return this->T;
}

METHOD(crypter_t, set_key, bool,
	private_rc2_crypter_t *this, chunk_t key)
{
	uint8_t L[128], T8, TM, idx;
	int i;

	if (key.len != this->T)
	{
		return FALSE;
	}
	for (i = 0; i < key.len; i++)
	{
		L[i] = key.ptr[i];
	}
	for (; i < 128; i++)
	{
		idx = L[i-1] + L[i-key.len];
		L[i] = PITABLE[idx];
	}
	T8 = (this->T1 + 7) / 8;
	TM = ~(0xFF << (8 - (8*T8 - this->T1)));
	L[128-T8] = PITABLE[L[128-T8] & TM];
	for (i = 127-T8; i >= 0; i--)
	{
		idx = L[i+1] ^ L[i+T8];
		L[i] = PITABLE[idx];
	}
	for (i = 0; i < 64; i++)
	{
		this->K[i] = GET16(&L[i << 1]);
	}
	memwipe(L, sizeof(L));
	return TRUE;
}

METHOD(crypter_t, destroy, void,
	private_rc2_crypter_t *this)
{
	memwipe(this->K, sizeof(this->K));
	free(this);
}

/*
 * Described in header
 */
rc2_crypter_t *rc2_crypter_create(encryption_algorithm_t algo, size_t key_size)
{
	private_rc2_crypter_t *this;
	size_t effective;

	if (algo != ENCR_RC2_CBC)
	{
		return NULL;
	}
	key_size = max(1, key_size);
	effective = RC2_EFFECTIVE_KEY_LEN(key_size);
	key_size = min(128, RC2_KEY_LEN(key_size));
	effective = max(1, min(1024, effective ?: key_size * 8));

	INIT(this,
		.public = {
			.crypter = {
				.encrypt = _encrypt,
				.decrypt = _decrypt,
				.get_block_size = _get_block_size,
				.get_iv_size = _get_iv_size,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
		.T = key_size,
		.T1 = effective,
	);

	return &this->public;
}
