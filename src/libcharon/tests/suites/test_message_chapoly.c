/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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

#include "test_suite.h"

#include <encoding/message.h>

static aead_t *aead;

static iv_gen_t *ivgen;

METHOD(keymat_t, get_version, ike_version_t,
	keymat_t *this)
{
	return IKEV2;
}

METHOD(keymat_t, get_aead, aead_t*,
	keymat_t *this, bool in)
{
	return aead;
}

METHOD(aead_t, get_iv_gen, iv_gen_t*,
	aead_t *this)
{
	return ivgen;
}

METHOD(iv_gen_t, get_iv, bool,
	iv_gen_t *this, uint64_t seq, size_t size, uint8_t *buffer)
{
	if (size != 8)
	{
		return FALSE;
	}
	memcpy(buffer, "\x10\x11\x12\x13\x14\x15\x16\x17", 8);
	return TRUE;
}

METHOD(iv_gen_t, allocate_iv, bool,
	iv_gen_t *this, uint64_t seq, size_t size, chunk_t *chunk)
{
	if (size != 8)
	{
		return FALSE;
	}
	*chunk = chunk_alloc(size);
	return get_iv(this, seq, chunk->len, chunk->ptr);
}

/**
 * Appendix B draft-ietf-ipsecme-chacha20-poly1305-06
 */
START_TEST(test_chacha20poly1305)
{
	uint64_t spii, spir;
	ike_sa_id_t *id;
	message_t *m;
	uint32_t window = htonl(10);
	chunk_t chunk, exp;
	keymat_t keymat = {
		.get_version = _get_version,
		.create_dh = (void*)return_null,
		.create_nonce_gen = (void*)return_null,
		.get_aead = _get_aead,
	};

	m = message_create(IKEV2, 0);
	m->set_exchange_type(m, INFORMATIONAL);
	htoun64(&spii, 0xFF);
	htoun64(&spir, 0xFF);
	id = ike_sa_id_create(IKEV2, spii, spir, FALSE);
	m->set_ike_sa_id(m, id);
	id->destroy(id);
	m->set_source(m, host_create_from_string("1.2.3.4", 4500));
	m->set_destination(m, host_create_from_string("4.3.2.1", 4500));
	m->set_message_id(m, 9);
	m->add_notify(m, TRUE, SET_WINDOW_SIZE, chunk_from_thing(window));

	aead = lib->crypto->create_aead(lib->crypto, ENCR_CHACHA20_POLY1305, 32, 4);
	ck_assert(aead);
	ck_assert(aead->set_key(aead, chunk_from_chars(
									0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
									0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
									0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
									0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
									0xFF,0xFF,0xFF,0xFF)));
	INIT(ivgen,
		.get_iv = _get_iv,
		.allocate_iv = _allocate_iv,
		.destroy = (void*)free,
	);
	aead->get_iv_gen = _get_iv_gen,

	ck_assert(m->generate(m, &keymat, NULL) == SUCCESS);
	chunk = m->get_packet_data(m);
	exp = chunk_from_chars(0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
						   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
						   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
						   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
						   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
						   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
						   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
						   0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
						   0xFF,0xFF,0xFF,0xFF,0xFF);
	ck_assert_msg(chunk_equals(chunk, exp), "got %B\nexp %B", &chunk, &exp);
	ivgen->destroy(ivgen);
	aead->destroy(aead);
	m->destroy(m);
}
END_TEST

Suite *message_chapoly_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("chapoly");

	tc = tcase_create("ChaCha20Poly1305 IKEv2 encryption");
	tcase_add_test(tc, test_chacha20poly1305);
	suite_add_tcase(s, tc);

	return s;
}
