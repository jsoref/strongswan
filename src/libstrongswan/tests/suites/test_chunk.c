/*
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

#include "test_suite.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <utils/chunk.h>
#include <threading/thread.h>

/*******************************************************************************
 * utilities
 */

static void assert_chunk_empty(chunk_t chunk)
{
	ck_assert(chunk.len == 0 && chunk.ptr == NULL);
}

/*******************************************************************************
 * equals
 */

START_TEST(test_chunk_equals)
{
	chunk_t chunk = chunk_from_str("chunk");
	chunk_t chunk_a, chunk_b;

	chunk_a = chunk_empty;
	chunk_b = chunk_empty;
	ck_assert(!chunk_equals(chunk_a, chunk_b));

	chunk_a = chunk;
	ck_assert(!chunk_equals(chunk_a, chunk_b));
	chunk_b = chunk;
	ck_assert(chunk_equals(chunk_a, chunk_b));

	chunk_b = chunk_from_str("asdf");
	ck_assert(!chunk_equals(chunk_a, chunk_b));

	chunk_b = chunk_from_str("chunk");
	ck_assert(chunk_equals(chunk_a, chunk_b));
}
END_TEST

/*******************************************************************************
 * equals_const
 */

START_TEST(test_chunk_equals_const)
{
	chunk_t chunk = chunk_from_str("chunk");
	chunk_t chunk_a, chunk_b;

	chunk_a = chunk_empty;
	chunk_b = chunk_empty;
	ck_assert(!chunk_equals_const(chunk_a, chunk_b));

	chunk_a = chunk;
	ck_assert(!chunk_equals_const(chunk_a, chunk_b));
	chunk_b = chunk;
	ck_assert(chunk_equals_const(chunk_a, chunk_b));

	chunk_b = chunk_from_str("asdf");
	ck_assert(!chunk_equals_const(chunk_a, chunk_b));

	chunk_b = chunk_from_str("chunk");
	ck_assert(chunk_equals_const(chunk_a, chunk_b));
}
END_TEST

/*******************************************************************************
 * chunk_compare test
 */

static struct {
	int result;
	chunk_t a;
	chunk_t b;
} compare_data[] = {
	{ 0, { NULL, 0 }, { NULL, 0 }},
	{ 0, chunk_from_chars(0xFF), chunk_from_chars(0xFF)},
	{-1, chunk_from_chars(0xFF), chunk_from_chars(0xFF)},
	{ 1, chunk_from_chars(0xFF), chunk_from_chars(0xFF)},
	{ 0, chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF, 0xFF)},
	{-1, chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF, 0xFF)},
	{ 1, chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF, 0xFF)},
	{-1, chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF, 0xFF)},
	{ 1, chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF, 0xFF)},
	{-1, chunk_from_chars(0xFF), chunk_from_chars(0xFF, 0xFF)},
	{ 1, chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF)},
};

START_TEST(test_compare)
{
	int result, expected;

	result = chunk_compare(compare_data[_i].a, compare_data[_i].b);
	expected = compare_data[_i].result;
	ck_assert((result == 0 && expected == 0) ||
			  (result < 0 && expected < 0) ||
			  (result > 0 && expected > 0));
}
END_TEST

/*******************************************************************************
 * clear
 */

START_TEST(test_chunk_clear)
{
	chunk_t chunk;
	u_char *ptr;
	int i;
	bool cleared = TRUE;

	chunk = chunk_empty;
	chunk_clear(&chunk);
	chunk_free(&chunk);

	chunk = chunk_alloc(64);
	ptr = chunk.ptr;
	for (i = 0; i < 64; i++)
	{
		chunk.ptr[i] = i;
	}
	chunk_clear(&chunk);
	/* check memory area of freed chunk. We can't use ck_assert() for this
	 * test directly, as it might allocate data at the freed area.  comparing
	 * two bytes at once reduces the chances of conflicts if memory got
	 * overwritten already */
	for (i = 0; i < 64; i += 2)
	{
		if (ptr[i] != 0 && ptr[i] == i &&
			ptr[i+1] != 0 && ptr[i+1] == i+1)
		{
			cleared = FALSE;
			break;
		}
	}
	assert_chunk_empty(chunk);
	ck_assert(cleared);
}
END_TEST

/*******************************************************************************
 * chunk_length
 */

START_TEST(test_chunk_length)
{
	chunk_t a, b, c;
	size_t len;

	a = chunk_empty;
	b = chunk_empty;
	c = chunk_empty;
	len = chunk_length("ccc", a, b, c);
	ck_assert_int_eq(len, 0);

	a = chunk_from_str("foo");
	b = chunk_from_str("bar");
	len = chunk_length("ccc", a, b, c);
	ck_assert_int_eq(len, 6);

	len = chunk_length("zcc", a, b, c);
	ck_assert_int_eq(len, 0);

	len = chunk_length("czc", a, b, c);
	ck_assert_int_eq(len, 3);

	a = chunk_from_str("foo");
	b = chunk_from_str("bar");
	c = chunk_from_str("baz");
	len = chunk_length("ccc", a, b, c);
	ck_assert_int_eq(len, 9);
}
END_TEST

/*******************************************************************************
 * chunk_create_cat
 */

START_TEST(test_chunk_create_cat)
{
	chunk_t foo, bar;
	chunk_t a, b, c;
	u_char *ptra, *ptrb;

	foo = chunk_from_str("foo");
	bar = chunk_from_str("bar");

	/* to simplify things we use the chunk_cata macro */

	a = chunk_empty;
	b = chunk_empty;
	c = chunk_cata("cc", a, b);
	ck_assert_int_eq(c.len, 0);
	ck_assert(c.ptr != NULL);

	a = foo;
	b = bar;
	c = chunk_cata("cc", a, b);
	ck_assert_int_eq(c.len, 6);
	ck_assert(chunk_equals(c, chunk_from_str("foobar")));

	a = chunk_clone(foo);
	b = chunk_clone(bar);
	c = chunk_cata("mm", a, b);
	ck_assert_int_eq(c.len, 6);
	ck_assert(chunk_equals(c, chunk_from_str("foobar")));

	a = chunk_clone(foo);
	b = chunk_clone(bar);
	ptra = a.ptr;
	ptrb = b.ptr;
	c = chunk_cata("ss", a, b);
	ck_assert_int_eq(c.len, 6);
	ck_assert(chunk_equals(c, chunk_from_str("foobar")));
	/* check memory area of cleared chunk */
	ck_assert(!chunk_equals(foo, chunk_create(ptra, 3)));
	ck_assert(!chunk_equals(bar, chunk_create(ptrb, 3)));
}
END_TEST

/*******************************************************************************
 * chunk_split
 */

static bool mem_in_chunk(u_char *ptr, chunk_t chunk)
{
	return ptr >= chunk.ptr && ptr < (chunk.ptr + chunk.len);
}

START_TEST(test_chunk_split)
{
	chunk_t foo, bar, foobar;
	chunk_t a, b, c;
	u_char *ptra, *ptrb;

	foo = chunk_from_str("foo");
	bar = chunk_from_str("bar");
	foobar = chunk_from_str("foobar");

	chunk_split(foobar, "aa", 3, &a, 3, &b);
	ck_assert(chunk_equals(a, foo));
	ck_assert(chunk_equals(b, bar));
	ck_assert(!mem_in_chunk(a.ptr, foobar));
	ck_assert(!mem_in_chunk(b.ptr, foobar));
	chunk_free(&a);
	chunk_free(&b);

	chunk_split(foobar, "mm", 3, &a, 3, &b);
	ck_assert(chunk_equals(a, foo));
	ck_assert(chunk_equals(b, bar));
	ck_assert(mem_in_chunk(a.ptr, foobar));
	ck_assert(mem_in_chunk(b.ptr, foobar));

	chunk_split(foobar, "am", 3, &a, 3, &b);
	ck_assert(chunk_equals(a, foo));
	ck_assert(chunk_equals(b, bar));
	ck_assert(!mem_in_chunk(a.ptr, foobar));
	ck_assert(mem_in_chunk(b.ptr, foobar));
	chunk_free(&a);

	a = chunk_alloca(3);
	ptra = a.ptr;
	b = chunk_alloca(3);
	ptrb = b.ptr;
	chunk_split(foobar, "cc", 3, &a, 3, &b);
	ck_assert(chunk_equals(a, foo));
	ck_assert(chunk_equals(b, bar));
	ck_assert(a.ptr == ptra);
	ck_assert(b.ptr == ptrb);

	chunk_split(foobar, "mm", 1, NULL, 2, &a, 2, NULL, 1, &b);
	ck_assert(chunk_equals(a, chunk_from_str("oo")));
	ck_assert(chunk_equals(b, chunk_from_str("r")));

	chunk_split(foobar, "mm", 6, &a, 6, &b);
	ck_assert(chunk_equals(a, foobar));
	assert_chunk_empty(b);

	chunk_split(foobar, "mac", 12, &a, 12, &b, 12, &c);
	ck_assert(chunk_equals(a, foobar));
	assert_chunk_empty(b);
	assert_chunk_empty(c);
}
END_TEST

/*******************************************************************************
 * chunk_skip[_zero]
 */

START_TEST(test_chunk_skip)
{
	chunk_t foobar, a;

	foobar = chunk_from_str("foobar");
	a = foobar;
	a = chunk_skip(a, 0);
	ck_assert_chunk_eq(a, foobar);
	a = chunk_skip(a, 1);
	ck_assert_chunk_eq(a, chunk_from_str("oobar"));
	a = chunk_skip(a, 2);
	ck_assert_chunk_eq(a, chunk_from_str("bar"));
	a = chunk_skip(a, 3);
	assert_chunk_empty(a);

	a = foobar;
	a = chunk_skip(a, 6);
	assert_chunk_empty(a);

	a = foobar;
	a = chunk_skip(a, 10);
	assert_chunk_empty(a);
}
END_TEST

START_TEST(test_chunk_skip_zero)
{
	chunk_t foobar, a;

	a = chunk_skip_zero(chunk_empty);
	assert_chunk_empty(a);

	foobar = chunk_from_str("foobar");
	a = chunk_skip_zero(foobar);
	ck_assert_chunk_eq(a, foobar);

	foobar = chunk_from_chars(0xFF);
	a = chunk_skip_zero(foobar);
	ck_assert_chunk_eq(a, foobar);

	a = chunk_skip_zero(chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF));
	ck_assert_chunk_eq(a, chunk_from_chars(0xFF, 0xFF, 0xFF));
	a = chunk_skip_zero(a);
	ck_assert_chunk_eq(a, chunk_from_chars(0xFF, 0xFF, 0xFF));

	a = chunk_skip_zero(chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF));
	ck_assert_chunk_eq(a, chunk_from_chars(0xFF, 0xFF, 0xFF));
}
END_TEST

/*******************************************************************************
 * BASE16 encoding test
 */

START_TEST(test_base16)
{
	/* test vectors from RFC 4648:
	 *
	 * BASE16("") = ""
	 * BASE16("f") = "66"
	 * BASE16("fo") = "666F"
	 * BASE16("foo") = "666F6F"
	 * BASE16("foob") = "666F6F62"
	 * BASE16("fooba") = "666F6F6261"
	 * BASE16("foobar") = "666F6F626172"
	 */
	typedef struct {
		bool upper;
		char *in;
		char *out;
	} testdata_t;

	testdata_t test[] = {
		{TRUE,  "", ""},
		{TRUE,  "f", "66"},
		{TRUE,  "fo", "666F"},
		{TRUE,  "foo", "666F6F"},
		{TRUE,  "foob", "666F6F62"},
		{TRUE,  "fooba", "666F6F6261"},
		{TRUE,  "foobar", "666F6F626172"},
		{FALSE, "", ""},
		{FALSE, "f", "66"},
		{FALSE, "fo", "666f"},
		{FALSE, "foo", "666f6f"},
		{FALSE, "foob", "666f6f62"},
		{FALSE, "fooba", "666f6f6261"},
		{FALSE, "foobar", "666f6f626172"},
	};
	testdata_t test_prefix_colon[] = {
		{TRUE,  "", "0x"},
		{TRUE,  "f", "0xFF"},
		{TRUE,  "fo", "66:6F"},
		{TRUE,  "foo", "0xFF:6F:6F"},
		{FALSE, "foob", "66:6f:6f:62"},
		{FALSE, "fooba", "0xFF:6f:6f:62:61"},
		{FALSE, "foobar", "66:6f:6f:62:61:72"},
		{FALSE, "foobar", "0xFF:6f6f:6261:72"},
	};
	int i;

	for (i = 0; i < countof(test); i++)
	{
		chunk_t out;

		out = chunk_to_hex(chunk_create(test[i].in, strlen(test[i].in)), NULL,
						   test[i].upper);
		ck_assert_str_eq(out.ptr, test[i].out);
		free(out.ptr);
	}

	for (i = 0; i < countof(test); i++)
	{
		chunk_t out;

		out = chunk_from_hex(chunk_create(test[i].out, strlen(test[i].out)), NULL);
		fail_unless(strneq(out.ptr, test[i].in, out.len),
					"base16 conversion error - should '%s', is %#B",
					test[i].in, &out);
		free(out.ptr);
	}

	for (i = 0; i < countof(test_prefix_colon); i++)
	{
		chunk_t out;

		out = chunk_from_hex(chunk_create(test_prefix_colon[i].out,
							 strlen(test_prefix_colon[i].out)), NULL);
		fail_unless(strneq(out.ptr, test_prefix_colon[i].in, out.len),
					"base16 conversion error - should '%s', is %#B",
					test_prefix_colon[i].in, &out);
		free(out.ptr);
	}
}
END_TEST

/*******************************************************************************
 * BASE64 encoding test
 */

START_TEST(test_base64)
{
	/* test vectors from RFC 4648:
	 *
	 * BASE64("") = ""
	 * BASE64("f") = "Zg=="
	 * BASE64("fo") = "Zm8="
	 * BASE64("foo") = "Zm9v"
	 * BASE64("foob") = "Zm9vYg=="
	 * BASE64("fooba") = "Zm9vYmE="
	 * BASE64("foobar") = "Zm9vYmFy"
	 */
	typedef struct {
		char *in;
		char *out;
	} testdata_t;

	testdata_t test[] = {
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foob", "Zm9vYg=="},
		{"fooba", "Zm9vYmE="},
		{"foobar", "Zm9vYmFy"},
	};
	int i;

	for (i = 0; i < countof(test); i++)
	{
		chunk_t out;

		out = chunk_to_base64(chunk_create(test[i].in, strlen(test[i].in)), NULL);
		ck_assert_str_eq(out.ptr, test[i].out);
		free(out.ptr);
	}

	for (i = 0; i < countof(test); i++)
	{
		chunk_t out;

		out = chunk_from_base64(chunk_create(test[i].out, strlen(test[i].out)), NULL);
		fail_unless(strneq(out.ptr, test[i].in, out.len),
					"base64 conversion error - should '%s', is %#B",
					test[i].in, &out);
		free(out.ptr);
	}
}
END_TEST

/*******************************************************************************
 * BASE32 encoding test
 */

START_TEST(test_base32)
{
	/* test vectors from RFC 4648:
	 *
	 * BASE32("") = ""
	 * BASE32("f") = "MY======"
	 * BASE32("fo") = "MZXQ===="
	 * BASE32("foo") = "MZXW6==="
	 * BASE32("foob") = "MZXW6YQ="
	 * BASE32("fooba") = "MZXW6YTB"
	 * BASE32("foobar") = "MZXW6YTBOI======"
	 */
	typedef struct {
		char *in;
		char *out;
	} testdata_t;

	testdata_t test[] = {
		{"", ""},
		{"f", "MY======"},
		{"fo", "MZXQ===="},
		{"foo", "MZXW6==="},
		{"foob", "MZXW6YQ="},
		{"fooba", "MZXW6YTB"},
		{"foobar", "MZXW6YTBOI======"},
	};
	int i;

	for (i = 0; i < countof(test); i++)
	{
		chunk_t out;

		out = chunk_to_base32(chunk_create(test[i].in, strlen(test[i].in)), NULL);
		ck_assert_str_eq(out.ptr, test[i].out);
		free(out.ptr);
	}
}
END_TEST

/*******************************************************************************
 * chunk_increment test
 */

static struct {
	bool overflow;
	chunk_t in;
	chunk_t out;
} increment_data[] = {
	{TRUE,  { NULL, 0 }, { NULL, 0 }},
	{FALSE, chunk_from_chars(0xFF), chunk_from_chars(0xFF)},
	{FALSE, chunk_from_chars(0xFF), chunk_from_chars(0xFF)},
	{TRUE,  chunk_from_chars(0xFF), chunk_from_chars(0xFF)},
	{FALSE, chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF, 0xFF)},
	{FALSE, chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF, 0xFF)},
	{FALSE, chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF, 0xFF)},
	{TRUE,  chunk_from_chars(0xFF, 0xFF), chunk_from_chars(0xFF, 0xFF)},
};

START_TEST(test_increment)
{
	chunk_t chunk;
	bool overflow;

	chunk = chunk_clonea(increment_data[_i].in);
	overflow = chunk_increment(chunk);
	ck_assert(overflow == increment_data[_i].overflow);
	ck_assert(!increment_data[_i].out.ptr ||
			  chunk_equals(chunk, increment_data[_i].out));
}
END_TEST

/*******************************************************************************
 * chunk_copy_pad tests
 */

static struct {
	size_t len;
	u_char chr;
	chunk_t src;
	chunk_t exp;
} copy_pad_data[] = {
	{0, 0xFF, { NULL, 0 }, { NULL, 0 }},
	{4, 0xFF, { NULL, 0 }, chunk_from_chars(0xFF,0xFF,0xFF,0xFF)},
	{0, 0xFF, chunk_from_chars(0xFF), { NULL, 0 }},
	{1, 0xFF, chunk_from_chars(0xFF), chunk_from_chars(0xFF)},
	{2, 0xFF, chunk_from_chars(0xFF), chunk_from_chars(0xFF,0xFF)},
	{3, 0xFF, chunk_from_chars(0xFF), chunk_from_chars(0xFF,0xFF,0xFF)},
	{4, 0xFF, chunk_from_chars(0xFF), chunk_from_chars(0xFF,0xFF,0xFF,0xFF)},
	{4, 0xFF, chunk_from_chars(0xFF), chunk_from_chars(0xFF,0xFF,0xFF,0xFF)},
	{1, 0xFF, chunk_from_chars(0xFF,0xFF,0xFF,0xFF), chunk_from_chars(0xFF)},
	{2, 0xFF, chunk_from_chars(0xFF,0xFF,0xFF,0xFF), chunk_from_chars(0xFF,0xFF)},
	{3, 0xFF, chunk_from_chars(0xFF,0xFF,0xFF,0xFF), chunk_from_chars(0xFF,0xFF,0xFF)},
	{4, 0xFF, chunk_from_chars(0xFF,0xFF,0xFF,0xFF), chunk_from_chars(0xFF,0xFF,0xFF,0xFF)},
};

START_TEST(test_copy_pad)
{
	chunk_t chunk;

	chunk = chunk_copy_pad(chunk_alloca(copy_pad_data[_i].len),
						   copy_pad_data[_i].src, copy_pad_data[_i].chr);
	ck_assert_chunk_eq(chunk, copy_pad_data[_i].exp);
}
END_TEST

/*******************************************************************************
 * chunk_printable tests
 */

static struct {
	bool printable;
	chunk_t in;
	char *out;
} printable_data[] = {
	{TRUE,  chunk_from_chars(0xFF), "1"},
	{FALSE, chunk_from_chars(0xFF), "?"},
	{FALSE, chunk_from_chars(0xFF, 0xFF), "1?"},
	{FALSE, chunk_from_chars(0xFF, 0xFF), "?1"},
	{TRUE,  chunk_from_chars(0xFF, 0xFF), "?1"},
	{FALSE, chunk_from_chars(0xFF, 0xFF, 0xFF), "?1?"},
	{FALSE, chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF), "?1?2"},
};

START_TEST(test_printable)
{
	bool printable;

	printable = chunk_printable(printable_data[_i].in, NULL, ' ');
	ck_assert(printable == printable_data[_i].printable);
}
END_TEST

START_TEST(test_printable_sanitize)
{
	chunk_t sane, expected;
	bool printable;

	printable = chunk_printable(printable_data[_i].in, &sane, '?');
	ck_assert(printable == printable_data[_i].printable);
	expected = chunk_from_str(printable_data[_i].out);
	ck_assert(chunk_equals(sane, expected));
	chunk_free(&sane);
}
END_TEST

START_TEST(test_printable_empty)
{
	chunk_t sane;
	bool printable;

	printable = chunk_printable(chunk_empty, NULL, ' ');
	ck_assert(printable);

	sane.ptr = (void*)1;
	sane.len = 1;
	printable = chunk_printable(chunk_empty, &sane, ' ');
	ck_assert(printable);
	assert_chunk_empty(sane);
}
END_TEST

/*******************************************************************************
 * test for chunk_mac(), i.e. SipHash-2-4
 */

/**
 * SipHash-2-4 output with
 * k = 00 01 02 ...
 * and
 * in = (empty string)
 * in = 00 (1 byte)
 * in = 00 01 (2 bytes)
 * in = 00 01 02 (3 bytes)
 * ...
 * in = 00 01 02 ... 3e (63 bytes)
 */
static const u_char sip_vectors[64][8] =
{
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }
};

/**
 * Our SipHash-2-4 implementation returns the result in host order, which
 * doesn't matter for practical purposes and even avoids a byte swap.  But
 * because the test vectors are in little-endian we have to account for this
 * with this custom comparison function.
 */
static inline bool sipeq(const void *a, const void *b, size_t n)
{
	u_char *ap = (u_char*)a, *bp = (u_char*)b;
	int i;

	for (i = 0; i < n; i++)
	{
#ifdef WORDS_BIGENDIAN
		if (ap[i] != bp[n - i - 1])
#else
		if (ap[i] != bp[i])
#endif
		{
			return FALSE;
		}
	}
	return TRUE;
}

START_TEST(test_chunk_mac)
{
	chunk_t in;
	u_char key[16];
	uint64_t out;
	int i, count;

	count = countof(sip_vectors);
	in = chunk_alloca(count);

	for (i = 0; i < 16; ++i)
	{
		key[i] = i;
	}

	for (i = 0; i < count; ++i)
	{
		in.ptr[i] = i;
		in.len = i;
		out = chunk_mac(in, key);
		fail_unless(sipeq(&out, sip_vectors[i], 8),
					"test vector failed for %d bytes", i);
	}
}
END_TEST

/*******************************************************************************
 * test for chunk_hash[_inc]()
 */

START_TEST(test_chunk_hash)
{
	chunk_t chunk;
	uint32_t hash_a, hash_b, hash_c;

	chunk = chunk_from_str("asdf");

	/* output is randomized, so there are no test-vectors we could use */
	hash_a = chunk_hash(chunk);
	hash_b = chunk_hash(chunk);
	ck_assert(hash_a == hash_b);
	hash_b = chunk_hash_inc(chunk, hash_a);
	ck_assert(hash_a != hash_b);
	hash_c = chunk_hash_inc(chunk, hash_a);
	ck_assert(hash_b == hash_c);
}
END_TEST

/*******************************************************************************
 * test for chunk_hash_static[_inc]()
 */

START_TEST(test_chunk_hash_static)
{
	chunk_t in;
	uint32_t out, hash_a, hash_b, hash_inc = 0xFF;
	int i, count;

	count = countof(sip_vectors);
	in = chunk_alloca(count);

	for (i = 0; i < count; ++i)
	{
		in.ptr[i] = i;
		in.len = i;
		/* compared to chunk_mac() we only get half the value back */
		out = chunk_hash_static(in);
		fail_unless(sipeq(&out, sip_vectors[i], 4),
					"test vector failed for %d bytes", i);
	}
	hash_a = chunk_hash_static_inc(in, out);
	ck_assert_int_eq(hash_a, hash_inc);
	hash_b = chunk_hash_static_inc(in, out);
	ck_assert_int_eq(hash_a, hash_b);
}
END_TEST

/*******************************************************************************
 * test for chunk_internet_checksum[_inc]()
 */

static inline uint16_t compensate_alignment(uint16_t val)
{
	return ((val & 0xFF) << 8) | (val >> 8);
}

START_TEST(test_chunk_internet_checksum)
{
	chunk_t chunk;
	uint16_t sum;

	chunk = chunk_from_chars(0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
							 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF);

	sum = chunk_internet_checksum(chunk);
	ck_assert_int_eq(0xFF, ntohs(sum));

	sum = chunk_internet_checksum(chunk_create(chunk.ptr, 10));
	sum = chunk_internet_checksum_inc(chunk_create(chunk.ptr+10, 10), sum);
	ck_assert_int_eq(0xFF, ntohs(sum));

	/* need to compensate for even/odd alignment */
	sum = chunk_internet_checksum(chunk_create(chunk.ptr, 9));
	sum = compensate_alignment(sum);
	sum = chunk_internet_checksum_inc(chunk_create(chunk.ptr+9, 11), sum);
	sum = compensate_alignment(sum);
	ck_assert_int_eq(0xFF, ntohs(sum));

	chunk = chunk_from_chars(0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
							 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF);

	sum = chunk_internet_checksum(chunk);
	ck_assert_int_eq(0xFF, ntohs(sum));

	sum = chunk_internet_checksum(chunk_create(chunk.ptr, 10));
	sum = chunk_internet_checksum_inc(chunk_create(chunk.ptr+10, 9), sum);
	ck_assert_int_eq(0xFF, ntohs(sum));

	/* need to compensate for even/odd alignment */
	sum = chunk_internet_checksum(chunk_create(chunk.ptr, 9));
	sum = compensate_alignment(sum);
	sum = chunk_internet_checksum_inc(chunk_create(chunk.ptr+9, 10), sum);
	sum = compensate_alignment(sum);
	ck_assert_int_eq(0xFF, ntohs(sum));
}
END_TEST

/*******************************************************************************
 * test for chunk_map and friends
 */

START_TEST(test_chunk_map)
{
	chunk_t *map, contents = chunk_from_chars(0xFF,0xFF,0xFF,0xFF,0xFF);
#ifdef WIN32
	char *path = "C:\\Windows\\Temp\\strongswan-chunk-map-test";
#else
	char *path = "/tmp/strongswan-chunk-map-test";
#endif

	ck_assert(chunk_write(contents, path, 022, TRUE));

	/* read */
	map = chunk_map(path, FALSE);
	ck_assert(map != NULL);
	ck_assert_msg(chunk_equals(*map, contents), "%B", map);
	/* altering mapped chunk should not hurt */
	*map = chunk_empty;
	ck_assert(chunk_unmap(map));

	/* write */
	map = chunk_map(path, TRUE);
	ck_assert(map != NULL);
	ck_assert_msg(chunk_equals(*map, contents), "%B", map);
	map->ptr[0] = 0xFF;
	ck_assert(chunk_unmap(map));

	/* verify write */
	contents.ptr[0] = 0xFF;
	map = chunk_map(path, FALSE);
	ck_assert(map != NULL);
	ck_assert_msg(chunk_equals(*map, contents), "%B", map);
	ck_assert(chunk_unmap(map));

	unlink(path);
}
END_TEST

/*******************************************************************************
 * test for chunk_from_fd
 */

START_TEST(test_chunk_from_fd_file)
{
	chunk_t in, contents = chunk_from_chars(0xFF,0xFF,0xFF,0xFF,0xFF);
#ifdef WIN32
	char *path = "C:\\Windows\\Temp\\strongswan-chunk-fd-test";
#else
	char *path = "/tmp/strongswan-chunk-fd-test";
#endif
	int fd;

	ck_assert(chunk_write(contents, path, 022, TRUE));

	fd = open(path, O_RDONLY);
	ck_assert(fd != -1);

	ck_assert(chunk_from_fd(fd, &in));
	close(fd);
	ck_assert_msg(chunk_equals(in, contents), "%B", &in);
	unlink(path);
	free(in.ptr);
}
END_TEST

START_TEST(test_chunk_from_fd_skt)
{
	chunk_t in, contents = chunk_from_chars(0xFF,0xFF,0xFF,0xFF,0xFF);
	int s[2];

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0);
	ck_assert_int_eq(send(s[1], contents.ptr, contents.len, 0), contents.len);
	close(s[1]);
	ck_assert_msg(chunk_from_fd(s[0], &in), "%s", strerror(errno));
	close(s[0]);
	ck_assert_msg(chunk_equals(in, contents), "%B", &in);
	free(in.ptr);
}
END_TEST

#define FROM_FD_COUNT 8192

void *chunk_from_fd_run(void *data)
{
	int i, fd = (uintptr_t)data;

	for (i = 0; i < FROM_FD_COUNT; i++)
	{
		ck_assert(send(fd, &i, sizeof(i), 0) == sizeof(i));
	}
	close(fd);
	return NULL;
}

START_TEST(test_chunk_from_fd_huge)
{
	thread_t *thread;
	chunk_t in;
	int s[2], i;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0);

	thread = thread_create(chunk_from_fd_run, (void*)(uintptr_t)s[1]);
	ck_assert_msg(chunk_from_fd(s[0], &in), "%s", strerror(errno));
	ck_assert_int_eq(in.len, FROM_FD_COUNT * sizeof(i));
	for (i = 0; i < FROM_FD_COUNT; i++)
	{
		ck_assert_int_eq(((int*)in.ptr)[i], i);
	}
	thread->join(thread);
	close(s[0]);
	free(in.ptr);
}
END_TEST

/*******************************************************************************
 * printf_hook tests
 */

static struct {
	chunk_t in;
	char *out;
	char *out_plus;
} printf_hook_data[] = {
	{chunk_from_chars(), "", ""},
	{chunk_from_chars(0xFF), "00", "00"},
	{chunk_from_chars(0xFF, 0xFF), "00:01", "0001"},
	{chunk_from_chars(0xFF, 0xFF, 0xFF), "00:01:02", "000102"},
};

START_TEST(test_printf_hook_hash)
{
	char buf[16];
	int len;

	len = snprintf(buf, sizeof(buf), "%#B", &printf_hook_data[_i].in);
	ck_assert(len >= 0 && len < sizeof(buf));
	ck_assert_str_eq(buf, printf_hook_data[_i].out);
}
END_TEST

START_TEST(test_printf_hook_plus)
{
	char buf[16];
	int len;

	len = snprintf(buf, sizeof(buf), "%+B", &printf_hook_data[_i].in);
	ck_assert(len >= 0 && len < sizeof(buf));
	ck_assert_str_eq(buf, printf_hook_data[_i].out_plus);
}
END_TEST

START_TEST(test_printf_hook)
{
	char buf[128], mem[128];
	int len;

	/* %B should be the same as %b, which is what we check, comparing the
	 * actual result could be tricky as %b prints the chunk's memory address */
	len = snprintf(buf, sizeof(buf), "%B", &printf_hook_data[_i].in);
	ck_assert(len >= 0 && len < sizeof(buf));
	len = snprintf(mem, sizeof(mem), "%b", printf_hook_data[_i].in.ptr,
				  (u_int)printf_hook_data[_i].in.len);
	ck_assert(len >= 0 && len < sizeof(mem));
	ck_assert_str_eq(buf, mem);
}
END_TEST

Suite *chunk_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("chunk");

	tc = tcase_create("equals");
	tcase_add_test(tc, test_chunk_equals);
	tcase_add_test(tc, test_chunk_equals_const);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_compare");
	tcase_add_loop_test(tc, test_compare, 0, countof(compare_data));
	suite_add_tcase(s, tc);

	tc = tcase_create("clear");
	tcase_add_test(tc, test_chunk_clear);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_length");
	tcase_add_test(tc, test_chunk_length);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_create_cat");
	tcase_add_test(tc, test_chunk_create_cat);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_split");
	tcase_add_test(tc, test_chunk_split);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_skip");
	tcase_add_test(tc, test_chunk_skip);
	tcase_add_test(tc, test_chunk_skip_zero);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_increment");
	tcase_add_loop_test(tc, test_increment, 0, countof(increment_data));
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_copy_pad");
	tcase_add_loop_test(tc, test_copy_pad, 0, countof(copy_pad_data));
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_printable");
	tcase_add_loop_test(tc, test_printable, 0, countof(printable_data));
	tcase_add_loop_test(tc, test_printable_sanitize, 0, countof(printable_data));
	tcase_add_test(tc, test_printable_empty);
	suite_add_tcase(s, tc);

	tc = tcase_create("baseXX");
	tcase_add_test(tc, test_base64);
	tcase_add_test(tc, test_base32);
	tcase_add_test(tc, test_base16);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_mac");
	tcase_add_test(tc, test_chunk_mac);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_hash");
	tcase_add_test(tc, test_chunk_hash);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_hash_static");
	tcase_add_test(tc, test_chunk_hash_static);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_internet_checksum");
	tcase_add_test(tc, test_chunk_internet_checksum);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_map");
	tcase_add_test(tc, test_chunk_map);
	suite_add_tcase(s, tc);

	tc = tcase_create("chunk_from_fd");
	tcase_add_test(tc, test_chunk_from_fd_file);
	tcase_add_test(tc, test_chunk_from_fd_skt);
	tcase_add_test(tc, test_chunk_from_fd_huge);
	suite_add_tcase(s, tc);

	tc = tcase_create("printf_hook");
	tcase_add_loop_test(tc, test_printf_hook_hash, 0, countof(printf_hook_data));
	tcase_add_loop_test(tc, test_printf_hook_plus, 0, countof(printf_hook_data));
	tcase_add_loop_test(tc, test_printf_hook, 0, countof(printf_hook_data));
	suite_add_tcase(s, tc);

	return s;
}
