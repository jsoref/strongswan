/*
 * Copyright (C) 2013 Andreas Steffen
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

#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <utils/chunk.h>

/*******************************************************************************
 * algorithm_identifier
 */

START_TEST(test_asn1_algorithmIdentifier)
{
	typedef struct {
		int n;
		chunk_t algid;
	} testdata_t;

	testdata_t test[] = {
		{ OID_ECDSA_WITH_SHA1, chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ OID_SHA1_WITH_RSA,   chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
	};

	chunk_t algid;
	int i;

	for (i = 0; i < countof(test); i++)
	{
		algid = asn1_algorithmIdentifier(test[i].n);
		ck_assert(chunk_equals(algid, test[i].algid));
		free(algid.ptr);
	}
}
END_TEST

/*******************************************************************************
 * parse_algorithm_identifier
 */

START_TEST(test_asn1_parse_algorithmIdentifier)
{
	typedef struct {
		int alg;
		bool empty;
		chunk_t parameters;
	} testdata_t;

	testdata_t test[] = {
		{ OID_ECDSA_WITH_SHA1, TRUE,  chunk_empty },
		{ OID_SHA1_WITH_RSA,   TRUE,  chunk_from_chars(0xFF, 0xFF) },
		{ OID_3DES_EDE_CBC,    FALSE, chunk_from_chars(0xFF, 0xFF, 0xFF) },
		{ OID_PBKDF2,          FALSE, chunk_from_chars(0xFF, 0xFF, 0xFF) }
	};

	chunk_t algid, parameters;
	int i, alg;

	for (i = 0; i < countof(test); i++)
	{
		algid = asn1_wrap(ASN1_SEQUENCE, "mc",
					 asn1_build_known_oid(test[i].alg), test[i].parameters);
		parameters = chunk_empty;
		if (i == 2)
		{
			alg = asn1_parse_algorithmIdentifier(algid, 0, NULL);
		}
		else
		{
			alg = asn1_parse_algorithmIdentifier(algid, 0, &parameters);
			if (test[i].empty)
			{
				ck_assert(parameters.len == 0 && parameters.ptr == NULL);
			}
				else
			{
				ck_assert(chunk_equals(parameters, test[i].parameters));
			}
		}
		ck_assert(alg == test[i].alg);
		chunk_free(&algid);
	}
}
END_TEST

/*******************************************************************************
 * known_oid
 */

START_TEST(test_asn1_known_oid)
{
	typedef struct {
		int n;
		chunk_t oid;
	} testdata_t;

	testdata_t test[] = {
		{ OID_UNKNOWN,    chunk_empty },
		{ OID_UNKNOWN,    chunk_from_chars(0xFF, 0xFF, 0xFF) },
		{ OID_COUNTRY,    chunk_from_chars(0xFF, 0xFF, 0xFF) },
		{ OID_STRONGSWAN, chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										   0xFF, 0xFF, 0xFF, 0xFF) }
	};

	int i;

	for (i = 0; i < countof(test); i++)
	{
		ck_assert(asn1_known_oid(test[i].oid) == test[i].n);
	}
}
END_TEST

/*******************************************************************************
 * build_known_oid
 */

START_TEST(test_asn1_build_known_oid)
{
	typedef struct {
		int n;
		chunk_t oid;
	} testdata_t;

	testdata_t test[] = {
		{ OID_UNKNOWN,    chunk_empty },
		{ OID_MAX,        chunk_empty },
		{ OID_COUNTRY,    chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ OID_STRONGSWAN, chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
										   0xFF, 0xFF, 0xFF, 0xFF, 0xFF) }
	};

	int i;
	chunk_t oid = chunk_empty;

	for (i = 0; i < countof(test); i++)
	{
		oid = asn1_build_known_oid(test[i].n);
		if (test[i].oid.len == 0)
		{
			ck_assert(oid.len == 0 && oid.ptr == NULL);
		}
		else
		{
			ck_assert(chunk_equals(oid, test[i].oid));
			chunk_free(&oid);
		}
	}
}
END_TEST

/*******************************************************************************
 * oid_from_string
 */

START_TEST(test_asn1_oid_from_string)
{
	typedef struct {
		char *string;
		chunk_t oid;
	} testdata_t;

	testdata_t test[] = {
		{ "",  chunk_empty },
		{ " ", chunk_empty },
		{ "0.2.262.1", chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF) },
		{ "1.2.840.10045.4.1", chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ "1.3.6.1.4.1.36906.1", chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ "2.16.840.1.101.3.4.2.1", chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ "0.10.100.1000.10000.100000.1000000.10000000.100000000.268435455",
			chunk_from_chars(0xFF,0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ "0.1.2.3.4.5.6.7.8.9.10.128.129.130.131.132.133.134.135.136.137."
		  "256.257.258.259.260.261.262.263.264.265.384.385.386.387.388."
		  "2097153", chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF) },
		{ "0.1.2.3.4.5.6.7.8.9.10.128.129.130.131.132.133.134.135.136.137."
		  "256.257.258.259.260.261.262.263.264.265.384.385.386.387.388."
		  "1.2097153", chunk_empty },
		{ "1.a.2.b.3", chunk_empty }
	};

	int i;
	chunk_t oid = chunk_empty;

	for (i = 0; i < countof(test); i++)
	{
		oid = asn1_oid_from_string(test[i].string);
		if (test[i].oid.len == 0)
		{
			ck_assert(oid.len == 0 && oid.ptr == NULL);
		}
		else
		{
			ck_assert(chunk_equals(oid, test[i].oid));
			chunk_free(&oid);
		}
	}
}
END_TEST

/*******************************************************************************
 * oid_to_string
 */

START_TEST(test_asn1_oid_to_string)
{
	typedef struct {
		char *string;
		chunk_t oid;
	} testdata_t;

	testdata_t test[] = {
		{  NULL,  chunk_empty },
		{ "0.2.262.1", chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF) },
		{ "1.2.840.10045.4.1", chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ "1.3.6.1.4.1.36906.1", chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ "2.16.840.1.101.3.4.2.1", chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ "0.10.100.1000.10000.100000.1000000.10000000.100000000.268435455",
			chunk_from_chars( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ NULL, chunk_from_chars(
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		    0xFF, 0xFF, 0xFF, 0xFF) },
		{ NULL, chunk_from_chars(0xFF, 0xFF) }
	};

	int i;
	char *string = NULL;

	for (i = 0; i < countof(test); i++)
	{
		string = asn1_oid_to_string(test[i].oid);
		if (test[i].string == NULL)
		{
			ck_assert(string == NULL);
		}
		else
		{
			ck_assert(streq(string, test[i].string));
			free(string);
		}
	}
}
END_TEST

/*******************************************************************************
 * length
 */

START_TEST(test_asn1_length)
{
	chunk_t a;

	a = chunk_empty;
	ck_assert(asn1_length(&a) == ASN1_INVALID_LENGTH);

	a = chunk_from_chars(0xFF);
	ck_assert(asn1_length(&a) == ASN1_INVALID_LENGTH);

	a = chunk_from_chars(0xFF, 0xFF);
	ck_assert(asn1_length(&a) == 0);

	a = chunk_from_chars(0xFF, 0xFF);
	ck_assert(asn1_length(&a) == ASN1_INVALID_LENGTH);

	a = chunk_from_chars(0xFF, 0xFF, 0xFF);
	ck_assert(asn1_length(&a) == 1);

	a = chunk_from_chars(0xFF, 0xFF, 0xFF);
	a.len = 2 + 127;
	ck_assert(asn1_length(&a) == 127);

	a = chunk_from_chars(0xFF, 0xFF, 0xFF);
	a.len = 2 + 128;
	ck_assert(asn1_length(&a) == ASN1_INVALID_LENGTH);

	a = chunk_from_chars(0xFF, 0xFF);
	ck_assert(asn1_length(&a) == ASN1_INVALID_LENGTH);

	a = chunk_from_chars(0xFF, 0xFF, 0xFF);
	ck_assert(asn1_length(&a) == 0);

	a = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF);
	ck_assert(asn1_length(&a) == ASN1_INVALID_LENGTH);

	a = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF);
	a.len = 3 + 128;
	ck_assert(asn1_length(&a) == 128);

	a = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	a.len = 4 + 258;
	ck_assert(asn1_length(&a) == 258);

	a = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	a.len = 5 + 66051;
	ck_assert(asn1_length(&a) == 66051);

	a = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	a.len = 6 + 16909060;
	ck_assert(asn1_length(&a) == 16909060);

	/* largest chunk on 32 bit system */
	a = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	a.len = 4294967295U;
	ck_assert(asn1_length(&a) == 4294967289U);

}
END_TEST

/*******************************************************************************
 * unwrap
 */

START_TEST(test_asn1_unwrap)
{
	chunk_t c0 = chunk_from_chars(0xFF);
	chunk_t c1 = chunk_from_chars(0xFF, 0xFF, 0xFF);
	chunk_t c2 = chunk_from_chars(0xFF, 0xFF);
	chunk_t c3 = chunk_from_chars(0xFF, 0xFF);
	chunk_t c4 = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF);
	chunk_t c5 = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF);

	chunk_t inner;
	chunk_t inner_ref = chunk_from_chars(0xFF);

	ck_assert(asn1_unwrap(&c0, &inner) == ASN1_INVALID);

	ck_assert(asn1_unwrap(&c1, &inner) == ASN1_SEQUENCE);

	ck_assert(chunk_equals(inner, inner_ref));

	ck_assert(asn1_unwrap(&c2, &inner) == ASN1_INVALID);

	ck_assert(asn1_unwrap(&c3, &inner) == ASN1_INVALID);

	ck_assert(asn1_unwrap(&c4, &inner) == ASN1_SEQUENCE);

	ck_assert(chunk_equals(inner, inner_ref));

	ck_assert(asn1_unwrap(&c5, &inner) == ASN1_INVALID);
}
END_TEST

/*******************************************************************************
 * is_asn1
 */

START_TEST(test_is_asn1)
{
	typedef struct {
		bool asn1;
		chunk_t chunk;
	} testdata_t;

	u_char buf[8];
	chunk_t chunk_zero = { buf, 0 };
	chunk_t chunk_mean = {   0, 1 };

	testdata_t test[] = {
		{ FALSE, chunk_zero },
		{ FALSE, chunk_empty },
		{ FALSE, chunk_mean },
		{ TRUE,  chunk_from_chars(0xFF, 0xFF) },
		{ TRUE,  chunk_from_chars(0xFF, 0xFF) },
		{ TRUE,  chunk_from_chars(0xFF, 0xFF) },
		{ FALSE, chunk_from_chars(0xFF, 0xFF) },
		{ FALSE, chunk_from_chars(0xFF, 0xFF) },
		{ FALSE, chunk_from_chars(0xFF, 0xFF) },
		{ TRUE,  chunk_from_chars(0xFF, 0xFF, 0xFF) },
		{ FALSE, chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF) },
		{ TRUE,  chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF) },
		{ FALSE, chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
	};

	int i;

	for (i = 0; i < countof(test); i++)
	{
		ck_assert(is_asn1(test[i].chunk) == test[i].asn1);
	}
}
END_TEST

/*******************************************************************************
 * is_printablestring
 */

START_TEST(test_asn1_is_printablestring)
{
	typedef struct {
		bool printable;
		char *string;
	} testdata_t;


	testdata_t test[] = {
		{ TRUE,  "" },
		{ TRUE,  "Z" },
		{ FALSE, "Z#" },
		{ FALSE, "&Z" },
		{ FALSE, "Z@z" },
		{ FALSE, "!" },  { FALSE, "*" },  { FALSE, "$" },  { FALSE, "%" },
		{ FALSE, "[" },  { FALSE, "]" },  { FALSE, "{" },  { FALSE, "}" },
		{ FALSE, "|" },  { FALSE, "~" },  { FALSE, "^" },  { FALSE, "_" },
		{ FALSE, "\"" }, { FALSE, "\\" }, { FALSE, "ä" },  { FALSE, "à" },
		{ TRUE,  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
				 "0123456789 '()+,-./:=?" },
	};

	chunk_t chunk;
	int i;

	ck_assert(asn1_is_printablestring(chunk_empty));

	for (i = 0; i < countof(test); i++)
	{
		chunk = chunk_from_str(test[i].string);
		ck_assert(asn1_is_printablestring(chunk) == test[i].printable);
	}
}
END_TEST

/*******************************************************************************
 * to_time
 */

START_TEST(test_asn1_to_time)
{
	typedef struct {
		time_t time;
		uint8_t type;
		char *string;
	} testdata_t;

	testdata_t test[] = {
		{       352980, 0xFF, "197001050203Z" },
		{       352984, 0xFF, "19700105020304Z" },
		{       352980, 0xFF, "7001050203Z" },
		{       347580, 0xFF, "7001050203+0130" },
		{       358380, 0xFF, "7001050203-0130" },
		{       352984, 0xFF, "700105020304Z" },
		{       347584, 0xFF, "700105020304+0130" },
		{       358384, 0xFF, "700105020304-0130" },
		{            0, 0xFF, "700105020304+01" },
		{            0, 0xFF, "700105020304-01" },
		{            0, 0xFF, "700105020304" },
		{            0, 0xFF, "70010502Z" },
		{            0, 0xFF, "7001050203xxZ" },
		{            0, 0xFF, "7000050203Z" },
		{            0, 0xFF, "7013050203Z" },
		{            0, 0xFF, "7001004203Z" },
		{            0, 0xFF, "7001320203Z" },
		{            0, 0xFF, "700101-103Z" },
		{            0, 0xFF, "7001016003Z" },
		{            0, 0xFF, "70010102-1Z" },
		{            0, 0xFF, "7001010260Z" },
		{            0, 0xFF, "7001010203-1Z" },
		{            0, 0xFF, "700101020361Z" },
		{   -631152000, 0xFF, "500101000000Z" }, /* UTCTime min */
		{           59, 0xFF, "691231235959-0001" },
		{           -1, 0xFF, "691231235959Z" },
		{            0, 0xFF, "700101000000Z" },
		{          -60, 0xFF, "700101000000+0001" },
		{ 2524607999UL, 0xFF, "491231235959Z" }, /* UTCTime max */
		{      5097600, 0xFF, "7003010000Z" },
		{     68256000, 0xFF, "7203010000Z" },
		{    951868800, 0xFF, "0003010000Z" },
		{ 4107542400UL, 0xFF, "210003010000Z" }
	};

	int i;
	chunk_t chunk;

	for (i = 0; i < countof(test); i++)
	{
		if (sizeof(time_t) == 4 && test[i].time < 0)
		{
			continue;
		}
		chunk = chunk_from_str(test[i].string);
		ck_assert(asn1_to_time(&chunk, test[i].type) == test[i].time);
	}
}
END_TEST

/*******************************************************************************
 * from_time
 */

START_TEST(test_asn1_from_time)
{
	typedef struct {
		time_t time;
		uint8_t type;
		chunk_t chunk;
	} testdata_t;

	testdata_t test[] = {
		{       352984, 0xFF, chunk_from_chars(
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{       352984, 0xFF, chunk_from_chars(
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{   1078099200, 0xFF, chunk_from_chars(
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ 4107542400UL, 0xFF, chunk_from_chars(
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) }
	};

	int i;
	chunk_t chunk;

	for (i = 0; i < countof(test); i++)
	{
		if (sizeof(time_t) == 4 && test[i].time < 0)
		{
			continue;
		}
		chunk = asn1_from_time(&test[i].time, test[i].type);
		ck_assert(chunk_equals(chunk, test[i].chunk));
		free(chunk.ptr);
	}
}
END_TEST

/*******************************************************************************
 * parse_time
 */

START_TEST(test_asn1_parse_time)
{
	typedef struct {
		time_t time;
		chunk_t chunk;
	} testdata_t;

	testdata_t test[] = {
		{ 352984, chunk_from_chars(
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ 352984, chunk_from_chars(
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{      0, chunk_from_chars(0xFF, 0xFF) }
	};

	int i;

	for (i = 0; i < countof(test); i++)
	{
		ck_assert(asn1_parse_time(test[i].chunk, 0) == test[i].time);
	}
}
END_TEST

/*******************************************************************************
 * build_object
 */

START_TEST(test_asn1_build_object)
{
	typedef struct {
		size_t len;
		size_t size;
		u_char *b;
	} testdata_t;

	u_char b0[] = { 0xFF, 0xFF };
	u_char b1[] = { 0xFF, 0xFF };
	u_char b2[] = { 0xFF, 0xFF, 0xFF };
	u_char b3[] = { 0xFF, 0xFF, 0xFF };
	u_char b4[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	u_char b5[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	u_char b6[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	testdata_t test[] = {
		{     0, sizeof(b0), b0 },
		{   127, sizeof(b1), b1 },
		{   128, sizeof(b2), b2 },
 		{   255, sizeof(b3), b3 },
		{   256, sizeof(b4), b4 },
		{ 65535, sizeof(b5), b5 },
		{ 65536, sizeof(b6), b6 }
	};

	chunk_t a = chunk_empty;
	u_char *pos;
	int i;

	for (i = 0; i < countof(test); i++)
	{
		pos = asn1_build_object(&a, test[i].b[0], test[i].len);
		ck_assert(pos == (a.ptr + test[i].size));
		ck_assert(a.len == test[i].size + test[i].len);
		ck_assert(memeq(a.ptr, test[i].b, test[i].size));
		chunk_free(&a);
	}
}
END_TEST

/*******************************************************************************
 * simple_object
 */

START_TEST(test_asn1_simple_object)
{
	chunk_t a = chunk_empty;
	chunk_t b = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	chunk_t c = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

	a = asn1_simple_object(0xFF, c);
	ck_assert(chunk_equals(a, b));
	chunk_free(&a);
}
END_TEST

/*******************************************************************************
 * parse_simple_object
 */

START_TEST(test_asn1_parse_simple_object)
{
	typedef struct {
		bool res;
		int type;
		chunk_t chunk;
	} testdata_t;

	testdata_t test[] = {
		{ FALSE, 0xFF, chunk_from_chars(0xFF) },
		{ FALSE, 0xFF, chunk_from_chars(0xFF, 0xFF, 0xFF) },
		{ FALSE, 0xFF, chunk_from_chars(0xFF, 0xFF) },
		{ TRUE,  0xFF, chunk_from_chars(0xFF, 0xFF, 0xFF) },
		{ TRUE,  0xFF, chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF) },
		{ TRUE,  0xFF, chunk_from_chars(0xFF, 0xFF) },
		{ TRUE,  0xFF, chunk_from_chars(0xFF, 0xFF, 0xFF), }
	};

	int i;
	bool res;

	for (i = 0; i < countof(test); i++)
	{
		res = asn1_parse_simple_object(&test[i].chunk, test[i].type, 0, "test");
		ck_assert(res == test[i].res);
		if (res && test[i].chunk.len)
		{
			ck_assert(*test[i].chunk.ptr == 0xFF);
		}
	}
}
END_TEST

/*******************************************************************************
 * bitstring
 */

START_TEST(test_asn1_bitstring)
{
	chunk_t a = chunk_empty;
	chunk_t b = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	chunk_t c = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF);
	chunk_t d = chunk_clone(c);

	a = asn1_bitstring("c", c);
	ck_assert(chunk_equals(a, b));
	chunk_free(&a);

	a = asn1_bitstring("m", d);
	ck_assert(chunk_equals(a, b));
	chunk_free(&a);
}
END_TEST

/*******************************************************************************
 * integer
 */

START_TEST(test_asn1_integer)
{
	typedef struct {
		chunk_t b;
		chunk_t c;
	} testdata_t;

	chunk_t b0 = chunk_from_chars(0xFF, 0xFF, 0xFF);
	chunk_t b1 = chunk_from_chars(0xFF, 0xFF, 0xFF);
	chunk_t b2 = chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF);

	chunk_t c0 = chunk_empty;
	chunk_t c1 = chunk_from_chars(0xFF);
	chunk_t c2 = chunk_from_chars(0xFF);
	chunk_t c3 = chunk_from_chars(0xFF, 0xFF);

	testdata_t test[] = {
		{ b0, c0 },
		{ b1, c1 },
		{ b2, c2 },
		{ b2, c3 }
	};

	chunk_t a = chunk_empty;
	int i;

	for (i = 0; i < countof(test); i++)
	{
		a = asn1_integer("c", test[i].c);
		ck_assert(chunk_equals(a, test[i].b));
		chunk_free(&a);

		a = asn1_integer("m", chunk_clone(test[i].c));
		ck_assert(chunk_equals(a, test[i].b));
		chunk_free(&a);
	}
}
END_TEST

/*******************************************************************************
 * parse_integer_uint64
 */

START_TEST(test_asn1_parse_integer_uint64)
{
	struct {
		uint64_t n;
		chunk_t chunk;
	} test[] = {
		{             67305985ULL, chunk_from_chars(
						0xFF, 0xFF, 0xFF, 0xFF) },
		{   578437695752307201ULL, chunk_from_chars(
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ 18446744073709551615ULL, chunk_from_chars(
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) }
	};

	int i;

	for (i = 0; i < countof(test); i++)
	{
		ck_assert(asn1_parse_integer_uint64(test[i].chunk) == test[i].n);
	}
}
END_TEST

/*******************************************************************************
 * integer_from_uint64
 */

START_TEST(test_asn1_integer_from_uint64)
{
	struct {
		uint64_t n;
		chunk_t chunk;
	} test[] = {
		{                    0ULL, chunk_from_chars(0xFF) },
		{                  255ULL, chunk_from_chars(0xFF) },
		{                  256ULL, chunk_from_chars(0xFF, 0xFF) },
		{             67305985ULL, chunk_from_chars(0xFF, 0xFF, 0xFF, 0xFF) },
		{   578437695752307201ULL, chunk_from_chars(
							0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
		{ 18446744073709551615ULL, chunk_from_chars(
							0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
	};
	chunk_t asn;
	int i;

	for (i = 0; i < countof(test); i++)
	{
		asn = asn1_integer_from_uint64(test[i].n);
		ck_assert_chunk_eq(test[i].chunk, asn);
		chunk_free(&asn);
	}
}
END_TEST

Suite *asn1_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("asn1");

	tc = tcase_create("algorithmIdentifier");
	tcase_add_test(tc, test_asn1_algorithmIdentifier);
	suite_add_tcase(s, tc);

	tc = tcase_create("parse_algorithmIdentifier");
	tcase_add_test(tc, test_asn1_parse_algorithmIdentifier);
	suite_add_tcase(s, tc);

	tc = tcase_create("known_oid");
	tcase_add_test(tc, test_asn1_known_oid);
	suite_add_tcase(s, tc);

	tc = tcase_create("build_known_oid");
	tcase_add_test(tc, test_asn1_build_known_oid);
	suite_add_tcase(s, tc);

	tc = tcase_create("oid_from_string");
	tcase_add_test(tc, test_asn1_oid_from_string);
	suite_add_tcase(s, tc);

	tc = tcase_create("oid_to_string");
	tcase_add_test(tc, test_asn1_oid_to_string);
	suite_add_tcase(s, tc);

	tc = tcase_create("length");
	tcase_add_test(tc, test_asn1_length);
	suite_add_tcase(s, tc);

	tc = tcase_create("unwrap");
	tcase_add_test(tc, test_asn1_unwrap);
	suite_add_tcase(s, tc);

	tc = tcase_create("is_asn1");
	tcase_add_test(tc, test_is_asn1);
	suite_add_tcase(s, tc);

	tc = tcase_create("is_printablestring");
	tcase_add_test(tc, test_asn1_is_printablestring);
	suite_add_tcase(s, tc);

	tc = tcase_create("to_time");
	tcase_add_test(tc, test_asn1_to_time);
	suite_add_tcase(s, tc);

	tc = tcase_create("from_time");
	tcase_add_test(tc, test_asn1_from_time);
	suite_add_tcase(s, tc);

	tc = tcase_create("parse_time");
	tcase_add_test(tc, test_asn1_parse_time);
	suite_add_tcase(s, tc);

	tc = tcase_create("build_object");
	tcase_add_test(tc, test_asn1_build_object);
	suite_add_tcase(s, tc);

	tc = tcase_create("simple_object");
	tcase_add_test(tc, test_asn1_simple_object);
	suite_add_tcase(s, tc);

	tc = tcase_create("parse_simple_object");
	tcase_add_test(tc, test_asn1_parse_simple_object);
	suite_add_tcase(s, tc);

	tc = tcase_create("bitstring");
	tcase_add_test(tc, test_asn1_bitstring);
	suite_add_tcase(s, tc);

	tc = tcase_create("integer");
	tcase_add_test(tc, test_asn1_integer);
	suite_add_tcase(s, tc);

	tc = tcase_create("integer_uint64");
	tcase_add_test(tc, test_asn1_parse_integer_uint64);
	tcase_add_test(tc, test_asn1_integer_from_uint64);
	suite_add_tcase(s, tc);

	return s;
}
