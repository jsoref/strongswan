/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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
#include <credentials/sets/mem_cred.h>
#include <credentials/certificates/x509.h>

/**
 * RSA private key, so we don't have to generate one
 */
static char keydata[] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,
};

/**
 * Issue a certificate with permitted/excluded name constraints
 */
static certificate_t* create_cert(certificate_t *ca, char *subject, char *san,
								x509_flag_t flags, identification_t *permitted,
								identification_t *excluded)
{
	private_key_t *privkey;
	public_key_t *pubkey;
	certificate_t *cert;
	identification_t *id;
	linked_list_t *plist, *elist, *sans;

	privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
								 BUILD_BLOB_ASN1_DER, chunk_from_thing(keydata),
								 BUILD_END);
	ck_assert(privkey);
	pubkey = privkey->get_public_key(privkey);
	ck_assert(pubkey);
	plist = linked_list_create();
	if (permitted)
	{
		plist->insert_last(plist, permitted);
	}
	elist = linked_list_create();
	if (excluded)
	{
		elist->insert_last(elist, excluded);
	}
	sans = linked_list_create();
	if (san)
	{
		id = identification_create_from_string(san);
		sans->insert_last(sans, id);
	}
	id = identification_create_from_string(subject);
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
						BUILD_SIGNING_KEY, privkey,
						BUILD_PUBLIC_KEY, pubkey,
						BUILD_SUBJECT, id,
						BUILD_X509_FLAG, flags,
						BUILD_SIGNING_CERT, ca,
						BUILD_SUBJECT_ALTNAMES, sans,
						BUILD_PERMITTED_NAME_CONSTRAINTS, plist,
						BUILD_EXCLUDED_NAME_CONSTRAINTS, elist,
						BUILD_END);
	ck_assert(cert);
	id->destroy(id);
	sans->destroy_offset(sans, offsetof(identification_t, destroy));
	plist->destroy_offset(plist, offsetof(identification_t, destroy));
	elist->destroy_offset(elist, offsetof(identification_t, destroy));
	privkey->destroy(privkey);
	pubkey->destroy(pubkey);

	return cert;
}

/**
 * Check if a certificate with given subject has a valid trustchain
 */
static bool check_trust(identification_t *subject)
{
	enumerator_t *certs;
	certificate_t *cert;
	bool trusted;

	certs = lib->credmgr->create_trusted_enumerator(lib->credmgr, KEY_ANY,
													subject, FALSE);
	trusted = certs->enumerate(certs, &cert, NULL);
	certs->destroy(certs);

	return trusted;
}

static mem_cred_t *creds;

START_SETUP(setup)
{
	creds = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &creds->set);
}
END_SETUP

START_TEARDOWN(teardown)
{
	lib->credmgr->remove_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	lib->credmgr->flush_cache(lib->credmgr, CERT_ANY);
}
END_TEARDOWN

static struct {
	char *constraint;
	char *subject;
	bool good;
} permitted_dn[] = {
	{ "C=CH, O=strongSwan", "C=CH, O=strongSwan, CN=tester", TRUE },
	{ "C=CH, O=strongSwan", "C=CH, O=strong", FALSE },
	{ "C=CH, O=strongSwan", "C=CH, O=strong, CN=tester", FALSE },
	{ "C=CH, O=strongSwan", "C=CH, O=another, CN=tester", FALSE },
	{ "C=CH, O=strongSwan", "C=CH, CN=tester, O=strongSwan", FALSE },
};

START_TEST(test_permitted_dn)
{
	certificate_t *ca, *im, *sj;
	identification_t *id;

	id = identification_create_from_string(permitted_dn[_i].constraint);
	ca = create_cert(NULL, "C=CH, O=strongSwan, CN=CA", NULL, X509_CA, id, NULL);
	id = identification_create_from_string(permitted_dn[_i].constraint);
	im = create_cert(ca, "C=CH, O=strongSwan, CN=IM", NULL, X509_CA, id, NULL);
	sj = create_cert(im, permitted_dn[_i].subject, NULL, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_trust(sj->get_subject(sj)) == permitted_dn[_i].good);
}
END_TEST

static struct {
	id_type_t ctype;
	char *cdata;
	char *subject;
	bool good;
} permitted_san[] = {
	{ ID_FQDN, ".strongswan.org", "test.strongswan.org", TRUE },
	{ ID_FQDN, "strongswan.org", "test.strongswan.org", TRUE },
	{ ID_FQDN, "a.b.c.strongswan.org", "d.a.b.c.strongswan.org", TRUE },
	{ ID_FQDN, "a.b.c.strongswan.org", "a.b.c.d.strongswan.org", FALSE },
	{ ID_FQDN, "strongswan.org", "strongswan.org.com", FALSE },
	{ ID_FQDN, ".strongswan.org", "strongswan.org", FALSE },
	{ ID_FQDN, "strongswan.org", "nostrongswan.org", FALSE },
	{ ID_FQDN, "strongswan.org", "swan.org", FALSE },
	{ ID_FQDN, "strongswan.org", "swan.org", FALSE },
	{ ID_RFC822_ADDR, "tester@strongswan.org", "tester@strongswan.org", TRUE },
	{ ID_RFC822_ADDR, "tester@strongswan.org", "atester@strongswan.org", FALSE },
	{ ID_RFC822_ADDR, "strongswan.org", "tester@strongswan.org", TRUE },
	{ ID_RFC822_ADDR, "strongswan.org", "tester@test.strongswan.org", FALSE },
	{ ID_RFC822_ADDR, ".strongswan.org", "tester@test.strongswan.org", TRUE },
	{ ID_RFC822_ADDR, ".strongswan.org", "tester@strongswan.org", FALSE },
};

START_TEST(test_permitted_san)
{
	certificate_t *ca, *sj;
	identification_t *id;

	id = identification_create_from_encoding(permitted_san[_i].ctype,
									chunk_from_str(permitted_san[_i].cdata));
	ca = create_cert(NULL, "CN=CA", NULL, X509_CA, id, NULL);
	sj = create_cert(ca, "CN=SJ", permitted_san[_i].subject, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_trust(sj->get_subject(sj)) == permitted_san[_i].good);
}
END_TEST

static struct {
	char *constraint;
	char *subject;
	bool good;
} excluded_dn[] = {
	{ "C=CH, O=another", "C=CH, O=strongSwan, CN=tester", TRUE },
	{ "C=CH, O=another", "C=CH, O=anot", TRUE },
	{ "C=CH, O=another", "C=CH, O=anot, CN=tester", TRUE },
	{ "C=CH, O=another", "C=CH, O=another, CN=tester", FALSE },
	{ "C=CH, O=another", "C=CH, CN=tester, O=another", TRUE },
};

START_TEST(test_excluded_dn)
{
	certificate_t *ca, *im, *sj;
	identification_t *id;

	id = identification_create_from_string(excluded_dn[_i].constraint);
	ca = create_cert(NULL, "C=CH, O=strongSwan, CN=CA", NULL, X509_CA, NULL, id);
	id = identification_create_from_string(excluded_dn[_i].constraint);
	im = create_cert(ca, "C=CH, O=strongSwan, CN=IM", NULL, X509_CA, NULL, id);
	sj = create_cert(im, excluded_dn[_i].subject, NULL, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_trust(sj->get_subject(sj)) == excluded_dn[_i].good);
}
END_TEST

static struct {
	id_type_t ctype;
	char *cdata;
	char *subject;
	bool good;
} excluded_san[] = {
	{ ID_FQDN, ".strongswan.org", "test.strongswan.org", FALSE },
	{ ID_FQDN, "strongswan.org", "test.strongswan.org", FALSE },
	{ ID_FQDN, "a.b.c.strongswan.org", "d.a.b.c.strongswan.org", FALSE },
	{ ID_FQDN, "a.b.c.strongswan.org", "a.b.c.d.strongswan.org", TRUE },
	{ ID_FQDN, "strongswan.org", "strongswan.org.com", TRUE },
	{ ID_FQDN, ".strongswan.org", "strongswan.org", TRUE },
	{ ID_FQDN, "strongswan.org", "nostrongswan.org", TRUE },
	{ ID_FQDN, "strongswan.org", "swan.org", TRUE },
	{ ID_FQDN, "strongswan.org", "swan.org", TRUE },
	{ ID_RFC822_ADDR, "tester@strongswan.org", "tester@strongswan.org", FALSE },
	{ ID_RFC822_ADDR, "tester@strongswan.org", "atester@strongswan.org", TRUE },
	{ ID_RFC822_ADDR, "strongswan.org", "tester@strongswan.org", FALSE },
	{ ID_RFC822_ADDR, "strongswan.org", "tester@test.strongswan.org", TRUE },
	{ ID_RFC822_ADDR, ".strongswan.org", "tester@test.strongswan.org", FALSE },
	{ ID_RFC822_ADDR, ".strongswan.org", "tester@strongswan.org", TRUE },
};

START_TEST(test_excluded_san)
{
	certificate_t *ca, *sj;
	identification_t *id;

	id = identification_create_from_encoding(excluded_san[_i].ctype,
									chunk_from_str(excluded_san[_i].cdata));
	ca = create_cert(NULL, "CN=CA", NULL, X509_CA, NULL, id);
	sj = create_cert(ca, "CN=SJ", excluded_san[_i].subject, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_trust(sj->get_subject(sj)) == excluded_san[_i].good);
}
END_TEST

static struct {
	char *caconst;
	char *imconst;
	char *subject;
	bool good;
} permitted_dninh[] = {
	{ "C=CH", "C=CH, O=strongSwan", "C=CH, O=strongSwan, CN=tester", TRUE },
	{ "C=CH", "C=DE, O=strongSwan", "C=CH, O=strongSwan, CN=tester", FALSE },
	{ "C=CH, O=strongSwan", "C=CH", "C=CH", FALSE },
};

START_TEST(test_permitted_dninh)
{
	certificate_t *ca, *im, *sj;
	identification_t *id;

	id = identification_create_from_string(permitted_dninh[_i].caconst);
	ca = create_cert(NULL, "C=CH, O=strongSwan, CN=CA", NULL, X509_CA, id, NULL);
	id = identification_create_from_string(permitted_dninh[_i].imconst);
	im = create_cert(ca, "C=CH, O=strongSwan, CN=IM", NULL, X509_CA, id, NULL);
	sj = create_cert(im, permitted_dninh[_i].subject, NULL, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_trust(sj->get_subject(sj)) == permitted_dninh[_i].good);
}
END_TEST

static struct {
	char *caconst;
	char *imconst;
	char *subject;
	bool good;
} excluded_dninh[] = {
	{ "C=CH, O=strongSwan", "C=CH", "C=DE", TRUE },
	{ "C=CH, O=strongSwan", "C=DE", "C=CH", FALSE },
	{ "C=CH", "C=CH, O=strongSwan", "C=CH, O=strongSwan, CN=tester", FALSE },
};

START_TEST(test_excluded_dninh)
{
	certificate_t *ca, *im, *sj;
	identification_t *id;

	id = identification_create_from_string(excluded_dninh[_i].caconst);
	ca = create_cert(NULL, "C=CH, O=strongSwan, CN=CA", NULL, X509_CA, NULL, id);
	id = identification_create_from_string(excluded_dninh[_i].imconst);
	im = create_cert(ca, "C=DE, CN=IM", NULL, X509_CA, NULL, id);
	sj = create_cert(im, excluded_dninh[_i].subject, NULL, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_trust(sj->get_subject(sj)) == excluded_dninh[_i].good);
}
END_TEST

Suite *certnames_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("certnames");

	tc = tcase_create("permitted DN name constraints");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_permitted_dn, 0, countof(permitted_dn));
	suite_add_tcase(s, tc);

	tc = tcase_create("permitted subjectAltName constraints");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_permitted_san, 0, countof(permitted_san));
	suite_add_tcase(s, tc);

	tc = tcase_create("excluded DN constraints");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_excluded_dn, 0, countof(excluded_dn));
	suite_add_tcase(s, tc);

	tc = tcase_create("excluded subjectAltName constraints");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_excluded_san, 0, countof(excluded_san));
	suite_add_tcase(s, tc);

	tc = tcase_create("permitted DN name constraint inherit");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_permitted_dninh, 0, countof(permitted_dninh));
	suite_add_tcase(s, tc);

	tc = tcase_create("excluded DN name constraint inherit");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_loop_test(tc, test_excluded_dninh, 0, countof(excluded_dninh));
	suite_add_tcase(s, tc);

	return s;
}
