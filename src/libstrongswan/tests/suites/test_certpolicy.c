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
 * Issue a certificate fr given policy, including extended flags
 */
static certificate_t* create_cert_ext(certificate_t *ca, char *subject,
									  char *oid, x509_flag_t flags,
									  char *map_s, char *map_i,
									  u_int require_explicit,
									  u_int inhibit_mapping,
									  u_int inhibit_any)
{
	private_key_t *privkey;
	public_key_t *pubkey;
	certificate_t *cert;
	identification_t *id;
	linked_list_t *policies, *maps;
	x509_cert_policy_t policy = {};
	x509_policy_mapping_t map = {};

	privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
								 BUILD_BLOB_ASN1_DER, chunk_from_thing(keydata),
								 BUILD_END);
	ck_assert(privkey);
	pubkey = privkey->get_public_key(privkey);
	ck_assert(pubkey);
	policies = linked_list_create();
	if (oid)
	{
		policy.oid = asn1_oid_from_string(oid);
		ck_assert(policy.oid.ptr);
		policies->insert_last(policies, &policy);
	}
	maps = linked_list_create();
	if (map_s && map_i)
	{
		map.subject = asn1_oid_from_string(map_s);
		ck_assert(map.subject.ptr);
		map.issuer = asn1_oid_from_string(map_i);
		ck_assert(map.issuer.ptr);
		maps->insert_last(maps, &map);
	}
	id = identification_create_from_string(subject);
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
						BUILD_SIGNING_KEY, privkey,
						BUILD_PUBLIC_KEY, pubkey,
						BUILD_SUBJECT, id,
						BUILD_X509_FLAG, flags,
						BUILD_CERTIFICATE_POLICIES, policies,
						BUILD_POLICY_MAPPINGS, maps,
						BUILD_SIGNING_CERT, ca,
						BUILD_POLICY_REQUIRE_EXPLICIT, require_explicit,
						BUILD_POLICY_INHIBIT_MAPPING, inhibit_mapping,
						BUILD_POLICY_INHIBIT_ANY, inhibit_any,
						BUILD_END);
	ck_assert(cert);
	id->destroy(id);
	policies->destroy(policies);
	maps->destroy(maps);
	privkey->destroy(privkey);
	pubkey->destroy(pubkey);
	free(policy.oid.ptr);
	free(map.subject.ptr);
	free(map.issuer.ptr);

	return cert;
}

/**
 * Issue a certificate with given certificate policy and flags
 */
static certificate_t* create_cert(certificate_t *ca, char *subject,
								  char *oid, x509_flag_t flags,
								  char *map_s, char *map_i)
{
	return create_cert_ext(ca, subject, oid, flags, map_s, map_i,
						   X509_NO_CONSTRAINT, X509_NO_CONSTRAINT,
						   X509_NO_CONSTRAINT);
}

/**
 * Check if a certificate with given subject has an oid
 */
static bool check_oid(identification_t *subject, char *oid)
{
	enumerator_t *certs, *auths;
	certificate_t *cert;
	auth_cfg_t *auth;
	bool found = FALSE;
	auth_rule_t type;
	char *current;

	certs = lib->credmgr->create_trusted_enumerator(lib->credmgr, KEY_ANY,
													subject, FALSE);
	if (!certs->enumerate(certs, &cert, &auth))
	{
		certs->destroy(certs);
		ck_assert_msg(FALSE, "no trusted certificate found for %Y", subject);
	}
	auths = auth->create_enumerator(auth);
	while (auths->enumerate(auths, &type, &current))
	{
		if (type == AUTH_RULE_CERT_POLICY)
		{
			if (streq(current, oid))
			{
				found = TRUE;
				break;
			}
		}
	}
	auths->destroy(auths);
	certs->destroy(certs);

	return found;
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

static char *anyPolicy = "2.5.29.32.0";
static char *extended = "2.23.140.1.1";
static char *baseline = "2.23.140.1.2";

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

START_TEST(test_valid_fixed)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", baseline, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", baseline, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_valid_any1)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", baseline, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_valid_any2)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", anyPolicy, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_invalid_missing)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", baseline, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", baseline, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", NULL, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_invalid_wrong)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", baseline, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", baseline, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), extended));
}
END_TEST

START_TEST(test_invalid_any1)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", anyPolicy, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", NULL, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_invalid_any2)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", anyPolicy, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", anyPolicy, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_badchain_wrong)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", baseline, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", extended, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", extended, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), baseline));
	ck_assert(!check_oid(sj->get_subject(sj), extended));
}
END_TEST

START_TEST(test_badchain_gap)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", baseline, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", NULL, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_badchain_any)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", baseline, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", anyPolicy, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", extended, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), extended));
}
END_TEST

START_TEST(test_valid_mapping)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", extended, X509_CA, baseline, extended);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_valid_mapping_twice)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", "2.23.140.1.3", X509_CA,
					 extended, "2.23.140.1.3");
	im = create_cert(ca, "CN=IM", extended, X509_CA, baseline, extended);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_invalid_mapping_loop)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", extended, X509_CA, baseline, baseline);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_invalid_mapping_notallowed)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", baseline, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", extended, X509_CA, baseline, extended);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_invalid_mapping_nopolicy)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert(NULL, "CN=CA", baseline, X509_CA, NULL, NULL);
	im = create_cert(ca, "CN=IM", "2.23.140.1.3", X509_CA, baseline, extended);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(!check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_inhibit_mapping_good)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert_ext(NULL, "CN=CA", extended, X509_CA, NULL, NULL,
						 X509_NO_CONSTRAINT, 1, X509_NO_CONSTRAINT);
	im = create_cert(ca, "CN=IM", extended, X509_CA, baseline, extended);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_inhibit_mapping_bad)
{
	certificate_t *ca, *i1, *i2, *sj;

	ca = create_cert_ext(NULL, "CN=CA", extended, X509_CA, NULL, NULL,
						 X509_NO_CONSTRAINT, 1, X509_NO_CONSTRAINT);
	i1 = create_cert(ca, "CN=IM1", extended, X509_CA, NULL, NULL);
	i2 = create_cert(i1, "CN=IM2", extended, X509_CA, baseline, extended);
	sj = create_cert(i2, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, i1);
	creds->add_cert(creds, FALSE, i2);
	creds->add_cert(creds, FALSE, sj);

	/* TODO: we currently reject the certificate completely, but should
	 * actually just invalidate the policy not mapped properly */
	ck_assert(!check_trust(sj->get_subject(sj)));
}
END_TEST

START_TEST(test_inhibit_any_good)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert_ext(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL,
						 X509_NO_CONSTRAINT, X509_NO_CONSTRAINT, 1);
	im = create_cert(ca, "CN=IM", anyPolicy, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_inhibit_any_bad)
{
	certificate_t *ca, *i1, *i2, *sj;

	ca = create_cert_ext(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL,
						 X509_NO_CONSTRAINT, X509_NO_CONSTRAINT, 1);
	i1 = create_cert(ca, "CN=IM1", anyPolicy, X509_CA, NULL, NULL);
	i2 = create_cert(i1, "CN=IM2", anyPolicy, X509_CA, NULL, NULL);
	sj = create_cert(i2, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, i1);
	creds->add_cert(creds, FALSE, i2);
	creds->add_cert(creds, FALSE, sj);

	/* TODO: we currently reject the certificate completely, but should
	 * actually just invalidate the policy relying on inhibited anyPolicy */
	ck_assert(!check_trust(sj->get_subject(sj)));
}
END_TEST

START_TEST(test_require_explicit_good)
{
	certificate_t *ca, *im, *sj;

	ca = create_cert_ext(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL,
						 1, X509_NO_CONSTRAINT, X509_NO_CONSTRAINT);
	im = create_cert(ca, "CN=IM", baseline, X509_CA, NULL, NULL);
	sj = create_cert(im, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, im);
	creds->add_cert(creds, FALSE, sj);

	ck_assert(check_oid(sj->get_subject(sj), baseline));
}
END_TEST

START_TEST(test_require_explicit_bad)
{
	certificate_t *ca, *i1, *i2, *sj;

	ca = create_cert_ext(NULL, "CN=CA", anyPolicy, X509_CA, NULL, NULL,
						 1, X509_NO_CONSTRAINT, X509_NO_CONSTRAINT);
	i1 = create_cert(ca, "CN=IM1", extended, X509_CA, NULL, NULL);
	i2 = create_cert(i1, "CN=IM2", extended, X509_CA, NULL, NULL);
	sj = create_cert(i2, "CN=SJ", baseline, 0, NULL, NULL);

	creds->add_cert(creds, TRUE, ca);
	creds->add_cert(creds, FALSE, i1);
	creds->add_cert(creds, FALSE, i2);
	creds->add_cert(creds, FALSE, sj);

	/* TODO: we currently reject the certificate completely, but should
	 * actually just invalidate the policy violating requireExplicit */
	ck_assert(!check_trust(sj->get_subject(sj)));
}
END_TEST

Suite *certpolicy_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("certpolicy");

	tc = tcase_create("policy valid");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_valid_fixed);
	tcase_add_test(tc, test_valid_any1);
	tcase_add_test(tc, test_valid_any2);
	suite_add_tcase(s, tc);

	tc = tcase_create("policy invalid");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_invalid_missing);
	tcase_add_test(tc, test_invalid_wrong);
	tcase_add_test(tc, test_invalid_any1);
	tcase_add_test(tc, test_invalid_any2);
	suite_add_tcase(s, tc);

	tc = tcase_create("policy badchain");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_badchain_wrong);
	tcase_add_test(tc, test_badchain_gap);
	tcase_add_test(tc, test_badchain_any);
	suite_add_tcase(s, tc);

	tc = tcase_create("policy valid mapping");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_valid_mapping);
	tcase_add_test(tc, test_valid_mapping_twice);
	suite_add_tcase(s, tc);

	tc = tcase_create("policy invalid mapping");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_invalid_mapping_loop);
	tcase_add_test(tc, test_invalid_mapping_notallowed);
	tcase_add_test(tc, test_invalid_mapping_nopolicy);
	suite_add_tcase(s, tc);

	tc = tcase_create("inhibit policy mapping");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_inhibit_mapping_good);
	tcase_add_test(tc, test_inhibit_mapping_bad);
	suite_add_tcase(s, tc);

	tc = tcase_create("inhibit any policy");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_inhibit_any_good);
	tcase_add_test(tc, test_inhibit_any_bad);
	suite_add_tcase(s, tc);

	tc = tcase_create("require explicit policy");
	tcase_add_checked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_require_explicit_good);
	tcase_add_test(tc, test_require_explicit_bad);
	suite_add_tcase(s, tc);

	return s;
}
