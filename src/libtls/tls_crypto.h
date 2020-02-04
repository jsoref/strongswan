/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

/**
 * @defgroup tls_crypto tls_crypto
 * @{ @ingroup libtls
 */

#ifndef TLS_CRYPTO_H_
#define TLS_CRYPTO_H_

typedef struct tls_crypto_t tls_crypto_t;
typedef enum tls_cipher_suite_t tls_cipher_suite_t;
typedef enum tls_hash_algorithm_t tls_hash_algorithm_t;
typedef enum tls_signature_algorithm_t tls_signature_algorithm_t;
typedef enum tls_client_certificate_type_t tls_client_certificate_type_t;
typedef enum tls_ecc_curve_type_t tls_ecc_curve_type_t;
typedef enum tls_named_curve_t tls_named_curve_t;
typedef enum tls_ansi_point_format_t tls_ansi_point_format_t;
typedef enum tls_ec_point_format_t tls_ec_point_format_t;

#include "tls.h"
#include "tls_prf.h"
#include "tls_protection.h"

#include <library.h>

#include <credentials/keys/private_key.h>

/**
 * TLS cipher suites
 */
enum tls_cipher_suite_t {
	TLS_NULL_WITH_NULL_NULL =					0xFF,
	TLS_RSA_WITH_NULL_MD5 =						0xFF,
	TLS_RSA_WITH_NULL_SHA =						0xFF,
	TLS_RSA_EXPORT_WITH_RC4_40_MD5 =			0xFF,
	TLS_RSA_WITH_RC4_128_MD5 =					0xFF,
	TLS_RSA_WITH_RC4_128_SHA =					0xFF,
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 =		0xFF,
	TLS_RSA_WITH_IDEA_CBC_SHA =					0xFF,
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA =			0xFF,
	TLS_RSA_WITH_DES_CBC_SHA =					0xFF,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA =				0xFF,
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA =		0xFF,
	TLS_DH_DSS_WITH_DES_CBC_SHA =				0xFF,
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA =			0xFF,
	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA =		0xFF,
	TLS_DH_RSA_WITH_DES_CBC_SHA =				0xFF,
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA =			0xFF,
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA =		0xFF,
	TLS_DHE_DSS_WITH_DES_CBC_SHA =				0xFF,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA =			0xFF,
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA =		0xFF,
	TLS_DHE_RSA_WITH_DES_CBC_SHA =				0xFF,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA =			0xFF,
	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 =		0xFF,
	TLS_DH_anon_WITH_RC4_128_MD5 =				0xFF,
	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA =		0xFF,
	TLS_DH_anon_WITH_DES_CBC_SHA =				0xFF,
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA =			0xFF,

	TLS_KRB5_WITH_DES_CBC_SHA =					0xFF,
	TLS_KRB5_WITH_3DES_EDE_CBC_SHA =			0xFF,
	TLS_KRB5_WITH_RC4_128_SHA =					0xFF,
	TLS_KRB5_WITH_IDEA_CBC_SHA =				0xFF,
	TLS_KRB5_WITH_DES_CBC_MD5 =					0xFF,
	TLS_KRB5_WITH_3DES_EDE_CBC_MD5 =			0xFF,
	TLS_KRB5_WITH_RC4_128_MD5 =					0xFF,
	TLS_KRB5_WITH_IDEA_CBC_MD5 =				0xFF,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA =		0xFF,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA =		0xFF,
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA =			0xFF,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 =		0xFF,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 =		0xFF,
	TLS_KRB5_EXPORT_WITH_RC4_40_MD5 =			0xFF,
	TLS_PSK_WITH_NULL_SHA =						0xFF,
	TLS_DHE_PSK_WITH_NULL_SHA =					0xFF,
	TLS_RSA_PSK_WITH_NULL_SHA =					0xFF,
	TLS_RSA_WITH_AES_128_CBC_SHA =				0xFF,
	TLS_DH_DSS_WITH_AES_128_CBC_SHA =			0xFF,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA =			0xFF,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA =			0xFF,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA =			0xFF,
	TLS_DH_anon_WITH_AES_128_CBC_SHA =			0xFF,
	TLS_RSA_WITH_AES_256_CBC_SHA =				0xFF,
	TLS_DH_DSS_WITH_AES_256_CBC_SHA =			0xFF,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA =			0xFF,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA =			0xFF,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA =			0xFF,
	TLS_DH_anon_WITH_AES_256_CBC_SHA =			0xFF,
	TLS_RSA_WITH_NULL_SHA256 =					0xFF,
	TLS_RSA_WITH_AES_128_CBC_SHA256 =			0xFF,
	TLS_RSA_WITH_AES_256_CBC_SHA256 =			0xFF,
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA =			0xFF,
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA =		0xFF,
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA =		0xFF,
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA =		0xFF,
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA =		0xFF,
	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA =		0xFF,

	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256 =		0xFF,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256 =		0xFF,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 =		0xFF,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 =		0xFF,
	TLS_DH_anon_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_DH_anon_WITH_AES_256_CBC_SHA256 =		0xFF,

	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA =			0xFF,
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA =		0xFF,
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA =		0xFF,
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA =		0xFF,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA =		0xFF,
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA =		0xFF,
	TLS_PSK_WITH_RC4_128_SHA =					0xFF,
	TLS_PSK_WITH_3DES_EDE_CBC_SHA =				0xFF,
	TLS_PSK_WITH_AES_128_CBC_SHA =				0xFF,
	TLS_PSK_WITH_AES_256_CBC_SHA =				0xFF,
	TLS_DHE_PSK_WITH_RC4_128_SHA =				0xFF,
	TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA =			0xFF,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA =			0xFF,
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA =			0xFF,
	TLS_RSA_PSK_WITH_RC4_128_SHA =				0xFF,
	TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA =			0xFF,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA =			0xFF,
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA =			0xFF,
	TLS_RSA_WITH_SEED_CBC_SHA =					0xFF,
	TLS_DH_DSS_WITH_SEED_CBC_SHA =				0xFF,
	TLS_DH_RSA_WITH_SEED_CBC_SHA =				0xFF,
	TLS_DHE_DSS_WITH_SEED_CBC_SHA =				0xFF,
	TLS_DHE_RSA_WITH_SEED_CBC_SHA =				0xFF,
	TLS_DH_anon_WITH_SEED_CBC_SHA =				0xFF,
	TLS_RSA_WITH_AES_128_GCM_SHA256 =			0xFF,
	TLS_RSA_WITH_AES_256_GCM_SHA384 =			0xFF,
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 =		0xFF,
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 =		0xFF,
	TLS_DH_RSA_WITH_AES_128_GCM_SHA256 =		0xFF,
	TLS_DH_RSA_WITH_AES_256_GCM_SHA384 =		0xFF,
	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 =		0xFF,
	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 =		0xFF,
	TLS_DH_DSS_WITH_AES_128_GCM_SHA256 =		0xFF,
	TLS_DH_DSS_WITH_AES_256_GCM_SHA384 =		0xFF,
	TLS_DH_anon_WITH_AES_128_GCM_SHA256 =		0xFF,
	TLS_DH_anon_WITH_AES_256_GCM_SHA384 =		0xFF,
	TLS_PSK_WITH_AES_128_GCM_SHA256 =			0xFF,
	TLS_PSK_WITH_AES_256_GCM_SHA384 =			0xFF,
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 =		0xFF,
	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 =		0xFF,
	TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 =		0xFF,
	TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 =		0xFF,
	TLS_PSK_WITH_AES_128_CBC_SHA256 =			0xFF,
	TLS_PSK_WITH_AES_256_CBC_SHA384 =			0xFF,
	TLS_PSK_WITH_NULL_SHA256 =					0xFF,
	TLS_PSK_WITH_NULL_SHA384 =					0xFF,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 =		0xFF,
	TLS_DHE_PSK_WITH_NULL_SHA256 =				0xFF,
	TLS_DHE_PSK_WITH_NULL_SHA384 =				0xFF,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 =		0xFF,
	TLS_RSA_PSK_WITH_NULL_SHA256 =				0xFF,
	TLS_RSA_PSK_WITH_NULL_SHA384 =				0xFF,
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 =		0xFF,
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 =	0xFF,
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 =	0xFF,
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 =	0xFF,
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 =	0xFF,
	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 =	0xFF,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 =		0xFF,
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 =	0xFF,
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 =	0xFF,
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 =	0xFF,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 =	0xFF,
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 =	0xFF,

	TLS_EMPTY_RENEGOTIATION_INFO_SCSV =			0xFF,

	TLS_ECDH_ECDSA_WITH_NULL_SHA =				0xFF,
	TLS_ECDH_ECDSA_WITH_RC4_128_SHA =			0xFF,
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA =		0xFF,
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA =		0xFF,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA =		0xFF,
	TLS_ECDHE_ECDSA_WITH_NULL_SHA =				0xFF,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA =			0xFF,
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA =		0xFF,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA =		0xFF,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA =		0xFF,
	TLS_ECDH_RSA_WITH_NULL_SHA =				0xFF,
	TLS_ECDH_RSA_WITH_RC4_128_SHA =				0xFF,
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA =		0xFF,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA =			0xFF,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA =			0xFF,
	TLS_ECDHE_RSA_WITH_NULL_SHA =				0xFF,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA =			0xFF,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA =		0xFF,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA =		0xFF,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA =		0xFF,
	TLS_ECDH_anon_WITH_NULL_SHA =				0xFF,
	TLS_ECDH_anon_WITH_RC4_128_SHA =			0xFF,
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA =		0xFF,
	TLS_ECDH_anon_WITH_AES_128_CBC_SHA =		0xFF,
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA =		0xFF,
	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA =			0xFF,
	TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA =		0xFF,
	TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA =		0xFF,
	TLS_SRP_SHA_WITH_AES_128_CBC_SHA =			0xFF,
	TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA =		0xFF,
	TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA =		0xFF,
	TLS_SRP_SHA_WITH_AES_256_CBC_SHA =			0xFF,
	TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA =		0xFF,
	TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA =		0xFF,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 =	0xFF,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 =	0xFF,
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 =	0xFF,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 =	0xFF,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 =		0xFF,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 =		0xFF,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 =	0xFF,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 =	0xFF,
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 =	0xFF,
	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 =	0xFF,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =		0xFF,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =		0xFF,
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 =		0xFF,
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 =		0xFF,
	TLS_ECDHE_PSK_WITH_RC4_128_SHA =			0xFF,
	TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA =		0xFF,
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA =		0xFF,
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA =		0xFF,
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 =		0xFF,
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 =		0xFF,
	TLS_ECDHE_PSK_WITH_NULL_SHA =				0xFF,
	TLS_ECDHE_PSK_WITH_NULL_SHA256 =			0xFF,
	TLS_ECDHE_PSK_WITH_NULL_SHA384 =			0xFF
};

/**
 * Enum names for tls_cipher_suite_t
 */
extern enum_name_t *tls_cipher_suite_names;

/**
 * TLS HashAlgorithm identifiers
 */
enum tls_hash_algorithm_t {
	TLS_HASH_NONE =		0,
	TLS_HASH_MD5 =		1,
	TLS_HASH_SHA1 =		2,
	TLS_HASH_SHA224 =	3,
	TLS_HASH_SHA256 =	4,
	TLS_HASH_SHA384 =	5,
	TLS_HASH_SHA512 =	6,
};

/**
 * Enum names for tls_hash_algorithm_t
 */
extern enum_name_t *tls_hash_algorithm_names;

/**
 * TLS SignatureAlgorithm identifiers
 */
enum tls_signature_algorithm_t {
	TLS_SIG_RSA =		1,
	TLS_SIG_DSA =		2,
	TLS_SIG_ECDSA =		3,
};

/**
 * Enum names for tls_signature_algorithm_t
 */
extern enum_name_t *tls_signature_algorithm_names;

/**
 * TLS ClientCertificateType
 */
enum tls_client_certificate_type_t {
	TLS_RSA_SIGN =			1,
	TLS_DSA_SIGN =			2,
	TLS_RSA_FIXED_DH =		3,
	TLS_DSS_FIXED_DH =		4,
	TLS_RSA_EPHEMERAL_DH =	5,
	TLS_DSS_EPHEMERAL_DH =	6,
	TLS_FORTEZZA_DMS =		20,
	TLS_ECDSA_SIGN =		64,
	TLS_RSA_FIXED_ECDH =	65,
	TLS_ECDSA_FIXED_ECDH =	66,
};

/**
 * Enum names for tls_client_certificate_type_t
 */
extern enum_name_t *tls_client_certificate_type_names;

/**
 * TLS EccCurveType
 */
enum tls_ecc_curve_type_t {
	TLS_ECC_EXPLICIT_PRIME =	1,
	TLS_ECC_EXPLICIT_CHAR2 =	2,
	TLS_ECC_NAMED_CURVE =		3,
};

/**
 * Enum names for tls_ecc_curve_type_t
 */
extern enum_name_t *tls_ecc_curve_type_names;

/**
 * TLS Named Curve identifiers
 */
enum tls_named_curve_t {
	TLS_SECT163K1 =		 1,
	TLS_SECT163R1 =		 2,
	TLS_SECT163R2 =		 3,
	TLS_SECT193R1 =		 4,
	TLS_SECT193R2 =		 5,
	TLS_SECT233K1 =		 6,
	TLS_SECT233R1 =		 7,
	TLS_SECT239K1 =		 8,
	TLS_SECT283K1 =		 9,
	TLS_SECT283R1 =		10,
	TLS_SECT409K1 =		11,
	TLS_SECT409R1 =		12,
	TLS_SECT571K1 =		13,
	TLS_SECT571R1 =		14,
	TLS_SECP160K1 =		15,
	TLS_SECP160R1 =		16,
	TLS_SECP160R2 =		17,
	TLS_SECP192K1 =		18,
	TLS_SECP192R1 =		19,
	TLS_SECP224K1 =		20,
	TLS_SECP224R1 =		21,
	TLS_SECP256K1 =		22,
	TLS_SECP256R1 =		23,
	TLS_SECP384R1 =		24,
	TLS_SECP521R1 =		25,
};

/**
 * Enum names for tls_named_curve_t
 */
extern enum_name_t *tls_named_curve_names;

/**
 * EC Point format, ANSI X9.62.
 */
enum tls_ansi_point_format_t {
	TLS_ANSI_COMPRESSED =	2,
	TLS_ANSI_COMPRESSED_Y =	3,
	TLS_ANSI_UNCOMPRESSED =	4,
	TLS_ANSI_HYBRID =		6,
	TLS_ANSI_HYBRID_Y =		7,
};

/**
 * Enum names for tls_ansi_point_format_t.
 */
extern enum_name_t *tls_ansi_point_format_names;

/**
 * EC Point format, TLS specific identifiers.
 */
enum tls_ec_point_format_t {
	TLS_EC_POINT_UNCOMPRESSED = 0,
	TLS_EC_POINT_ANSIX962_COMPRESSED_PRIME = 1,
	TLS_EC_POINT_ANSIX962_COMPRESSED_CHAR2 = 2,
};

/**
 * Enum names for tls_ec_point_format_t.
 */
extern enum_name_t *tls_ec_point_format_names;

/**
 * TLS crypto helper functions.
 */
struct tls_crypto_t {

	/**
	 * Get a list of supported TLS cipher suites.
	 *
	 * @param suites		list of suites, points to internal data
	 * @return				number of suites returned
	 */
	int (*get_cipher_suites)(tls_crypto_t *this, tls_cipher_suite_t **suites);

	/**
	 * Select and store a cipher suite from a given list of candidates.
	 *
	 * @param suites		list of candidates to select from
	 * @param count			number of suites
	 * @param key			key type used, or KEY_ANY
	 * @return				selected suite, 0 if none acceptable
	 */
	tls_cipher_suite_t (*select_cipher_suite)(tls_crypto_t *this,
										tls_cipher_suite_t *suites, int count,
										key_type_t key);

	/**
	 * Get the Diffie-Hellman group to use, if any.
	 *
	 * @return				Diffie Hellman group, ord MODP_NONE
	 */
	diffie_hellman_group_t (*get_dh_group)(tls_crypto_t *this);

	/**
	 * Write the list of supported hash/sig algorithms to writer.
	 *
	 * @param writer		writer to write supported hash/sig algorithms
	 */
	void (*get_signature_algorithms)(tls_crypto_t *this, bio_writer_t *writer);

	/**
	 * Create an enumerator over supported ECDH groups.
	 *
	 * Enumerates over (diffie_hellman_group_t, tls_named_curve_t)
	 *
	 * @return				enumerator
	 */
	enumerator_t* (*create_ec_enumerator)(tls_crypto_t *this);

	/**
	 * Set the protection layer of the TLS stack to control it.
	 *
	 * @param protection		protection layer to work on
	 */
	void (*set_protection)(tls_crypto_t *this, tls_protection_t *protection);

	/**
	 * Store exchanged handshake data, used for cryptographic operations.
	 *
	 * @param type			handshake sub type
	 * @param data			data to append to handshake buffer
	 */
	void (*append_handshake)(tls_crypto_t *this,
							 tls_handshake_type_t type, chunk_t data);

	/**
	 * Sign a blob of data, append signature to writer.
	 *
	 * @param key			private key to use for signature
	 * @param writer		TLS writer to write signature to
	 * @param data			data to sign
	 * @param hashsig		list of TLS1.2 hash/sig algorithms to select from
	 * @return				TRUE if signature create successfully
	 */
	bool (*sign)(tls_crypto_t *this, private_key_t *key,
				 bio_writer_t *writer, chunk_t data, chunk_t hashsig);

	/**
	 * Verify a blob of data, read signature from a reader.
	 *
	 * @param key			public key to verify signature with
	 * @param reader		TLS reader to read signature from
	 * @param data			data to verify signature
	 * @return				TRUE if signature valid
	 */
	bool (*verify)(tls_crypto_t *this, public_key_t *key,
				   bio_reader_t *reader, chunk_t data);

	/**
	 * Create a signature of the handshake data using a given private key.
	 *
	 * @param key			private key to use for signature
	 * @param writer		TLS writer to write signature to
	 * @param hashsig		list of TLS1.2 hash/sig algorithms to select from
	 * @return				TRUE if signature create successfully
	 */
	bool (*sign_handshake)(tls_crypto_t *this, private_key_t *key,
						   bio_writer_t *writer, chunk_t hashsig);

	/**
	 * Verify the signature over handshake data using a given public key.
	 *
	 * @param key			public key to verify signature with
	 * @param reader		TLS reader to read signature from
	 * @return				TRUE if signature valid
	 */
	bool (*verify_handshake)(tls_crypto_t *this, public_key_t *key,
							 bio_reader_t *reader);

	/**
	 * Calculate the data of a TLS finished message.
	 *
	 * @param label			ASCII label to use for calculation
	 * @param out			buffer to write finished data to
	 * @return				TRUE if calculation successful
	 */
	bool (*calculate_finished)(tls_crypto_t *this, char *label, char out[12]);

	/**
	 * Derive the master secret, MAC and encryption keys.
	 *
	 * @param premaster		premaster secret
	 * @param session		session identifier to cache master secret
	 * @param id			identity the session is bound to
	 * @param client_random	random data from client hello
	 * @param server_random	random data from server hello
	 * @return				TRUE if secrets derived successfully
	 */
	bool (*derive_secrets)(tls_crypto_t *this, chunk_t premaster,
						   chunk_t session, identification_t *id,
						   chunk_t client_random, chunk_t server_random);

	/**
	 * Try to resume a TLS session, derive key material.
	 *
	 * @param session		session identifier
	 * @param id			identity the session is bound to
	 * @param client_random	random data from client hello
	 * @param server_random	random data from server hello
	 * @return				selected suite
	 */
	tls_cipher_suite_t (*resume_session)(tls_crypto_t *this, chunk_t session,
										 identification_t *id,
										 chunk_t client_random,
										 chunk_t server_random);

	/**
	 * Check if we have a session to resume as a client.
	 *
	 * @param id			server identity to get a session for
	 * @return				allocated session identifier, or chunk_empty
	 */
	chunk_t (*get_session)(tls_crypto_t *this, identification_t *id);

	/**
	 * Change the cipher used at protection layer.
	 *
	 * @param inbound		TRUE to change inbound cipher, FALSE for outbound
	 */
	void (*change_cipher)(tls_crypto_t *this, bool inbound);

	/**
	 * Get the MSK to use in EAP-TLS.
	 *
	 * @return				MSK, points to internal data
	 */
	chunk_t (*get_eap_msk)(tls_crypto_t *this);

	/**
	 * Destroy a tls_crypto_t.
	 */
	void (*destroy)(tls_crypto_t *this);
};

/**
 * Create a tls_crypto instance.
 *
 * @param tls			TLS stack
 * @param cache			TLS session cache
 * @return				TLS crypto helper
 */
tls_crypto_t *tls_crypto_create(tls_t *tls, tls_cache_t *cache);

/**
 * Get a list of all supported TLS cipher suites.
 *
 * @param null			include supported NULL encryption suites
 * @param suites		pointer to allocated suites array, to free(), or NULL
 * @return				number of suites supported
 */
int tls_crypto_get_supported_suites(bool null, tls_cipher_suite_t **suites);

#endif /** TLS_CRYPTO_H_ @}*/
