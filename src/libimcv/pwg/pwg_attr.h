/*
 * Copyright (C) 2015 Andreas Steffen
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

/**
 * @defgroup pwg_attr pwg_attr
 * @{ @ingroup libimcv
 */

#ifndef PWG_ATTR_H_
#define PWG_ATTR_H_

#include <pa_tnc/pa_tnc_attr.h>
#include <library.h>

typedef enum pwg_attr_t pwg_attr_t;

/**
 * PWG HCD IF-M Attributes (Hardcopy Device Health Assessment TNC Binding)
 */
enum pwg_attr_t {
	PWG_HCD_ATTRS_NATURAL_LANG =          0xFF, /*   1 */
	PWG_HCD_MACHINE_TYPE_MODEL =          0xFF, /*   2 */
	PWG_HCD_VENDOR_NAME =                 0xFF, /*   3 */
	PWG_HCD_VENDOR_SMI_CODE =             0xFF, /*   4 */
	PWG_HCD_DEFAULT_PWD_ENABLED =         0xFF, /*  20 */
	PWG_HCD_FIREWALL_SETTING =            0xFF, /*  21 */
	PWG_HCD_FORWARDING_ENABLED =          0xFF, /*  22 */
	PWG_HCD_PSTN_FAX_ENABLED =            0xFF, /*  40 */
	PWG_HCD_TIME_SOURCE =                 0xFF, /*  50 ??? */
	PWG_HCD_FIRMWARE_NAME =               0xFF, /*  60 */
	PWG_HCD_FIRMWARE_PATCHES =            0xFF, /*  61 */
	PWG_HCD_FIRMWARE_STRING_VERSION =     0xFF, /*  62 */
	PWG_HCD_FIRMWARE_VERSION =            0xFF, /*  63 */
	PWG_HCD_RESIDENT_APP_NAME =           0xFF, /*  80 */
	PWG_HCD_RESIDENT_APP_PATCHES =        0xFF, /*  81 */
	PWG_HCD_RESIDENT_APP_STRING_VERSION = 0xFF, /*  82 */
	PWG_HCD_RESIDENT_APP_VERSION =        0xFF, /*  83 */
	PWG_HCD_USER_APP_NAME =               0xFF, /* 100 */
	PWG_HCD_USER_APP_PATCHES =            0xFF, /* 101 */
	PWG_HCD_USER_APP_STRING_VERSION =     0xFF, /* 102 */
	PWG_HCD_USER_APP_VERSION =            0xFF, /* 103 */
	PWG_HCD_USER_APP_ENABLED =            0xFF, /* 104 */
	PWG_HCD_USER_APP_PERSIST_ENABLED =    0xFF, /* 105 */
	PWG_HCD_CERTIFICATION_STATE =         0xFF, /* 200 */
	PWG_HCD_CONFIGURATION_STATE =         0xFF, /* 201 */
};

/**
 * enum name for pwg_attr_t.
 */
extern enum_name_t *pwg_attr_names;

/**
 * Create a TCG PA-TNC attribute from data
 *
 * @param type				attribute type
 * @param length			attribute length
 * @param value				attribute value or segment
 */
pa_tnc_attr_t* pwg_attr_create_from_data(uint32_t type, size_t length,
										 chunk_t value);

#endif /** PWG_ATTR_H_ @}*/
