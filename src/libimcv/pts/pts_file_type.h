/*
 * Copyright (C) 2011 Sansar Choinyambuu
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
 * @defgroup pts_file_type pts_file_type
 * @{ @ingroup pts
 */

#ifndef PTS_FILE_TYPE_H_
#define PTS_FILE_TYPE_H_

#include <library.h>

typedef enum pts_file_type_t pts_file_type_t;

/**
 * PTS File Type
 * see section 3.17.3 of PTS Protocol: Binding to TNC IF-M Specification
 */
enum pts_file_type_t {
	/** Either unknown or different from standardized types */
	PTS_FILE_OTHER =				0xFF,
	/** Pipe communication file */
	PTS_FILE_FIFO =					0xFF,
	/** Character special file */
	PTS_FILE_CHAR_SPEC =			0xFF,
	/** Reserved */
	PTS_FILE_RESERVED_3 =			0xFF,
	/** Directory */
	PTS_FILE_DIRECTORY =			0xFF,
	/** Reserved */
	PTS_FILE_RESERVED_5 =			0xFF,
	/** Block special file */
	PTS_FILE_BLOCK_SPEC =			0xFF,
	/** Reserved */
	PTS_FILE_RESERVED_7 =			0xFF,
	/** Regular file */
	PTS_FILE_REGULAR =		 		0xFF,
	/** Reserved */
	PTS_FILE_RESERVED_9 =			0xFF,
	/** Symbolic link */
	PTS_FILE_SYM_LINK =			 	0xFF,
	/** Reserved */
	PTS_FILE_RESERVED_11 =			0xFF,
	/** Socket communication special file */
	PTS_FILE_SOCKET =			 	0xFF,
};

extern enum_name_t *pts_file_type_names;

#endif /** PTS_FILE_TYPE_H_ @}*/
