/*
 * Copyright (C) 2015 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
 *
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

#include <test_suite.h>

#include "../vici_message.h"
#include "../vici_builder.h"

#include <unistd.h>

static char blob[] = {
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
};

typedef struct {
	vici_type_t type;
	char *name;
	chunk_t data;
} endecode_test_t;

static endecode_test_t endecode_test_simple[] = {
	{ VICI_SECTION_START,			"section1", {}							},
	{  VICI_KEY_VALUE,				"key1",		{ "value1", 6 }				},
	{  VICI_KEY_VALUE,				"key2",		{ "value2", 6 }				},
	{ VICI_SECTION_END,				NULL,		{}							},
	{ VICI_END,						NULL,		{}							},
};

static endecode_test_t endecode_test_nested[] = {
	{ VICI_SECTION_START,			"section1", {}							},
	{  VICI_SECTION_START,			"section2", {}							},
	{   VICI_SECTION_START,			"section3", {}							},
	{    VICI_KEY_VALUE,			"key1",		{ "value1", 6 }				},
	{    VICI_SECTION_START,		"section4", {}							},
	{     VICI_KEY_VALUE,			"key2",		{ "value2", 6 }				},
	{    VICI_SECTION_END,			NULL,		{}							},
	{   VICI_SECTION_END,			NULL,		{}							},
	{  VICI_SECTION_END,			NULL,		{}							},
	{  VICI_KEY_VALUE,				"key3",		{ "value3", 6 }				},
	{ VICI_SECTION_END,				NULL,		{}							},
	{ VICI_END,						NULL,		{}							},
};

static endecode_test_t endecode_test_list[] = {
	{ VICI_SECTION_START,			"section1", {}							},
	{  VICI_LIST_START,				"list1",	{}							},
	{   VICI_LIST_ITEM,				NULL,		{ "item1", 5 }				},
	{   VICI_LIST_ITEM,				NULL,		{ "item2", 5 }				},
	{  VICI_LIST_END,				NULL,		{}							},
	{  VICI_KEY_VALUE,				"key1",		{ "value1", 6 }				},
	{ VICI_SECTION_END,				NULL,		{}							},
	{ VICI_END,						NULL,		{}							},
};

static endecode_test_t endecode_test_blobs[] = {
	{ VICI_KEY_VALUE,				"key1",		{ blob, countof(blob) }		},
	{ VICI_SECTION_START,			"section1", {}							},
	{  VICI_LIST_START,				"list1",	{}							},
	{   VICI_LIST_ITEM,				NULL,		{ blob, countof(blob) }		},
	{   VICI_LIST_ITEM,				NULL,		{ blob, countof(blob) }		},
	{  VICI_LIST_END,				NULL,		{}							},
	{  VICI_KEY_VALUE,				"key2",		{ blob, countof(blob) }		},
	{ VICI_SECTION_END,				NULL,		{}							},
	{ VICI_END,						NULL,		{}							},
};

static endecode_test_t *endecode_tests[] = {
	endecode_test_simple,
	endecode_test_nested,
	endecode_test_list,
	endecode_test_blobs,
};

typedef struct {
	enumerator_t public;
	endecode_test_t *next;
} endecode_enum_t;

METHOD(enumerator_t, endecode_enumerate, bool,
	endecode_enum_t *this, va_list args)
{
	vici_type_t *type;
	chunk_t *data;
	char **name;

	VA_ARGS_VGET(args, type, name, data);
	if (this->next)
	{
		*type = this->next->type;
		*name = this->next->name;
		*data = this->next->data;
		if (this->next->type == VICI_END)
		{
			this->next = NULL;
		}
		else
		{
			this->next++;
		}
		return TRUE;
	}
	return FALSE;
}

static enumerator_t *endecode_create_enumerator(endecode_test_t *test)
{
	endecode_enum_t *enumerator;

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _endecode_enumerate,
			.destroy = (void*)free,
		},
		.next = test,
	);

	return &enumerator->public;
}

static void compare_vici(enumerator_t *parse, enumerator_t *tmpl)
{
	vici_type_t type, ttype;
	char *name, *tname;
	chunk_t data, tdata;;

	while (TRUE)
	{
		ck_assert(parse->enumerate(parse, &type, &name, &data));
		ck_assert(tmpl->enumerate(tmpl, &ttype, &tname, &tdata));
		ck_assert_int_eq(type, ttype);
		switch (type)
		{
			case VICI_END:
				return;
			case VICI_SECTION_START:
			case VICI_LIST_START:
				ck_assert(streq(name, tname));
				break;
			case VICI_LIST_ITEM:
				ck_assert(chunk_equals(data, tdata));
				break;
			case VICI_KEY_VALUE:
				ck_assert(streq(name, tname));
				ck_assert(chunk_equals(data, tdata));
				break;
			case VICI_SECTION_END:
			case VICI_LIST_END:
				break;
			default:
				ck_assert(FALSE);
				break;
		}
	}
}

START_TEST(test_endecode)
{
	enumerator_t *parse, *tmpl;
	vici_message_t *m;
	chunk_t data;

	tmpl = endecode_create_enumerator(endecode_tests[_i]);
	m = vici_message_create_from_enumerator(tmpl);
	ck_assert(m);
	data = chunk_clone(m->get_encoding(m));
	tmpl = endecode_create_enumerator(endecode_tests[_i]);
	parse = m->create_enumerator(m);
	ck_assert(parse);
	compare_vici(parse, tmpl);
	tmpl->destroy(tmpl);
	parse->destroy(parse);
	m->destroy(m);

	m = vici_message_create_from_data(data, TRUE);
	ck_assert(m);
	tmpl = endecode_create_enumerator(endecode_tests[_i]);
	parse = m->create_enumerator(m);
	ck_assert(parse);
	compare_vici(parse, tmpl);
	tmpl->destroy(tmpl);
	parse->destroy(parse);
	m->destroy(m);
}
END_TEST

START_TEST(test_vararg)
{
	enumerator_t *parse, *tmpl;
	vici_message_t *m;

	m = vici_message_create_from_args(
		VICI_SECTION_START, "section1",
		 VICI_LIST_START, "list1",
		  VICI_LIST_ITEM, chunk_from_str("item1"),
		  VICI_LIST_ITEM, chunk_from_str("item2"),
		 VICI_LIST_END,
		 VICI_KEY_VALUE, "key1", chunk_from_str("value1"),
		 VICI_SECTION_END,
		VICI_END);
	ck_assert(m);
	tmpl = endecode_create_enumerator(endecode_test_list);
	parse = m->create_enumerator(m);
	ck_assert(parse);

	compare_vici(parse, tmpl);

	m->destroy(m);
	tmpl->destroy(tmpl);
	parse->destroy(parse);
}
END_TEST

START_TEST(test_builder)
{
	enumerator_t *parse, *tmpl;
	vici_message_t *m;
	vici_builder_t *b;

	b = vici_builder_create();
	b->add(b, VICI_SECTION_START, "section1");
	b->add(b,  VICI_LIST_START, "list1");
	b->add(b,   VICI_LIST_ITEM, chunk_from_str("item1"));
	b->add(b,   VICI_LIST_ITEM, chunk_from_str("item2"));
	b->add(b,  VICI_LIST_END);
	b->add(b,  VICI_KEY_VALUE, "key1", chunk_from_str("value1"));
	b->add(b, VICI_SECTION_END);
	m = b->finalize(b);
	ck_assert(m);
	tmpl = endecode_create_enumerator(endecode_test_list);
	parse = m->create_enumerator(m);
	ck_assert(parse);

	compare_vici(parse, tmpl);

	m->destroy(m);
	tmpl->destroy(tmpl);
	parse->destroy(parse);
}
END_TEST

START_TEST(test_builder_fmt)
{
	enumerator_t *parse, *tmpl;
	vici_message_t *m;
	vici_builder_t *b;

	b = vici_builder_create();
	b->begin_section(b, "section1");
	b->begin_list(b, "list1");
	b->add_li(b, "item%u", 1);
	b->add_li(b, "%s%u", "item", 2);
	b->end_list(b);
	b->add_kv(b, "key1", "value%u", 1);
	b->end_section(b);
	m = b->finalize(b);
	ck_assert(m);
	tmpl = endecode_create_enumerator(endecode_test_list);
	parse = m->create_enumerator(m);
	ck_assert(parse);

	compare_vici(parse, tmpl);

	m->destroy(m);
	tmpl->destroy(tmpl);
	parse->destroy(parse);
}
END_TEST

static vici_message_t* build_getter_msg()
{
	return vici_message_create_from_args(
			VICI_KEY_VALUE, "key1", chunk_from_str("1"),
			VICI_SECTION_START, "section1",
			 VICI_KEY_VALUE, "key2", chunk_from_str("0xFF"),
			 VICI_SECTION_START, "section2",
			  VICI_KEY_VALUE, "key3", chunk_from_str("-1"),
			 VICI_SECTION_END,
			 VICI_KEY_VALUE, "key4", chunk_from_str("asdf"),
			VICI_SECTION_END,
			VICI_KEY_VALUE, "key5", chunk_from_str(""),
			VICI_END);
}

START_TEST(test_get_str)
{
	vici_message_t *m;

	m = build_getter_msg();

	ck_assert_str_eq(m->get_str(m, "def", "key1"), "1");
	ck_assert_str_eq(m->get_str(m, "def", "section1.key2"), "0xFF");
	ck_assert_str_eq(m->get_str(m, "def", "section%d.section2.key3", 1), "-1");
	ck_assert_str_eq(m->get_str(m, "def", "section1.key4"), "asdf");
	ck_assert_str_eq(m->get_str(m, "def", "key5"), "");
	ck_assert_str_eq(m->get_str(m, "no", "nonexistent"), "no");
	ck_assert_str_eq(m->get_str(m, "no", "n.o.n.e.x.i.s.t.e.n.t"), "no");

	m->destroy(m);
}
END_TEST

START_TEST(test_get_int)
{
	vici_message_t *m;

	m = build_getter_msg();

	ck_assert_int_eq(m->get_int(m, 2, "key1"), 1);
	ck_assert_int_eq(m->get_int(m, 2, "section1.key2"), 0xFF);
	ck_assert_int_eq(m->get_int(m, 2, "section1.section2.key3"), -1);
	ck_assert_int_eq(m->get_int(m, 2, "section1.key4"), 2);
	ck_assert_int_eq(m->get_int(m, 2, "key5"), 2);
	ck_assert_int_eq(m->get_int(m, 2, "nonexistent"), 2);
	ck_assert_int_eq(m->get_int(m, 2, "n.o.n.e.x.i.s.t.e.n.t"), 2);

	m->destroy(m);
}
END_TEST

START_TEST(test_get_bool)
{
	vici_message_t *m;

	m = build_getter_msg();

	ck_assert(m->get_bool(m, TRUE, "key1"));
	ck_assert(m->get_bool(m, FALSE, "key1"));

	ck_assert(m->get_bool(m, TRUE, "section1.key2"));
	ck_assert(m->get_bool(m, TRUE, "section1.section2.key3"));
	ck_assert(m->get_bool(m, TRUE, "section1.key4"));
	ck_assert(m->get_bool(m, TRUE, "key5"));
	ck_assert(m->get_bool(m, TRUE, "nonexistent"));
	ck_assert(m->get_bool(m, TRUE, "n.o.n.e.x.i.s.t.e.n.t"));

	ck_assert(!m->get_bool(m, FALSE, "section1.key2"));
	ck_assert(!m->get_bool(m, FALSE, "section1.section2.key3"));
	ck_assert(!m->get_bool(m, FALSE, "section1.key4"));
	ck_assert(!m->get_bool(m, FALSE, "key5"));
	ck_assert(!m->get_bool(m, FALSE, "nonexistent"));
	ck_assert(!m->get_bool(m, FALSE, "n.o.n.e.x.i.s.t.e.n.t"));

	m->destroy(m);
}
END_TEST

START_TEST(test_get_value)
{
	vici_message_t *m;
	chunk_t d = chunk_from_chars('d','e','f');

	m = build_getter_msg();

	ck_assert_chunk_eq(m->get_value(m, d, "key1"), chunk_from_str("1"));
	ck_assert_chunk_eq(m->get_value(m, d, "section1.key2"), chunk_from_str("0xFF"));
	ck_assert_chunk_eq(m->get_value(m, d, "section1.section2.key3"), chunk_from_str("-1"));
	ck_assert_chunk_eq(m->get_value(m, d, "section1.key4"), chunk_from_str("asdf"));
	ck_assert_chunk_eq(m->get_value(m, d, "key5"), chunk_empty);
	ck_assert_chunk_eq(m->get_value(m, d, "nonexistent"), d);
	ck_assert_chunk_eq(m->get_value(m, d, "n.o.n.e.x.i.s.t.e.n.t"), d);

	m->destroy(m);
}
END_TEST

Suite *message_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("vici message");

	tc = tcase_create("enumerator en/decode");
	tcase_add_loop_test(tc, test_endecode, 0, countof(endecode_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("vararg encode");
	tcase_add_test(tc, test_vararg);
	suite_add_tcase(s, tc);

	tc = tcase_create("builder encode");
	tcase_add_test(tc, test_builder);
	suite_add_tcase(s, tc);

	tc = tcase_create("builder format encode");
	tcase_add_test(tc, test_builder_fmt);
	suite_add_tcase(s, tc);

	tc = tcase_create("convenience getters");
	tcase_add_test(tc, test_get_str);
	tcase_add_test(tc, test_get_int);
	tcase_add_test(tc, test_get_bool);
	tcase_add_test(tc, test_get_value);
	suite_add_tcase(s, tc);

	return s;
}
