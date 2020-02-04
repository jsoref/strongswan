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

#include <unistd.h>
#include <time.h>

#define HTTP_SUCCESS(status) ((status) >= 200 && (status) < 300)

/**
 * HTTP test definition
 */
typedef struct {
	/* HTTP Method */
	char *meth;
	/* HTTP 1.x minor version */
	int minor;
	/* host to connect to */
	char *host;
	/* HTTP service port */
	int port;
	/* path on host to fetch from */
	char *path;
	/* request Content-Type, if any */
	char *type;
	/* request data, if any */
	void *req;
	/* length of request data */
	int req_len;
	/* response data, if any */
	void *res;
	/* length of response data */
	int res_len;
	/* status code, defaults to 200 */
	u_int code;
} test_service_t;

static char large[] = {
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

static bool servicing(void *data, stream_t *stream)
{
	test_service_t *test = (test_service_t*)data;
	char buf[1024], hdr[256], *start, *end = NULL, *body = NULL, *type = NULL;
	struct tm tm;
	time_t t;
	ssize_t len, tot = 0;
	int nr = 0;

	start = buf;

	/* parse method and headers */
	while (end != start)
	{
		len = stream->read(stream, buf + tot, sizeof(buf) - tot, TRUE);
		ck_assert(len > 0);
		tot += len;

		while (TRUE)
		{
			end = memchr(start, '\n', tot);
			if (!end)
			{
				break;
			}
			*end = '\0';
			ck_assert(end > buf);
			ck_assert(*(--end) == '\r');
			*end = '\0';
			if (end == start)
			{
				body = end + strlen("\r\n");
				break;
			}
			switch (nr++)
			{
				case 0:
					snprintf(hdr, sizeof(hdr), "%s %s HTTP/1.%u",
							 test->meth, test->path, test->minor);
					ck_assert_str_eq(hdr, start);
					break;
				default:
					if (strcasepfx(start, "Content-Length: "))
					{
						ck_assert_int_eq(
							atoi(start + strlen("Content-Length: ")),
							test->req_len);
					}
					if (strcasepfx(start, "Content-Type: "))
					{
						type = start + strlen("Content-Type: ");
					}
					break;
			}
			start = end + strlen("\r\n");
		}
	}

	if (test->type)
	{
		ck_assert(type);
		ck_assert_str_eq(type, test->type);
	}

	/* request body */
	if (test->req_len)
	{
		ck_assert(stream->read_all(stream, buf + tot,
								   test->req_len - (tot - (body - buf))));
		ck_assert(memeq(body, test->req, test->req_len));
	}

	if (!test->code)
	{
		test->code = 200;
	}

	/* response headers */
	snprintf(buf, sizeof(buf), "HTTP/1.%u %u OK\r\n", test->minor, test->code);
	ck_assert(stream->write_all(stream, buf, strlen(buf)));

	/* if the response code indicates an error the following write operations
	 * might fail because the client already terminated the TCP connection */
#define may_fail(test, op) ck_assert(op || !HTTP_SUCCESS(test->code))

	t = time(NULL);
	gmtime_r(&t, &tm);
	strftime(buf, sizeof(buf), "%a, %d %b %Y %T %z", &tm);
	may_fail(test, stream->write_all(stream, buf, strlen(buf)));
	snprintf(buf, sizeof(buf), "Server: strongSwan unit test\r\n");
	may_fail(test, stream->write_all(stream, buf, strlen(buf)));

	/* rest of response headers */
	snprintf(buf, sizeof(buf), "Content-Type: text/plain\r\n");
	may_fail(test, stream->write_all(stream, buf, strlen(buf)));
	snprintf(buf, sizeof(buf), "Content-Length: %u\r\n", test->res_len);
	may_fail(test, stream->write_all(stream, buf, strlen(buf)));
	snprintf(buf, sizeof(buf), "Connection: close\r\n");
	may_fail(test, stream->write_all(stream, buf, strlen(buf)));
	snprintf(buf, sizeof(buf), "\r\n");
	may_fail(test, stream->write_all(stream, buf, strlen(buf)));

	/* response body */
	may_fail(test, stream->write_all(stream, test->res, test->res_len));
	return FALSE;
}

static test_service_t gtests[] = {
	{ "GET", 1, "127.0.0.1", 6543, "/a/test/?b=c", NULL,
	  NULL, 0, "\x12\x34", 2, 0 },
	{ "GET", 0, "localhost", 6543, "/", NULL,
	  NULL, 0, NULL, 0, 0 },
	{ "GET", 0, "127.0.0.1", 6543, "/largefile", NULL,
	  NULL, 0, large, sizeof(large), 0 },
	{ "GET", 1, "[::1]", 6543, "/ipv6-url", NULL,
	  NULL, 0, "\x00\r\n\r\x00testdatablabla", 20, 0 },
};

START_TEST(test_get)
{
	stream_service_t *service;
	status_t status;
	chunk_t data, expected;
	char uri[256];

	lib->processor->set_threads(lib->processor, 8);

	snprintf(uri, sizeof(uri), "tcp://%s:%u", gtests[_i].host, gtests[_i].port);
	service = lib->streams->create_service(lib->streams, uri, 1);
	ck_assert(service != NULL);
	service->on_accept(service, servicing, &gtests[_i], JOB_PRIO_HIGH, 0);

	snprintf(uri, sizeof(uri), "http://%s:%u%s",
			 gtests[_i].host, gtests[_i].port, gtests[_i].path);
	status = lib->fetcher->fetch(lib->fetcher, uri, &data,
			!gtests[_i].minor ? FETCH_HTTP_VERSION_1_0 : FETCH_END,
			FETCH_END);
	ck_assert_int_eq(status, SUCCESS);
	expected = chunk_create(gtests[_i].res, gtests[_i].res_len);
	ck_assert_msg(chunk_compare(expected, data) == 0,
				  "exp %B\ngot %B\n", &expected, &data);
	free(data.ptr);

	service->destroy(service);
}
END_TEST


static test_service_t ptests[] = {
	{ "POST", 1, "127.0.0.1", 6543, "/a/test/?b=c", "application/binary",
	  "\x23\x45", 2, "\x12\x34", 2, 0 },
	{ "POST", 0, "localhost", 6543, "/largefile", "application/x-large",
	  large, sizeof(large), large, sizeof(large), 0 },
	{ "POST", 1, "[::1]", 6543, "/ipv6-url", "text/plain",
	  "\x00\r\n\r\x00testdatablabla", 20, "\x00\r\n\r\x00testdatablabla", 20, 0 },
};

START_TEST(test_post)
{
	stream_service_t *service;
	status_t status;
	chunk_t data, expected;
	char uri[256];

	lib->processor->set_threads(lib->processor, 8);

	snprintf(uri, sizeof(uri), "tcp://%s:%u", ptests[_i].host, ptests[_i].port);
	service = lib->streams->create_service(lib->streams, uri, 1);
	ck_assert(service != NULL);
	service->on_accept(service, servicing, &ptests[_i], JOB_PRIO_HIGH, 0);

	snprintf(uri, sizeof(uri), "http://%s:%u%s",
			 ptests[_i].host, ptests[_i].port, ptests[_i].path);
	status = lib->fetcher->fetch(lib->fetcher, uri, &data,
					FETCH_REQUEST_TYPE, ptests[_i].type,
					FETCH_REQUEST_DATA,
						chunk_create(ptests[_i].req, ptests[_i].req_len),
					!ptests[_i].minor ? FETCH_HTTP_VERSION_1_0 : FETCH_END,
					FETCH_END);
	ck_assert_int_eq(status, SUCCESS);
	expected = chunk_create(ptests[_i].res, ptests[_i].res_len);
	ck_assert_msg(chunk_compare(expected, data) == 0,
				  "exp %B\ngot %B\n", &expected, &data);
	free(data.ptr);

	service->destroy(service);
}
END_TEST


static test_service_t rtests[] = {
	{ "GET", 1, "localhost", 6544, "/", NULL, NULL, 0, NULL, 0, 200 },
	{ "GET", 1, "localhost", 6544, "/", NULL, NULL, 0, NULL, 0, 204 },
	{ "GET", 1, "localhost", 6544, "/", NULL, NULL, 0, NULL, 0, 400 },
	{ "GET", 1, "localhost", 6544, "/", NULL, NULL, 0, NULL, 0, 404 },
	{ "GET", 1, "localhost", 6544, "/", NULL, NULL, 0, NULL, 0, 500 },
};

START_TEST(test_response_code)
{
	stream_service_t *service;
	status_t status;
	chunk_t data = chunk_empty;
	char uri[256];
	u_int code;

	lib->processor->set_threads(lib->processor, 8);

	snprintf(uri, sizeof(uri), "tcp://%s:%u", rtests[_i].host, rtests[_i].port);
	service = lib->streams->create_service(lib->streams, uri, 1);
	ck_assert(service != NULL);
	service->on_accept(service, servicing, &rtests[_i], JOB_PRIO_HIGH, 0);

	snprintf(uri, sizeof(uri), "http://%s:%u%s",
			 rtests[_i].host, rtests[_i].port, rtests[_i].path);
	status = lib->fetcher->fetch(lib->fetcher, uri, &data,
								 FETCH_RESPONSE_CODE, &code, FETCH_END);
	ck_assert_int_eq(status, HTTP_SUCCESS(rtests[_i].code) ? SUCCESS : FAILED);
	ck_assert_int_eq(code, rtests[_i].code);
	free(data.ptr);

	service->destroy(service);
}
END_TEST

Suite *fetch_http_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("http fetcher");

	tc = tcase_create("GET");
	tcase_add_loop_test(tc, test_get, 0, countof(gtests));
	suite_add_tcase(s, tc);

	tc = tcase_create("POST");
	tcase_add_loop_test(tc, test_post, 0, countof(ptests));
	suite_add_tcase(s, tc);

	tc = tcase_create("response code");
	tcase_add_loop_test(tc, test_response_code, 0, countof(rtests));
	suite_add_tcase(s, tc);

	return s;
}
