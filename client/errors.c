/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

void git_error_vset(int error_class, const char *fmt, va_list ap)
{
	git_buf buf = GIT_BUF_INIT;

	if (fmt) {
		git_buf_vprintf(&buf, fmt, ap);

		if (error_class == GIT_ERROR_OS)
			git_buf_PUTS(&buf, ": ");
	}

	if (error_class == GIT_ERROR_OS)
		git__system_errmsg(&buf);

	if (!git_buf_oom(&buf))
		git_error_set_str(error_class, buf.ptr);

	git_buf_dispose(&buf);
}

void git_error_set(int error_class, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	git_error_vset(error_class, fmt, ap);
	va_end(ap);
}
