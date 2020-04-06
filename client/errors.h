/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_client_errors_h__
#define INCLUDE_client_errors_h__

/*
 * Set the error message.  These will proxy directly to the libgit2 error
 * function so that client library consumers have a single place for all
 * libgit2 errors, whether from the core library or the client library.
 */
extern void git_error_set(int error_class, const char *fmt, ...) GIT_FORMAT_PRINTF(2, 3);
extern void git_error_vset(int error_class, const char *fmt, va_list ap);

#endif
