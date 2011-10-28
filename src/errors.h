#ifndef INCLUDE_errors_h__
#define INCLUDE_errors_h__

#include "git2/common.h"

/* Deprecated - please use the more advanced functions below. */
#define git__throw(error, ...) \
	(git_error_createf(__FILE__, __LINE__, error, __VA_ARGS__), error)

#define git__rethrow(error, ...) \
	(git_error_createf(__FILE__, __LINE__, error, __VA_ARGS__), error)

/*
 * This implementation is loosely based on subversion's error
 * handling.
 */

git_error * git_error_createf(const char *file, unsigned int line, int code,
			      const char *msg, ...) GIT_FORMAT_PRINTF(4, 5);

git_error * git_error_quick_wrap(const char *file, int line,
				 git_error_code error, const char *msg);

/*
 * Wrap an error with a message. All git_error values are assigned with
 * child's fields.
 */
#define git_error_quick_wrap(error, message)				\
	git_error_quick_wrap(__FILE__, __LINE__, error, message)

/*
 * Use this function to wrap functions like
 *
 *	git_error * foo(void)
 *	{
 *		return git_error_trace(bar());
 *	}
 *
 * Otherwise the call of foo() wouldn't be visible in the trace.
 *
 */
#define git_error_trace(error) \
	git_error_quick_wrap(error, "traced error");

/* Throw an out-of-memory error */
extern git_error * git_error_oom(void);

#endif /* INCLUDE_errors_h__ */
