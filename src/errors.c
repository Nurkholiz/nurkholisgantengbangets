/*
 * Copyright (C) 2009-2011 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "errors.h"
#include "git2/thread-utils.h" /* for GIT_TLS */
#include "thread-utils.h" /* for GIT_TLS */
#include "posix.h"

#include <stdarg.h>

static GIT_TLS git_error *git_errno;

static struct {
	int num;
	const char *str;
} error_codes[] = {
	{GIT_ERROR, "Unspecified error"},
	{GIT_ENOTOID, "Input was not a properly formatted Git object id."},
	{GIT_ENOTFOUND, "Object does not exist in the scope searched."},
	{GIT_ENOMEM, "Not enough space available."},
	{GIT_EOSERR, "Consult the OS error information."},
	{GIT_EOBJTYPE, "The specified object is of invalid type"},
	{GIT_EOBJCORRUPTED, "The specified object has its data corrupted"},
	{GIT_ENOTAREPO, "The specified repository is invalid"},
	{GIT_EINVALIDTYPE, "The object or config variable type is invalid or doesn't match"},
	{GIT_EMISSINGOBJDATA, "The object cannot be written that because it's missing internal data"},
	{GIT_EPACKCORRUPTED, "The packfile for the ODB is corrupted"},
	{GIT_EFLOCKFAIL, "Failed to adquire or release a file lock"},
	{GIT_EZLIB, "The Z library failed to inflate/deflate an object's data"},
	{GIT_EBUSY, "The queried object is currently busy"},
	{GIT_EINVALIDPATH, "The path is invalid"},
	{GIT_EBAREINDEX, "The index file is not backed up by an existing repository"},
	{GIT_EINVALIDREFNAME, "The name of the reference is not valid"},
	{GIT_EREFCORRUPTED, "The specified reference has its data corrupted"},
	{GIT_ETOONESTEDSYMREF, "The specified symbolic reference is too deeply nested"},
	{GIT_EPACKEDREFSCORRUPTED, "The pack-refs file is either corrupted of its format is not currently supported"},
	{GIT_EINVALIDPATH, "The path is invalid" },
	{GIT_EREVWALKOVER, "The revision walker is empty; there are no more commits left to iterate"},
	{GIT_EINVALIDREFSTATE, "The state of the reference is not valid"},
	{GIT_ENOTIMPLEMENTED, "This feature has not been implemented yet"},
	{GIT_EEXISTS, "A reference with this name already exists"},
	{GIT_EOVERFLOW, "The given integer literal is too large to be parsed"},
	{GIT_ENOTNUM, "The given literal is not a valid number"},
	{GIT_EAMBIGUOUSOIDPREFIX, "The given oid prefix is ambiguous"},
};

const char *git_strerror(int num)
{
	size_t i;

	if (num == GIT_EOSERR)
		return strerror(errno);
	for (i = 0; i < ARRAY_SIZE(error_codes); i++)
		if (num == error_codes[i].num)
			return error_codes[i].str;

	return "Unknown error";
}

static git_error git_error_OOM = {
	GIT_ENOMEM,
	"out of memory",
	NULL,
	NULL,
	-1
};

git_error * git_error_oom(void)
{
	 /*
	  * Throw an out-of-memory error:
	  * what we return is actually a static pointer, because on
	  * oom situations we cannot afford to allocate a new error
	  * object.
	  *
	  * The `git_error_free` function will take care of not
	  * freeing this special type of error.
	  *
	  */
	return &git_error_OOM;
}

git_error * git_error_createf(const char *file, unsigned int line, int code,
			      const char *fmt, ...)
{
	git_error *err;
	va_list ap;
	size_t size;

	err = git__malloc(sizeof(git_error));
	if (err == NULL)
		return git_error_oom();

	memset(err, 0x0, sizeof(git_error));

	va_start(ap, fmt);
	size = p_vsnprintf(err->msg, 0, fmt, ap);
	va_end(ap);

	size++;

	err->msg = git__malloc(size);
	if (err->msg == NULL) {
		free(err);
		return git_error_oom();
	}

	va_start(ap, fmt);
	size = p_vsnprintf(err->msg, size, fmt, ap);
	va_end(ap);

	err->code  = code;
	err->child = git_errno;
	err->file  = file;
	err->line  = line;

	git_errno = err;

	return err;
}

git_error * git_error__quick_wrap(const char *file, int line,
								 git_error_code error, const char *msg)
{
	if (error == GIT_SUCCESS)
		return GIT_SUCCESS;

	return git_error_createf(file, line, error, "%s", msg);
}

void git_error_free(git_error *err)
{
	if (err == NULL)
		return;

	if (err->child)
		git_error_free(err->child);

	if (err->msg)
		free(err->msg);

	free(err);
}

void git_clearerror(void)
{
	git_error_free(git_errno);
	git_errno = NULL;
}

const char *git_lasterror(void)
{
	return git_errno == NULL ? NULL : git_errno->msg;
}

void git_error_print_stack(void)
{
	git_error *error;

	for (error = git_errno; error; error = error->child)
		fprintf(stderr, "%s:%u %s\n", error->file, error->line, error->msg);
}
