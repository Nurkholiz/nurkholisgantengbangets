/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git2.h"
#include "common.h"
#include "buffer.h"
#include "auth.h"
#include "auth_ntlm.h"

#ifdef GIT_NTLM

#include "ntlm.h"

typedef struct {
	git_http_auth_context parent;
	ntlm_client *ntlm;
	char *challenge;
} http_auth_ntlm_context;

static int ntlm_set_challenge(
	git_http_auth_context *c,
	const char *challenge)
{
	http_auth_ntlm_context *ctx = (http_auth_ntlm_context *)c;

	assert(ctx && challenge);

	git__free(ctx->challenge);

	ctx->challenge = git__strdup(challenge);
	GITERR_CHECK_ALLOC(ctx->challenge);

	printf("ok, challenge is: %s\n", ctx->challenge);

	return 0;
}

static int ntlm_set_credentials(http_auth_ntlm_context *ctx, git_cred *_cred)
{
	git_cred_userpass_plaintext *cred;
	const char *sep;
	const char *domain = NULL, *username;
	char *parsed_domain = NULL, *parsed_username = NULL;
	int error = 0;

	assert(_cred->credtype == GIT_CREDTYPE_USERPASS_PLAINTEXT);
	cred = (git_cred_userpass_plaintext *)_cred;

	username = cred->username;

	if ((sep = strchr(username, '\\')) != NULL) {
		parsed_domain = strndup(username, (sep - username));
		GITERR_CHECK_ALLOC(parsed_domain);

		parsed_username = strdup(sep + 1);
		GITERR_CHECK_ALLOC(parsed_username);

		domain = parsed_domain;
		username = parsed_username;
	}

	if (ntlm_client_set_credentials(ctx->ntlm,
	    username, domain, cred->password) < 0) {
		giterr_set(GITERR_NET, "could not set credentials: %s",
		    ntlm_client_errmsg(ctx->ntlm));
		error = -1;
		goto done;
	}

	printf("woo, my ntlm creds are %s\\%s / %s\n", domain ? domain : "(none)", username, cred->password);

done:
	git__free(parsed_domain);
	git__free(parsed_username);
	return error;
}

static int ntlm_next_token(
	git_buf *buf,
	git_http_auth_context *c,
	git_cred *cred)
{
	http_auth_ntlm_context *ctx = (http_auth_ntlm_context *)c;
	git_buf input_buf = GIT_BUF_INIT;
	const unsigned char *msg;
	size_t challenge_len, msg_len;
	int error = -1;

	printf("next token...\n");

	assert(buf && ctx && ctx->ntlm);

	challenge_len = ctx->challenge ? strlen(ctx->challenge) : 0;

	if (cred && (error = ntlm_set_credentials(ctx, cred)) < 0)
		goto done;

	if (challenge_len < 4) {
		giterr_set(GITERR_NET, "no ntlm challenge sent from server");
		goto done;
	} else if (challenge_len == 4) {
		if (memcmp(ctx->challenge, "NTLM", 4) != 0) {
			giterr_set(GITERR_NET, "server did not request NTLM");
			goto done;
		}

		if (ntlm_client_negotiate(&msg, &msg_len, ctx->ntlm) != 0) {
			giterr_set(GITERR_NET, "ntlm authentication failed: %s",
				ntlm_client_errmsg(ctx->ntlm));
			goto done;
		}
	} else {
		if (memcmp(ctx->challenge, "NTLM ", 5) != 0) {
			giterr_set(GITERR_NET, "challenge from server was not NTLM");
			goto done;
		}

		if (git_buf_decode_base64(&input_buf,
		    ctx->challenge + 5, challenge_len - 5) < 0) {
			giterr_set(GITERR_NET, "invalid NTLM challenge from server");
			goto done;
		}

		if (ntlm_client_set_challenge(ctx->ntlm,
		    (const unsigned char *)input_buf.ptr, input_buf.size) != 0) {
			giterr_set(GITERR_NET, "ntlm challenge failed: %s",
				ntlm_client_errmsg(ctx->ntlm));
			goto done;
		}

		if (ntlm_client_response(&msg, &msg_len, ctx->ntlm) != 0) {
			giterr_set(GITERR_NET, "ntlm authentication failed: %s",
				ntlm_client_errmsg(ctx->ntlm));
			goto done;
		}
	}

	git_buf_puts(buf, "Authorization: NTLM ");
	git_buf_encode_base64(buf, (const char *)msg, msg_len);
	git_buf_puts(buf, "\r\n");

	printf("RESPONSE: %s\n", buf->ptr);

	if (git_buf_oom(buf))
		goto done;

	error = 0;

done:
	return error;
}

static void ntlm_context_free(git_http_auth_context *c)
{
	http_auth_ntlm_context *ctx = (http_auth_ntlm_context *)c;

	ntlm_client_free(ctx->ntlm);
	git__free(ctx->challenge);
	git__free(ctx);
}

static int ntlm_init_context(
	http_auth_ntlm_context *ctx,
	const gitno_connection_data *connection_data)
{
	if ((ctx->ntlm = ntlm_client_init(NTLM_CLIENT_DEFAULTS)) == NULL) {
		giterr_set_oom();
		return -1;
	}

	if (ntlm_client_set_target(ctx->ntlm, connection_data->host) < 0) {
		giterr_set(GITERR_NET, "failed to initialize NTLM: %s",
		    ntlm_client_errmsg(ctx->ntlm));
		return -1;
	}

	return 0;
}

int git_http_auth_ntlm(
	git_http_auth_context **out,
	const gitno_connection_data *connection_data)
{
	http_auth_ntlm_context *ctx;

	GIT_UNUSED(connection_data);

	*out = NULL;

	ctx = git__calloc(1, sizeof(http_auth_ntlm_context));
	GITERR_CHECK_ALLOC(ctx);

	if (ntlm_init_context(ctx, connection_data) < 0) {
		git__free(ctx);
		return -1;
	}

	printf("--------------------------------------------------------\n");
	printf("starting ntlm?\n");

	ctx->parent.type = GIT_AUTHTYPE_NTLM;
	ctx->parent.credtypes = GIT_CREDTYPE_USERPASS_PLAINTEXT;
	ctx->parent.set_challenge = ntlm_set_challenge;
	ctx->parent.next_token = ntlm_next_token;
	ctx->parent.free = ntlm_context_free;

	*out = (git_http_auth_context *)ctx;

	return 0;
}

#endif /* GIT_NTLM */
