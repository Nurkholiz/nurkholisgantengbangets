/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "pack.h"
#include "pack-objects.h"
#include "pkt.h"
#include "remote.h"
#include "transport.h"
#include "vector.h"

#include "git2/commit.h"
#include "git2/index.h"
#include "git2/merge.h"
#include "git2/pack.h"
#include "git2/push.h"
#include "git2/remote.h"
#include "git2/revwalk.h"
#include "git2/tree.h"
#include "git2/version.h"

typedef struct push_spec {
	char *lref;
	char *rref;

	git_oid loid;
	git_oid roid;

	bool force;
} push_spec;

typedef struct push_status {
	bool ok;

	char *ref;
	char *msg;
} push_status;

struct git_push {
	git_repository *repo;
	git_packbuilder *pb;
	git_remote *remote;
	git_vector specs;
	git_transport_caps caps;

	/* report-status */
	bool unpack_ok;
	git_vector status;
};

int git_push_new(git_push **out, git_remote *remote)
{
	git_push *p;

	*out = NULL;

	p = git__calloc(1, sizeof(*p));
	GITERR_CHECK_ALLOC(p);

	p->repo = remote->repo;
	p->remote = remote;
	p->caps.report_status = 1;

	if (git_vector_init(&p->specs, 0, NULL) < 0) {
		git__free(p);
		return -1;
	}

	if (git_vector_init(&p->status, 0, NULL) < 0) {
		git_vector_free(&p->specs);
		git__free(p);
		return -1;
	}

	*out = p;
	return 0;
}

static void free_refspec(push_spec *spec)
{
	if (spec == NULL)
		return;

	if (spec->lref)
		git__free(spec->lref);

	if (spec->rref)
		git__free(spec->rref);

	git__free(spec);
}

static void free_status(push_status *status)
{
	if (status == NULL)
		return;

	if (status->msg)
		git__free(status->msg);

	git__free(status->ref);
	git__free(status);
}

static int check_ref(char *ref)
{
	if (strcmp(ref, "HEAD") &&
	    git__prefixcmp(ref, "refs/heads/") &&
	    git__prefixcmp(ref, "refs/tags/")) {
		giterr_set(GITERR_INVALID, "No valid reference '%s'", ref);
		return -1;
	}
	return 0;
}

static int parse_refspec(push_spec **spec, const char *str)
{
	push_spec *s;
	char *delim;

	*spec = NULL;

	s = git__calloc(1, sizeof(*s));
	GITERR_CHECK_ALLOC(s);

	if (str[0] == '+') {
		s->force = true;
		str++;
	}

	delim = strchr(str, ':');
	if (delim == NULL) {
		s->lref = git__strdup(str);
		if (!s->lref ||
		    check_ref(s->lref) < 0)
			goto on_error;
		s->rref = NULL;
	} else {
		if (delim - str) {
			s->lref = git__strndup(str, delim - str);
			if (!s->lref ||
			    check_ref(s->lref) < 0)
				goto on_error;
		} else
			s->lref = NULL;

		if (strlen(delim + 1)) {
			s->rref = git__strdup(delim + 1);
			if (!s->rref ||
			    check_ref(s->rref) < 0)
				goto on_error;
		} else
			s->rref = NULL;
	}

	*spec = s;
	return 0;

on_error:
	free_refspec(s);
	return -1;
}

int git_push_add_refspec(git_push *push, const char *refspec)
{
	push_spec *spec;

	assert(push && refspec);

	if (strchr(refspec, '*')) {
		giterr_set(GITERR_INVALID, "No wildcard refspec supported");
		return -1;
	}

	if (parse_refspec(&spec, refspec) < 0 ||
	    git_vector_insert(&push->specs, spec) < 0)
		return -1;

	return 0;
}

static int gen_pktline(git_buf *buf, git_push *push)
{
	git_remote_head *head;
	push_spec *spec;
	unsigned int i, j, len;
	char hex[41]; hex[40] = '\0';

	git_vector_foreach(&push->specs, i, spec) {
		len = 2*GIT_OID_HEXSZ + 7;

		if (i == 0) {
			len +=1; /* '\0' */
			if (push->caps.report_status)
				len += strlen(GIT_CAP_REPORT_STATUS);
		}

		if (spec->lref) {
			if (git_reference_name_to_oid(
					&spec->loid, push->repo, spec->lref) < 0) {
				giterr_set(GIT_ENOTFOUND, "No such reference '%s'", spec->lref);
				return -1;
			}

			if (!spec->rref) {
				/*
				 * No remote reference given; if we find a remote
				 * reference with the same name we will update it,
				 * otherwise a new reference will be created.
				 */
				len += strlen(spec->lref);
				git_vector_foreach(&push->remote->refs, j, head) {
					if (!strcmp(spec->lref, head->name)) {
						/*
						 * Update remote reference
						 */
						git_oid_cpy(&spec->roid, &head->oid);
						git_oid_fmt(hex, &spec->roid);
						git_buf_printf(buf, "%04x%s ", len, hex);

						git_oid_fmt(hex, &spec->loid);
						git_buf_printf(buf, "%s %s", hex,
							       spec->lref);

						break;
					}
				}

				if (git_oid_iszero(&spec->roid)) {
					/*
					 * Create remote reference
					 */
					git_oid_fmt(hex, &spec->loid);
					git_buf_printf(buf, "%04x%s %s %s", len,
						       GIT_OID_HEX_ZERO, hex, spec->lref);
				}
			} else {
				/*
				 * Remote reference given; update the given
				 * reference or create it.
				 */
				len += strlen(spec->rref);
				git_vector_foreach(&push->remote->refs, j, head) {
					if (!strcmp(spec->rref, head->name)) {
						/*
						 * Update remote reference
						 */
						git_oid_cpy(&spec->roid, &head->oid);
						git_oid_fmt(hex, &spec->roid);
						git_buf_printf(buf, "%04x%s ", len, hex);

						git_oid_fmt(hex, &spec->loid);
						git_buf_printf(buf, "%s %s", hex,
							       spec->rref);

						break;
					}
				}

				if (git_oid_iszero(&spec->roid)) {
					/*
					 * Create remote reference
					 */
					git_oid_fmt(hex, &spec->loid);
					git_buf_printf(buf, "%04x%s %s %s", len,
						       GIT_OID_HEX_ZERO, hex, spec->rref);
				}
			}

		} else {
			/*
			 * Delete remote reference
			 */
			git_vector_foreach(&push->remote->refs, j, head) {
				if (!strcmp(spec->rref, head->name)) {
					len += strlen(spec->rref);

					git_oid_fmt(hex, &head->oid);
					git_buf_printf(buf, "%04x%s %s %s", len,
						       hex, GIT_OID_HEX_ZERO, head->name);

					break;
				}
			}
		}

		if (i == 0) {
			git_buf_putc(buf, '\0');
			if (push->caps.report_status)
				git_buf_printf(buf, GIT_CAP_REPORT_STATUS);
		}

		git_buf_putc(buf, '\n');
	}
	git_buf_puts(buf, "0000");
	return git_buf_oom(buf) ? -1 : 0;
}

static int revwalk(git_vector *commits, git_push *push)
{
	git_remote_head *head;
	push_spec *spec;
	git_revwalk *rw;
	git_oid oid;
	unsigned int i;
	int error = -1;

	if (git_revwalk_new(&rw, push->repo) < 0)
		return -1;

	git_revwalk_sorting(rw, GIT_SORT_TIME);

	git_vector_foreach(&push->specs, i, spec) {
		if (git_oid_iszero(&spec->loid))
			/*
			 * Delete reference on remote side;
			 * nothing to do here.
			 */
			continue;

		if (git_oid_equal(&spec->loid, &spec->roid))
			continue; /* up-to-date */

		if (git_revwalk_push(rw, &spec->loid) < 0)
			goto on_error;

		if (!spec->force) {
			git_oid base;

			if (git_oid_iszero(&spec->roid))
				continue;

			if (!git_odb_exists(push->repo->_odb, &spec->roid)) {
				giterr_clear();
				error = GIT_ENONFASTFORWARD;
				goto on_error;
			}

			error = git_merge_base(&base, push->repo,
					       &spec->loid, &spec->roid);
			if (error == GIT_ENOTFOUND) {
				giterr_clear();
				error = GIT_ENONFASTFORWARD;
				goto on_error;
			}
			if (error < 0)
				goto on_error;
		}
	}

	git_vector_foreach(&push->remote->refs, i, head) {
		if (git_oid_iszero(&head->oid))
			continue;

		/* TODO */
		git_revwalk_hide(rw, &head->oid);
	}

	while ((error = git_revwalk_next(&oid, rw)) == 0) {
		git_oid *o = git__malloc(GIT_OID_RAWSZ);
		GITERR_CHECK_ALLOC(o);
		git_oid_cpy(o, &oid);
		if (git_vector_insert(commits, o) < 0) {
			error = -1;
			goto on_error;
		}
	}

on_error:
	git_revwalk_free(rw);
	return error == GIT_ITEROVER ? 0 : error;
}

static int queue_objects(git_push *push)
{
	git_vector commits;
	git_oid *o;
	unsigned int i;
	int error = -1;

	if (git_vector_init(&commits, 0, NULL) < 0)
		return -1;

	if (revwalk(&commits, push) < 0)
		goto on_error;

	if (!commits.length)
		return 0; /* nothing to do */

	git_vector_foreach(&commits, i, o) {
		if (git_packbuilder_insert(push->pb, o, NULL) < 0)
			goto on_error;
	}

	git_vector_foreach(&commits, i, o) {
		git_object *obj;

		if (git_object_lookup(&obj, push->repo, o, GIT_OBJ_ANY) < 0)
			goto on_error;

		switch (git_object_type(obj)) {
		case GIT_OBJ_TAG: /* TODO: expect tags */
		case GIT_OBJ_COMMIT:
			if (git_packbuilder_insert_tree(push->pb,
					git_commit_tree_oid((git_commit *)obj)) < 0) {
				git_object_free(obj);
				goto on_error;
			}
			break;
		case GIT_OBJ_TREE:
		case GIT_OBJ_BLOB:
		default:
			git_object_free(obj);
			giterr_set(GITERR_INVALID, "Given object type invalid");
			goto on_error;
		}
		git_object_free(obj);
	}
	error = 0;

on_error:
	git_vector_foreach(&commits, i, o) {
		git__free(o);
	}
	git_vector_free(&commits);
	return error;
}

static int do_push(git_push *push)
{
	git_transport *t = push->remote->transport;
	git_buf pktline = GIT_BUF_INIT;

	if (gen_pktline(&pktline, push) < 0)
		goto on_error;

#ifdef PUSH_DEBUG
{
	git_remote_head *head;
	push_spec *spec;
	unsigned int i;
	char hex[41]; hex[40] = '\0';

	git_vector_foreach(&push->remote->refs, i, head) {
		git_oid_fmt(hex, &head->oid);
		fprintf(stderr, "%s (%s)\n", hex, head->name);
	}

	git_vector_foreach(&push->specs, i, spec) {
		git_oid_fmt(hex, &spec->roid);
		fprintf(stderr, "%s (%s) -> ", hex, spec->lref);
		git_oid_fmt(hex, &spec->loid);
		fprintf(stderr, "%s (%s)\n", hex, spec->rref ?
			spec->rref : spec->lref);
	}
}
#endif

	/*
	 * A pack-file MUST be sent if either create or update command
	 * is used, even if the server already has all the necessary
	 * objects.  In this case the client MUST send an empty pack-file.
	 */

	if (git_packbuilder_new(&push->pb, push->repo) < 0)
		goto on_error;

	if (queue_objects(push) < 0)
		goto on_error;

	if (t->rpc) {
		git_buf pack = GIT_BUF_INIT;

		if (git_packbuilder_write_buf(&pack, push->pb) < 0)
			goto on_error;

		if (t->push(t, &pktline, &pack) < 0) {
			git_buf_free(&pack);
			goto on_error;
		}

		git_buf_free(&pack);
	} else {
		if (gitno_send(push->remote->transport,
			       pktline.ptr, pktline.size, 0) < 0)
			goto on_error;

		if (git_packbuilder_send(push->pb, push->remote->transport) < 0)
			goto on_error;
	}

	git_packbuilder_free(push->pb);
	git_buf_free(&pktline);
	return 0;

on_error:
	git_packbuilder_free(push->pb);
	git_buf_free(&pktline);
	return -1;
}

static int parse_report(git_push *push)
{
	gitno_buffer *buf = &push->remote->transport->buffer;
	git_pkt *pkt;
	const char *line_end;
	int error, recvd;

	for (;;) {
		if (buf->offset > 0)
			error = git_pkt_parse_line(&pkt, buf->data,
						   &line_end, buf->offset);
		else
			error = GIT_EBUFS;

		if (error < 0 && error != GIT_EBUFS)
			return -1;

		if (error == GIT_EBUFS) {
			if ((recvd = gitno_recv(buf)) < 0)
				return -1;

			if (recvd == 0) {
				giterr_set(GITERR_NET, "Early EOF");
				return -1;
			}
			continue;
		}

		gitno_consume(buf, line_end);

		if (pkt->type == GIT_PKT_OK) {
			push_status *status = git__malloc(sizeof(*status));
			GITERR_CHECK_ALLOC(status);
			status->ref = git__strdup(((git_pkt_ok *)pkt)->ref);
			status->msg = NULL;
			git_pkt_free(pkt);
			if (git_vector_insert(&push->status, status) < 0) {
				git__free(status);
				return -1;
			}
			continue;
		}

		if (pkt->type == GIT_PKT_NG) {
			push_status *status = git__malloc(sizeof(*status));
			GITERR_CHECK_ALLOC(status);
			status->ref = git__strdup(((git_pkt_ng *)pkt)->ref);
			status->msg = git__strdup(((git_pkt_ng *)pkt)->msg);
			git_pkt_free(pkt);
			if (git_vector_insert(&push->status, status) < 0) {
				git__free(status);
				return -1;
			}
			continue;
		}

		if (pkt->type == GIT_PKT_UNPACK) {
			push->unpack_ok = ((git_pkt_unpack *)pkt)->unpack_ok;
			git_pkt_free(pkt);
			continue;
		}

		if (pkt->type == GIT_PKT_FLUSH) {
			git_pkt_free(pkt);
			return 0;
		}

		git_pkt_free(pkt);
		giterr_set(GITERR_NET, "report-status: protocol error");
		return -1;
	}
}

static int finish_push(git_push *push)
{
	int error = -1;

	if (push->caps.report_status && parse_report(push) < 0)
		goto on_error;

	error = 0;

on_error:
	git_remote_disconnect(push->remote);
	return error;
}

static int cb_filter_refs(git_remote_head *ref, void *data)
{
	git_remote *remote = data;
	return git_vector_insert(&remote->refs, ref);
}

static int filter_refs(git_remote *remote)
{
	git_vector_clear(&remote->refs);
	return git_remote_ls(remote, cb_filter_refs, remote);
}

int git_push_finish(git_push *push)
{
	if (!git_remote_connected(push->remote) &&
		git_remote_connect(push->remote, GIT_DIR_PUSH) < 0)
			return -1;

	if (filter_refs(push->remote) < 0 || do_push(push) < 0) {
		git_remote_disconnect(push->remote);
		return -1;
	}

	return finish_push(push);
}

int git_push_unpack_ok(git_push *push)
{
	return push->unpack_ok;
}

int git_push_status_foreach(git_push *push,
		int (*cb)(const char *ref, const char *msg, void *data),
		void *data)
{
	push_status *status;
	unsigned int i;

	git_vector_foreach(&push->status, i, status) {
		if (cb(status->ref, status->msg, data) < 0)
			return GIT_EUSER;
	}

	return 0;
}

void git_push_free(git_push *push)
{
	push_spec *spec;
	push_status *status;
	unsigned int i;

	if (push == NULL)
		return;

	git_vector_foreach(&push->specs, i, spec) {
		free_refspec(spec);
	}
	git_vector_free(&push->specs);

	git_vector_foreach(&push->status, i, status) {
		free_status(status);
	}
	git_vector_free(&push->status);

	git__free(push);
}
