// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

struct rz_frida_session_t {
	ut64 id;
	RzFridaSessionState state;
	RzFridaUri uri;
	ut64 timeout_ms;
	bool cancel_requested;
	char *last_error;
	void *device_manager;
	void *device;
	void *session;
	void *script;
	void *cancellable;
};

const char *rz_frida_session_state_string(RzFridaSessionState state) {
	switch (state) {
	case RZ_FRIDA_SESSION_STATE_NEW:
		return "new";
	case RZ_FRIDA_SESSION_STATE_RESOLVED:
		return "resolved";
	case RZ_FRIDA_SESSION_STATE_CONNECTING:
		return "connecting";
	case RZ_FRIDA_SESSION_STATE_ATTACHED:
		return "attached";
	case RZ_FRIDA_SESSION_STATE_DETACHING:
		return "detaching";
	case RZ_FRIDA_SESSION_STATE_CLOSED:
		return "closed";
	case RZ_FRIDA_SESSION_STATE_ERROR:
		return "error";
	default:
		return "unknown";
	}
}

RzFridaSession *rz_frida_session_new(void) {
	RzFridaSession *session = RZ_NEW0(RzFridaSession);
	if (!session) {
		return NULL;
	}
	session->state = RZ_FRIDA_SESSION_STATE_NEW;
	session->timeout_ms = RZ_FRIDA_DEFAULT_TIMEOUT_MS;
	return session;
}

void rz_frida_session_free(RzFridaSession *session) {
	if (!session) {
		return;
	}
	rz_frida_uri_fini(&session->uri);
	RZ_FREE(session->last_error);
	RZ_FREE(session);
}

bool rz_frida_session_set_uri(RzFridaSession *session, const RzFridaUri *uri) {
	if (!session || !uri) {
		return false;
	}
	RzFridaUri copy = { 0 };
	if (!rz_frida_uri_copy(&copy, uri)) {
		return false;
	}
	rz_frida_uri_fini(&session->uri);
	session->uri = copy;
	session->state = RZ_FRIDA_SESSION_STATE_RESOLVED;
	return true;
}

const RzFridaUri *rz_frida_session_uri(const RzFridaSession *session) {
	return session ? &session->uri : NULL;
}

RzFridaSessionState rz_frida_session_state(const RzFridaSession *session) {
	return session ? session->state : RZ_FRIDA_SESSION_STATE_ERROR;
}

void rz_frida_session_set_timeout(RzFridaSession *session, ut64 timeout_ms) {
	if (!session) {
		return;
	}
	session->timeout_ms = timeout_ms;
}

ut64 rz_frida_session_timeout(const RzFridaSession *session) {
	return session ? session->timeout_ms : 0;
}

void rz_frida_session_request_cancel(RzFridaSession *session) {
	if (!session) {
		return;
	}
	session->cancel_requested = true;
}

bool rz_frida_session_is_cancelled(const RzFridaSession *session) {
	return session ? session->cancel_requested : false;
}

void rz_frida_session_set_error(RzFridaSession *session, const char *message) {
	if (!session) {
		return;
	}
	char *copy = rz_str_dup(message ? message : "internal error");
	if (!copy) {
		return;
	}
	RZ_FREE(session->last_error);
	session->last_error = copy;
	session->state = RZ_FRIDA_SESSION_STATE_ERROR;
}

const char *rz_frida_session_error(const RzFridaSession *session) {
	return session ? session->last_error : NULL;
}
