// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

/**
 * \brief Mutable state backing an \ref RzFridaSession handle.
 *
 * Tracks the resolved target, lifecycle bookkeeping, and frida-core
 * state the backend owns while a session is connected. The
 * pointer stays void here so this header-free struct does not pull
 * in frida-core for callers that only need the session API.
 */
struct rz_frida_session_t {
	ut64 id; ///< Numeric session identifier.
	RzFridaSessionState state; ///< Current lifecycle state.
	RzFridaUri uri; ///< Owned copy of the resolved target URI.
	ut64 timeout_ms; ///< Operation timeout in milliseconds.
	bool cancel_requested; ///< Set when cancellation was requested for the current operation
	char *last_error; ///< Owned text of the most recent error, or NULL.
	ut32 target_pid; ///< Process id resolved once the session attaches, spawns, or launches.
	void *backend_state; ///< frida-core handles owned by the backend, or NULL.
	RzFridaBackendDispose backend_dispose; ///< Releases backend_state during free, or NULL.
	void *cancel_user; ///< User data passed to cancel_hook, or NULL.
	RzFridaCancelHook cancel_hook; ///< Cancels the current backend operation, or NULL.
};

RZ_IPI const char *rz_frida_session_state_string(RzFridaSessionState state) {
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

RZ_IPI RzFridaSession *rz_frida_session_new(void) {
	RzFridaSession *session = RZ_NEW0(RzFridaSession);
	if (!session) {
		return NULL;
	}
	session->state = RZ_FRIDA_SESSION_STATE_NEW;
	session->timeout_ms = RZ_FRIDA_DEFAULT_TIMEOUT_MS;
	return session;
}

RZ_IPI void rz_frida_session_free(RzFridaSession *session) {
	if (!session) {
		return;
	}
	if (session->backend_dispose) {
		session->backend_dispose(session);
	}
	rz_frida_uri_fini(&session->uri);
	RZ_FREE(session->last_error);
	RZ_FREE(session);
}

RZ_IPI bool rz_frida_session_set_uri(RzFridaSession *session, const RzFridaUri *uri) {
	rz_return_val_if_fail(session && uri, false);

	RzFridaUri copy = { 0 };
	if (!rz_frida_uri_copy(&copy, uri)) {
		return false;
	}
	rz_frida_uri_fini(&session->uri);
	session->uri = copy;
	session->state = RZ_FRIDA_SESSION_STATE_RESOLVED;
	return true;
}

RZ_IPI const RzFridaUri *rz_frida_session_uri(const RzFridaSession *session) {
	rz_return_val_if_fail(session, NULL);
	return &session->uri;
}

RZ_IPI RzFridaSessionState rz_frida_session_state(const RzFridaSession *session) {
	rz_return_val_if_fail(session, RZ_FRIDA_SESSION_STATE_ERROR);
	return session->state;
}

RZ_IPI void rz_frida_session_set_timeout(RzFridaSession *session, ut64 timeout_ms) {
	rz_return_if_fail(session);
	session->timeout_ms = timeout_ms;
}

RZ_IPI ut64 rz_frida_session_timeout(const RzFridaSession *session) {
	rz_return_val_if_fail(session, 0);
	return session->timeout_ms;
}

RZ_IPI void rz_frida_session_request_cancel(RzFridaSession *session) {
	rz_return_if_fail(session);
	session->cancel_requested = true;
	if (session->cancel_hook) {
		session->cancel_hook(session->cancel_user);
	}
}

RZ_IPI bool rz_frida_session_is_cancelled(const RzFridaSession *session) {
	rz_return_val_if_fail(session, false);
	return session->cancel_requested;
}

RZ_IPI void rz_frida_session_reset_cancel(RzFridaSession *session) {
	rz_return_if_fail(session);
	session->cancel_requested = false;
}

RZ_IPI void rz_frida_session_set_error(RzFridaSession *session, const char *message) {
	rz_return_if_fail(session);
	char *copy = rz_str_dup(message ? message : "internal error");
	if (!copy) {
		return;
	}
	RZ_FREE(session->last_error);
	session->last_error = copy;
	session->state = RZ_FRIDA_SESSION_STATE_ERROR;
}

RZ_IPI const char *rz_frida_session_error(const RzFridaSession *session) {
	rz_return_val_if_fail(session, NULL);
	return session->last_error;
}

RZ_IPI void rz_frida_session_set_state(RzFridaSession *session, RzFridaSessionState state) {
	rz_return_if_fail(session);
	session->state = state;
}

RZ_IPI void rz_frida_session_set_target_pid(RzFridaSession *session, ut32 pid) {
	rz_return_if_fail(session);
	session->target_pid = pid;
}

RZ_IPI ut32 rz_frida_session_target_pid(const RzFridaSession *session) {
	rz_return_val_if_fail(session, 0);
	return session->target_pid;
}

RZ_IPI void rz_frida_session_set_backend_state(RzFridaSession *session, void *backend_state, RzFridaBackendDispose dispose) {
	rz_return_if_fail(session);
	session->backend_state = backend_state;
	session->backend_dispose = dispose;
}

RZ_IPI void *rz_frida_session_backend_state(const RzFridaSession *session) {
	rz_return_val_if_fail(session, NULL);
	return session->backend_state;
}

/**
 * \brief Register the hook that \ref rz_frida_session_request_cancel invokes.
 *
 * Pass NULL to clear it before the hook user data is released.
 */
RZ_IPI void rz_frida_session_set_cancel_hook(RzFridaSession *session, void *user, RzFridaCancelHook hook) {
	rz_return_if_fail(session);
	session->cancel_user = user;
	session->cancel_hook = hook;
}
