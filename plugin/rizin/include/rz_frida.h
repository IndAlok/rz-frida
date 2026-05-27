// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FRIDA_H
#define RZ_FRIDA_H

#include <rz_types.h>
#include <rz_util.h>

#define RZ_FRIDA_DEFAULT_TIMEOUT_MS 5000

typedef enum rz_frida_action_t {
	RZ_FRIDA_ACTION_UNKNOWN = 0,
	RZ_FRIDA_ACTION_LIST,
	RZ_FRIDA_ACTION_APPS,
	RZ_FRIDA_ACTION_ATTACH,
	RZ_FRIDA_ACTION_SPAWN,
	RZ_FRIDA_ACTION_LAUNCH,
} RzFridaAction;

typedef enum rz_frida_transport_t {
	RZ_FRIDA_TRANSPORT_UNKNOWN = 0,
	RZ_FRIDA_TRANSPORT_LOCAL,
	RZ_FRIDA_TRANSPORT_USB,
	RZ_FRIDA_TRANSPORT_REMOTE,
} RzFridaTransport;

typedef enum rz_frida_session_state_t {
	RZ_FRIDA_SESSION_STATE_NEW = 0,
	RZ_FRIDA_SESSION_STATE_RESOLVED,
	RZ_FRIDA_SESSION_STATE_CONNECTING,
	RZ_FRIDA_SESSION_STATE_ATTACHED,
	RZ_FRIDA_SESSION_STATE_DETACHING,
	RZ_FRIDA_SESSION_STATE_CLOSED,
	RZ_FRIDA_SESSION_STATE_ERROR,
} RzFridaSessionState;

typedef enum rz_frida_method_t {
	RZ_FRIDA_METHOD_UNKNOWN = 0,
	RZ_FRIDA_METHOD_STATUS,
	RZ_FRIDA_METHOD_DEVICES,
	RZ_FRIDA_METHOD_PROCESSES,
	RZ_FRIDA_METHOD_APPS,
	RZ_FRIDA_METHOD_ATTACH,
	RZ_FRIDA_METHOD_SPAWN,
	RZ_FRIDA_METHOD_LAUNCH,
	RZ_FRIDA_METHOD_DETACH,
} RzFridaMethod;

typedef enum rz_frida_error_t {
	RZ_FRIDA_ERROR_NONE = 0,
	RZ_FRIDA_ERROR_INVALID_URI,
	RZ_FRIDA_ERROR_INVALID_TARGET,
	RZ_FRIDA_ERROR_TIMEOUT,
	RZ_FRIDA_ERROR_CANCELLED,
	RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE,
	RZ_FRIDA_ERROR_NOT_IMPLEMENTED,
	RZ_FRIDA_ERROR_INTERNAL,
} RzFridaError;

typedef struct rz_frida_uri_t {
	RzFridaAction action_type;
	RzFridaTransport transport_type;
	char *action;
	char *transport;
	char *device;
	char *target;
} RzFridaUri;

typedef struct rz_frida_session_t RzFridaSession;

const char *rz_frida_action_string(RzFridaAction action);
RzFridaAction rz_frida_action_from_string(const char *action);
const char *rz_frida_transport_string(RzFridaTransport transport);
RzFridaTransport rz_frida_transport_from_string(const char *transport);

bool rz_frida_uri_parse(const char *uri, RzFridaUri *out);
bool rz_frida_uri_copy(RzFridaUri *dst, const RzFridaUri *src);
void rz_frida_uri_fini(RzFridaUri *uri);

RzFridaSession *rz_frida_session_new(void);
void rz_frida_session_free(RzFridaSession *session);
bool rz_frida_session_set_uri(RzFridaSession *session, const RzFridaUri *uri);
const RzFridaUri *rz_frida_session_uri(const RzFridaSession *session);
RzFridaSessionState rz_frida_session_state(const RzFridaSession *session);
const char *rz_frida_session_state_string(RzFridaSessionState state);
void rz_frida_session_set_timeout(RzFridaSession *session, ut64 timeout_ms);
ut64 rz_frida_session_timeout(const RzFridaSession *session);
void rz_frida_session_request_cancel(RzFridaSession *session);
bool rz_frida_session_is_cancelled(const RzFridaSession *session);
void rz_frida_session_set_error(RzFridaSession *session, const char *message);
const char *rz_frida_session_error(const RzFridaSession *session);

const char *rz_frida_method_string(RzFridaMethod method);
RzFridaMethod rz_frida_method_from_string(const char *method);
bool rz_frida_method_parse(const char *method, RzFridaMethod *out, PJ *pj);
const char *rz_frida_error_string(RzFridaError error);
void rz_frida_json_ok_begin(PJ *pj);
void rz_frida_json_ok_end(PJ *pj);
void rz_frida_json_ok_empty(PJ *pj);
void rz_frida_json_error(PJ *pj, RzFridaError error, const char *message);

bool rz_frida_devices_json(PJ *pj);

#endif
