// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FRIDA_H
#define RZ_FRIDA_H

#include <rz_types.h>
#include <rz_util.h>

#define RZ_FRIDA_DEFAULT_TIMEOUT_MS 5000

/**
 * \brief URI operation requested by the frontend or command layer.
 */
typedef enum rz_frida_action_t {
	RZ_FRIDA_ACTION_UNKNOWN = 0, ///< Unknown or unsupported action.
	RZ_FRIDA_ACTION_LIST, ///< List devices for a transport.
	RZ_FRIDA_ACTION_APPS, ///< List applications of a target device.
	RZ_FRIDA_ACTION_ATTACH, ///< Attach to an existing process.
	RZ_FRIDA_ACTION_SPAWN, ///< Spawn a new process without resuming it yet.
	RZ_FRIDA_ACTION_LAUNCH, ///< Launch a process and prepare a session.
} RzFridaAction;

/**
 * \brief Transport used to reach the Frida target.
 */
typedef enum rz_frida_transport_t {
	RZ_FRIDA_TRANSPORT_UNKNOWN = 0, ///< Unknown or unsupported transport.
	RZ_FRIDA_TRANSPORT_LOCAL, ///< Local Frida device.
	RZ_FRIDA_TRANSPORT_USB, ///< USB-connected Frida device.
	RZ_FRIDA_TRANSPORT_REMOTE, ///< Remote Frida endpoint.
} RzFridaTransport;

/**
 * \brief Internal lifecycle state for an rz-frida session.
 */
typedef enum rz_frida_session_state_t {
	RZ_FRIDA_SESSION_STATE_NEW = 0, ///< Session was allocated but no target is resolved.
	RZ_FRIDA_SESSION_STATE_RESOLVED, ///< Target URI was copied into the session.
	RZ_FRIDA_SESSION_STATE_CONNECTING, ///< Backend connection is in progress.
	RZ_FRIDA_SESSION_STATE_ATTACHED, ///< Session is attached to a target.
	RZ_FRIDA_SESSION_STATE_DETACHING, ///< Detach is in progress.
	RZ_FRIDA_SESSION_STATE_CLOSED, ///< Session is closed.
	RZ_FRIDA_SESSION_STATE_ERROR, ///< Session entered an error state.
} RzFridaSessionState;

/**
 * \brief Structured backend request method.
 */
typedef enum rz_frida_method_t {
	RZ_FRIDA_METHOD_UNKNOWN = 0, ///< Unknown or unsupported method.
	RZ_FRIDA_METHOD_STATUS, ///< Query plugin/session status.
	RZ_FRIDA_METHOD_DEVICES, ///< Enumerate Frida devices.
	RZ_FRIDA_METHOD_PROCESSES, ///< Enumerate processes.
	RZ_FRIDA_METHOD_APPS, ///< Enumerate applications.
	RZ_FRIDA_METHOD_ATTACH, ///< Attach to a target.
	RZ_FRIDA_METHOD_SPAWN, ///< Spawn a target.
	RZ_FRIDA_METHOD_LAUNCH, ///< Launch a target.
	RZ_FRIDA_METHOD_DETACH, ///< Detach from the active target.
} RzFridaMethod;

/**
 * \brief Stable structured error code for rz-frida replies.
 */
typedef enum rz_frida_error_t {
	RZ_FRIDA_ERROR_NONE = 0, ///< No error.
	RZ_FRIDA_ERROR_INVALID_URI, ///< URI grammar or validation failed.
	RZ_FRIDA_ERROR_INVALID_TARGET, ///< Target selection is missing or invalid.
	RZ_FRIDA_ERROR_TIMEOUT, ///< Operation timed out.
	RZ_FRIDA_ERROR_CANCELLED, ///< Operation was cancelled.
	RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, ///< Frida backend support is unavailable.
	RZ_FRIDA_ERROR_NOT_IMPLEMENTED, ///< Requested method is not implemented.
	RZ_FRIDA_ERROR_INTERNAL, ///< Internal failure.
} RzFridaError;

/**
 * \brief Parsed and validated frida:// URI.
 */
typedef struct rz_frida_uri_t {
	RzFridaAction action_type; ///< Action parsed from the URI.
	RzFridaTransport transport_type; ///< Transport parsed from the URI.
	char *action; ///< Action component as text.
	char *transport; ///< Transport component as text.
	char *device; ///< Device selector (empty, device id, or host:port).
	char *target; ///< Target selector (pid, process name, package, or path).
} RzFridaUri;

/**
 * \brief Opaque handle for an rz-frida session.
 */
typedef struct rz_frida_session_t RzFridaSession;

/**
 * \brief Backend cleanup callback run once when a session is freed.
 */
typedef void (*RzFridaBackendDispose)(RZ_NONNULL RzFridaSession *session);

RZ_IPI const char *rz_frida_action_string(RzFridaAction action);
RZ_IPI RzFridaAction rz_frida_action_from_string(RZ_NULLABLE const char *action);
RZ_IPI const char *rz_frida_transport_string(RzFridaTransport transport);
RZ_IPI RzFridaTransport rz_frida_transport_from_string(RZ_NULLABLE const char *transport);

RZ_IPI bool rz_frida_uri_parse(RZ_NONNULL const char *uri, RZ_NONNULL RzFridaUri *out);
RZ_IPI bool rz_frida_uri_copy(RZ_NONNULL RzFridaUri *dst, RZ_NONNULL const RzFridaUri *src);
RZ_IPI void rz_frida_uri_fini(RZ_NULLABLE RzFridaUri *uri);

/**
 * \brief Parse a decimal only target selector as a process id.
 */
RZ_IPI bool rz_frida_uri_target_pid(RZ_NONNULL const char *target, RZ_NONNULL ut32 *pid_out);

RZ_IPI RzFridaSession *rz_frida_session_new(void);
RZ_IPI void rz_frida_session_free(RZ_NULLABLE RzFridaSession *session);
RZ_IPI bool rz_frida_session_set_uri(RZ_NONNULL RzFridaSession *session, RZ_NONNULL const RzFridaUri *uri);
RZ_IPI const RzFridaUri *rz_frida_session_uri(RZ_NONNULL const RzFridaSession *session);
RZ_IPI RzFridaSessionState rz_frida_session_state(RZ_NONNULL const RzFridaSession *session);
RZ_IPI const char *rz_frida_session_state_string(RzFridaSessionState state);
RZ_IPI void rz_frida_session_set_timeout(RZ_NONNULL RzFridaSession *session, ut64 timeout_ms);
RZ_IPI ut64 rz_frida_session_timeout(RZ_NONNULL const RzFridaSession *session);
RZ_IPI void rz_frida_session_request_cancel(RZ_NONNULL RzFridaSession *session);
RZ_IPI bool rz_frida_session_is_cancelled(RZ_NONNULL const RzFridaSession *session);
RZ_IPI void rz_frida_session_set_error(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE const char *message);
RZ_IPI const char *rz_frida_session_error(RZ_NONNULL const RzFridaSession *session);
RZ_IPI void rz_frida_session_set_state(RZ_NONNULL RzFridaSession *session, RzFridaSessionState state);
RZ_IPI void rz_frida_session_set_target_pid(RZ_NONNULL RzFridaSession *session, ut32 pid);
RZ_IPI ut32 rz_frida_session_target_pid(RZ_NONNULL const RzFridaSession *session);
RZ_IPI void rz_frida_session_set_backend_state(RZ_NONNULL RzFridaSession *session, RZ_NULLABLE void *backend_state, RZ_NULLABLE RzFridaBackendDispose dispose);
RZ_IPI void *rz_frida_session_backend_state(RZ_NONNULL const RzFridaSession *session);

RZ_IPI const char *rz_frida_method_string(RzFridaMethod method);
RZ_IPI RzFridaMethod rz_frida_method_from_string(RZ_NULLABLE const char *method);
RZ_IPI bool rz_frida_method_parse(RZ_NULLABLE const char *method, RZ_NONNULL RzFridaMethod *out, RZ_NULLABLE PJ *pj);
RZ_IPI const char *rz_frida_error_string(RzFridaError error);
RZ_IPI void rz_frida_json_ok_begin(RZ_NONNULL PJ *pj);
RZ_IPI void rz_frida_json_ok_end(RZ_NONNULL PJ *pj);
RZ_IPI void rz_frida_json_ok_empty(RZ_NONNULL PJ *pj);
RZ_IPI void rz_frida_json_error(RZ_NONNULL PJ *pj, RzFridaError error, RZ_NULLABLE const char *message);

/**
 * \brief Start the Frida runtime used by the plugin backend.
 */
RZ_IPI void rz_frida_backend_init(void);

/**
 * \brief Stop the Frida runtime used by the plugin backend.
 */
RZ_IPI void rz_frida_backend_deinit(void);

/**
 * \brief Enumerate the available Frida devices into a JSON envelope.
 *
 * Writes an ok:true envelope carrying a "devices" array on success, or an
 * ok:false error envelope on failure. When the plugin is built without
 * frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the device list was emitted, false on any error.
 */
RZ_IPI bool rz_frida_devices_json(RZ_NONNULL PJ *pj);

/**
 * \brief Enumerate the processes on the local device into a JSON envelope.
 *
 * Writes an ok:true envelope carrying a "processes" array on success, or an
 * ok:false error envelope on failure. When the plugin is built without frida-core,
 * a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the process list was emitted, false on any error.
 */
RZ_IPI bool rz_frida_processes_json(RZ_NONNULL PJ *pj);

/**
 * \brief Open a session for the target described by the session URI.
 *
 * Resolves the local device, then attaches to a pid, or spawns or launches the
 * target before attaching. On success the live Frida handles are stored on the
 * session and an ok:true envelope carrying the action, pid, and state is
 * written, and on failure an ok:false envelope is written. When the plugin is built
 * without frida-core, a self contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session that owns the resolved URI and receives the backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the session was opened, false on any error.
 */
RZ_IPI bool rz_frida_backend_open(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);

/**
 * \brief Resume a target that was spawned suspended by \ref rz_frida_backend_open.
 *
 * Writes an ok:true envelope on success, or an ok:false envelope when the
 * session has nothing to resume or the backend is unavailable.
 *
 * \param session Session holding the backend handles to resume.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the target was resumed, false on any error.
 */
RZ_IPI bool rz_frida_backend_resume(RZ_NONNULL RzFridaSession *session, RZ_NONNULL PJ *pj);

#endif
