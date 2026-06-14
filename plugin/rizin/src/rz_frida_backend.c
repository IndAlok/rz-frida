// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// Frida-backed device backend. meson compiles this translation unit only when
// frida-core is available and linkable, builds without frida-core compile
// rz_frida_backend_null.c in its place.

#include <rz_frida.h>

#include <frida-core.h>

#include <rzfrida_agent.h>

#define RZ_FRIDA_DRAIN_POLL_MS 50

static int frida_runtime_refs = 0;

/**
 * \brief Start the Frida runtime used by the plugin backend.
 */
RZ_IPI void rz_frida_backend_init(void) {
	if (frida_runtime_refs++ == 0) {
		frida_init();
	}
}

/**
 * \brief Stop the Frida runtime used by the plugin backend.
 */
RZ_IPI void rz_frida_backend_deinit(void) {
	rz_return_if_fail(frida_runtime_refs > 0);
	if (--frida_runtime_refs == 0) {
		frida_deinit();
	}
}

static const char *device_type_string(FridaDeviceType type) {
	switch (type) {
	case FRIDA_DEVICE_TYPE_LOCAL:
		return "local";
	case FRIDA_DEVICE_TYPE_REMOTE:
		return "remote";
	case FRIDA_DEVICE_TYPE_USB:
		return "usb";
	default:
		return "unknown";
	}
}

static RzFridaError backend_error_code(GCancellable *cancellable, GError *error);

static FridaDevice *backend_resolve_device(FridaDeviceManager *manager, const RzFridaUri *uri, gint timeout, GCancellable *cancellable, GError **error) {
	rz_return_val_if_fail(manager, NULL);

	RzFridaTransport transport = uri ? uri->transport_type : RZ_FRIDA_TRANSPORT_LOCAL;
	switch (transport) {
	case RZ_FRIDA_TRANSPORT_USB:
		if (uri && RZ_STR_ISNOTEMPTY(uri->device)) {
			return frida_device_manager_get_device_by_id_sync(manager, uri->device, timeout, cancellable, error);
		}
		return frida_device_manager_get_device_by_type_sync(manager, FRIDA_DEVICE_TYPE_USB, timeout, cancellable, error);
	case RZ_FRIDA_TRANSPORT_REMOTE: {
		FridaRemoteDeviceOptions *options = frida_remote_device_options_new();
		if (!options) {
			return NULL;
		}
		FridaDevice *device = frida_device_manager_add_remote_device_sync(manager, uri ? uri->device : "", options, cancellable, error);
		frida_unref(options);
		return device;
	}
	case RZ_FRIDA_TRANSPORT_LOCAL:
		return frida_device_manager_get_device_by_type_sync(manager, FRIDA_DEVICE_TYPE_LOCAL, timeout, cancellable, error);
	case RZ_FRIDA_TRANSPORT_UNKNOWN:
	default:
		return NULL;
	}
}

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
RZ_IPI bool rz_frida_devices_json(PJ *pj) {
	rz_return_val_if_fail(pj, false);

	bool ok = false;
	GError *error = NULL;
	FridaDeviceManager *manager = NULL;
	FridaDeviceList *devices = NULL;

	manager = frida_device_manager_new();
	if (!manager) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida device manager");
		goto cleanup;
	}

	devices = frida_device_manager_enumerate_devices_sync(manager, NULL, &error);
	if (!devices) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL,
			error ? error->message : "cannot enumerate Frida devices");
		goto cleanup;
	}

	rz_frida_json_ok_begin(pj);
	pj_ka(pj, "devices");
	const gint count = frida_device_list_size(devices);
	for (gint i = 0; i < count; i++) {
		FridaDevice *device = frida_device_list_get(devices, i);
		if (!device) {
			continue;
		}
		pj_o(pj);
		pj_ks(pj, "id", frida_device_get_id(device));
		pj_ks(pj, "name", frida_device_get_name(device));
		pj_ks(pj, "type", device_type_string(frida_device_get_dtype(device)));
		pj_kb(pj, "lost", frida_device_is_lost(device));
		pj_end(pj);
		g_object_unref(device);
	}
	pj_end(pj);
	rz_frida_json_ok_end(pj);
	ok = true;

cleanup:
	if (error) {
		g_error_free(error);
	}
	if (devices) {
		frida_unref(devices);
	}
	if (manager) {
		frida_device_manager_close_sync(manager, NULL, NULL);
		frida_unref(manager);
	}
	return ok;
}

/**
 * \brief Enumerate the processes on a device into a JSON envelope.
 *
 * Resolves the device selected by \p uri, NULL or the local transport selects
 * the local device, then writes an ok:true envelope carrying a "processes"
 * array on success, or an ok:false error envelope on failure. When the plugin
 * is built without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param uri Parsed URI whose transport and device select the device, or NULL for local.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the process list was emitted, false on any error.
 */
RZ_IPI bool rz_frida_processes_json(const RzFridaUri *uri, PJ *pj) {
	rz_return_val_if_fail(pj, false);

	bool ok = false;
	GError *error = NULL;
	FridaDeviceManager *manager = NULL;
	FridaDevice *device = NULL;
	FridaProcessQueryOptions *options = NULL;
	FridaProcessList *processes = NULL;

	manager = frida_device_manager_new();
	if (!manager) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida device manager");
		goto cleanup;
	}

	device = backend_resolve_device(manager, uri, RZ_FRIDA_DEFAULT_TIMEOUT_MS, NULL, &error);
	if (!device) {
		rz_frida_json_error(pj, backend_error_code(NULL, error),
			error ? error->message : "cannot open the Frida device");
		goto cleanup;
	}

	options = frida_process_query_options_new();
	if (!options) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida process query options");
		goto cleanup;
	}

	processes = frida_device_enumerate_processes_sync(device, options, NULL, &error);
	if (!processes) {
		rz_frida_json_error(pj, backend_error_code(NULL, error),
			error ? error->message : "cannot enumerate processes");
		goto cleanup;
	}

	rz_frida_json_ok_begin(pj);
	pj_ka(pj, "processes");
	const gint count = frida_process_list_size(processes);
	for (gint i = 0; i < count; i++) {
		FridaProcess *process = frida_process_list_get(processes, i);
		if (!process) {
			continue;
		}
		pj_o(pj);
		pj_kn(pj, "pid", frida_process_get_pid(process));
		pj_ks(pj, "name", frida_process_get_name(process));
		pj_end(pj);
		g_object_unref(process);
	}
	pj_end(pj);
	rz_frida_json_ok_end(pj);
	ok = true;

cleanup:
	if (error) {
		g_error_free(error);
	}
	if (processes) {
		frida_unref(processes);
	}
	if (options) {
		frida_unref(options);
	}
	if (device) {
		frida_unref(device);
	}
	if (manager) {
		frida_device_manager_close_sync(manager, NULL, NULL);
		frida_unref(manager);
	}
	return ok;
}

/**
 * \brief Enumerate the applications on a device into a JSON envelope.
 *
 * Resolves the device selected by \p uri, NULL or the local transport selects
 * the local device, then writes an ok:true envelope carrying an "apps" array on
 * success, or an ok:false error envelope on failure. Application listing is most
 * useful for Android and iOS targets reached over USB. When the plugin is built
 * without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param uri Parsed URI whose transport and device select the device, or NULL for local.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the application list was emitted, false on any error.
 */
RZ_IPI bool rz_frida_apps_json(const RzFridaUri *uri, PJ *pj) {
	rz_return_val_if_fail(pj, false);

	bool ok = false;
	GError *error = NULL;
	FridaDeviceManager *manager = NULL;
	FridaDevice *device = NULL;
	FridaApplicationQueryOptions *options = NULL;
	FridaApplicationList *apps = NULL;

	manager = frida_device_manager_new();
	if (!manager) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida device manager");
		goto cleanup;
	}

	device = backend_resolve_device(manager, uri, RZ_FRIDA_DEFAULT_TIMEOUT_MS, NULL, &error);
	if (!device) {
		rz_frida_json_error(pj, backend_error_code(NULL, error),
			error ? error->message : "cannot open the Frida device");
		goto cleanup;
	}

	options = frida_application_query_options_new();
	if (!options) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida application query options");
		goto cleanup;
	}

	apps = frida_device_enumerate_applications_sync(device, options, NULL, &error);
	if (!apps) {
		rz_frida_json_error(pj, backend_error_code(NULL, error),
			error ? error->message : "cannot enumerate applications");
		goto cleanup;
	}

	rz_frida_json_ok_begin(pj);
	pj_ka(pj, "apps");
	const gint count = frida_application_list_size(apps);
	for (gint i = 0; i < count; i++) {
		FridaApplication *app = frida_application_list_get(apps, i);
		if (!app) {
			continue;
		}
		pj_o(pj);
		pj_ks(pj, "identifier", frida_application_get_identifier(app));
		pj_ks(pj, "name", frida_application_get_name(app));
		pj_kn(pj, "pid", frida_application_get_pid(app));
		pj_end(pj);
		g_object_unref(app);
	}
	pj_end(pj);
	rz_frida_json_ok_end(pj);
	ok = true;

cleanup:
	if (error) {
		g_error_free(error);
	}
	if (apps) {
		frida_unref(apps);
	}
	if (options) {
		frida_unref(options);
	}
	if (device) {
		frida_unref(device);
	}
	if (manager) {
		frida_device_manager_close_sync(manager, NULL, NULL);
		frida_unref(manager);
	}
	return ok;
}

typedef struct rz_frida_backend_session_t {
	FridaDeviceManager *manager;
	FridaDevice *device;
	FridaSession *session;
	GCancellable *cancellable;
	guint pid;
	bool spawned;
	bool resumed;
	FridaScript *script; ///< Loaded agent script, or NULL until first use.
	gulong message_handler; ///< Handler id for the script message signal, or 0.
	RzFridaPending *pending; ///< Ids of requests still awaiting a reply.
	ut64 await_id; ///< Request id the active drain waits for, 0 when idle.
	bool reply_ready; ///< Set when the awaited reply has been captured.
	RzFridaResponse reply; ///< Captured reply, owned while reply_ready is set.
	RzFridaMsgBuf *messages; ///< Async agent output not tied to a request.
	GMutex lock; ///< Guards reply state and the async message buffer.
	GCond reply_cond; ///< Signaled when reply_ready becomes true.
} RzFridaBackendSession;

static void backend_script_teardown(RzFridaBackendSession *backend);

static void backend_session_dispose(RzFridaSession *session) {
	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		return;
	}
	rz_frida_session_set_cancel_hook(session, NULL, NULL);
	// unload the agent while the session is still attached, then free the registry.
	backend_script_teardown(backend);
	rz_frida_pending_free(backend->pending);
	rz_frida_msgbuf_free(backend->messages);
	if (backend->session) {
		if (!frida_session_is_detached(backend->session)) {
			frida_session_detach_sync(backend->session, NULL, NULL);
		}
		frida_unref(backend->session);
	}
	if (backend->device) {
		// kill a spawned target we never resumed, else it stays suspended.
		if (backend->spawned && !backend->resumed) {
			frida_device_kill_sync(backend->device, backend->pid, NULL, NULL);
		}
		frida_unref(backend->device);
	}
	if (backend->manager) {
		frida_device_manager_close_sync(backend->manager, NULL, NULL);
		frida_unref(backend->manager);
	}
	if (backend->cancellable) {
		g_object_unref(backend->cancellable);
	}
	g_cond_clear(&backend->reply_cond);
	g_mutex_clear(&backend->lock);
	RZ_FREE(backend);
}

static void backend_cancel_hook(void *user) {
	if (user) {
		g_cancellable_cancel((GCancellable *)user);
	}
}

static RzFridaError backend_error_code(GCancellable *cancellable, GError *error) {
	if (cancellable && g_cancellable_is_cancelled(cancellable)) {
		return RZ_FRIDA_ERROR_CANCELLED;
	}
	if (error && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		return RZ_FRIDA_ERROR_CANCELLED;
	}
	if (error && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT)) {
		return RZ_FRIDA_ERROR_TIMEOUT;
	}
	if (error && g_error_matches(error, FRIDA_ERROR, FRIDA_ERROR_TIMED_OUT)) {
		return RZ_FRIDA_ERROR_TIMEOUT;
	}
	if (error && (g_error_matches(error, FRIDA_ERROR, FRIDA_ERROR_PROCESS_NOT_FOUND) ||
			g_error_matches(error, FRIDA_ERROR, FRIDA_ERROR_EXECUTABLE_NOT_FOUND) ||
			g_error_matches(error, FRIDA_ERROR, FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED))) {
		return RZ_FRIDA_ERROR_INVALID_TARGET;
	}
	return RZ_FRIDA_ERROR_INTERNAL;
}

static bool backend_resolve_pid(FridaDevice *device, const RzFridaUri *uri, GCancellable *cancellable, guint *pid, GError **error) {
	rz_return_val_if_fail(device && uri && pid, false);

	ut32 numeric = 0;
	if (rz_frida_uri_target_pid(uri->target, &numeric)) {
		*pid = numeric;
		return true;
	}
	FridaProcessMatchOptions *options = frida_process_match_options_new();
	if (!options) {
		return false;
	}
	// 0 match timeout, unknown names fail directly
	frida_process_match_options_set_timeout(options, 0);
	FridaProcess *process = frida_device_get_process_by_name_sync(device, uri->target, options, cancellable, error);
	frida_unref(options);
	if (!process) {
		return false;
	}
	*pid = frida_process_get_pid(process);
	g_object_unref(process);
	return true;
}

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
RZ_IPI bool rz_frida_backend_open(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	const RzFridaUri *uri = rz_frida_session_uri(session);
	if (!uri) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "session has no URI");
		return false;
	}
	switch (uri->action_type) {
	case RZ_FRIDA_ACTION_ATTACH:
	case RZ_FRIDA_ACTION_SPAWN:
	case RZ_FRIDA_ACTION_LAUNCH:
		break;
	default:
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "URI action cannot open a session");
		return false;
	}

	bool ok = false;
	GError *error = NULL;
	GCancellable *cancellable = NULL;
	FridaDeviceManager *manager = NULL;
	FridaDevice *device = NULL;
	FridaSession *frida_session = NULL;
	FridaSpawnOptions *spawn_options = NULL;
	RzFridaBackendSession *backend = NULL;
	guint pid = 0;
	bool spawned = false;
	bool resumed = false;

	cancellable = g_cancellable_new();
	if (!cancellable) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create the cancellable");
		goto cleanup;
	}

	rz_frida_session_set_cancel_hook(session, cancellable, backend_cancel_hook);
	if (rz_frida_session_is_cancelled(session)) {
		g_cancellable_cancel(cancellable);
	}

	manager = frida_device_manager_new();
	if (!manager) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida device manager");
		goto cleanup;
	}

	device = backend_resolve_device(manager, uri, (gint)rz_frida_session_timeout(session), cancellable, &error);
	if (!device) {
		rz_frida_json_error(pj, backend_error_code(cancellable, error),
			error ? error->message : "cannot open the Frida device");
		goto cleanup;
	}

	if (uri->action_type == RZ_FRIDA_ACTION_ATTACH) {
		if (!backend_resolve_pid(device, uri, cancellable, &pid, &error)) {
			rz_frida_json_error(pj, backend_error_code(cancellable, error),
				error ? error->message : "cannot resolve the attach target");
			goto cleanup;
		}
	} else {
		spawn_options = frida_spawn_options_new();
		if (!spawn_options) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create Frida spawn options");
			goto cleanup;
		}
		pid = frida_device_spawn_sync(device, uri->target, spawn_options, cancellable, &error);
		if (error) {
			rz_frida_json_error(pj, backend_error_code(cancellable, error),
				error->message ? error->message : "cannot spawn the target");
			goto cleanup;
		}
		spawned = true;
	}

	frida_session = frida_device_attach_sync(device, pid, NULL, cancellable, &error);
	if (!frida_session) {
		rz_frida_json_error(pj, backend_error_code(cancellable, error),
			error ? error->message : "cannot attach to the target");
		goto cleanup;
	}

	if (uri->action_type == RZ_FRIDA_ACTION_LAUNCH) {
		frida_device_resume_sync(device, pid, cancellable, &error);
		if (error) {
			rz_frida_json_error(pj, backend_error_code(cancellable, error),
				error->message ? error->message : "cannot resume the launched target");
			goto cleanup;
		}
		resumed = true;
	}

	backend = RZ_NEW0(RzFridaBackendSession);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate backend session state");
		goto cleanup;
	}
	g_mutex_init(&backend->lock);
	g_cond_init(&backend->reply_cond);
	backend->manager = manager;
	backend->device = device;
	backend->session = frida_session;
	backend->cancellable = cancellable;
	backend->pid = pid;
	backend->spawned = spawned;
	backend->resumed = resumed;

	rz_frida_session_set_backend_state(session, backend, backend_session_dispose);
	rz_frida_session_set_target_pid(session, (ut32)pid);
	rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_ATTACHED);

	rz_frida_json_ok_begin(pj);
	pj_ks(pj, "action", uri->action);
	pj_kn(pj, "pid", pid);
	pj_kb(pj, "resumed", resumed);
	pj_ks(pj, "state", rz_frida_session_state_string(rz_frida_session_state(session)));
	rz_frida_json_ok_end(pj);

	// the session owns these now, so the cleanup path shouldnt touch them.
	manager = NULL;
	device = NULL;
	frida_session = NULL;
	cancellable = NULL;
	ok = true;

cleanup:
	if (error) {
		g_error_free(error);
	}
	if (spawn_options) {
		frida_unref(spawn_options);
	}
	if (frida_session) {
		frida_session_detach_sync(frida_session, NULL, NULL);
		frida_unref(frida_session);
	}
	if (!ok && spawned && device) {
		frida_device_kill_sync(device, pid, NULL, NULL);
	}
	if (device) {
		frida_unref(device);
	}
	if (manager) {
		frida_device_manager_close_sync(manager, NULL, NULL);
		frida_unref(manager);
	}
	if (cancellable) {
		// failed open, clear hook before releasing cancellable
		rz_frida_session_set_cancel_hook(session, NULL, NULL);
		g_object_unref(cancellable);
	}
	return ok;
}

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
RZ_IPI bool rz_frida_backend_resume(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "session has no backend state");
		return false;
	}
	if (!backend->spawned) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "session was attached and has nothing to resume");
		return false;
	}
	if (backend->resumed) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "session has already been resumed");
		return false;
	}

	if (backend->cancellable) {
		g_cancellable_reset(backend->cancellable);
	}
	GError *error = NULL;
	frida_device_resume_sync(backend->device, backend->pid, backend->cancellable, &error);
	if (error) {
		rz_frida_json_error(pj, backend_error_code(backend->cancellable, error),
			error->message ? error->message : "cannot resume the target");
		g_error_free(error);
		return false;
	}
	backend->resumed = true;

	rz_frida_json_ok_begin(pj);
	pj_kn(pj, "pid", backend->pid);
	pj_kb(pj, "resumed", true);
	pj_ks(pj, "state", rz_frida_session_state_string(rz_frida_session_state(session)));
	rz_frida_json_ok_end(pj);
	return true;
}

/**
 * \brief Detach the open session and report it as closed.
 *
 * Detaches from the target and writes an ok:true envelope carrying the pid and
 * final state. The caller frees the session afterwards, which kills a target
 * that was spawned but never resumed and releases the remaining handles. When
 * the plugin is built without frida-core, a self-contained implementation
 * reports \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the backend handles to detach.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the session was closed, false on any error.
 */
RZ_IPI bool rz_frida_backend_close(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "session has no backend state");
		return false;
	}

	rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_DETACHING);
	if (backend->cancellable) {
		g_cancellable_reset(backend->cancellable);
	}
	GError *error = NULL;
	if (backend->session && !frida_session_is_detached(backend->session)) {
		frida_session_detach_sync(backend->session, backend->cancellable, &error);
		if (error) {
			rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_ERROR);
			rz_frida_json_error(pj, backend_error_code(backend->cancellable, error),
				error->message ? error->message : "cannot detach from the target");
			g_error_free(error);
			return false;
		}
	}
	rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_CLOSED);

	rz_frida_json_ok_begin(pj);
	pj_kn(pj, "pid", backend->pid);
	pj_ks(pj, "state", rz_frida_session_state_string(rz_frida_session_state(session)));
	rz_frida_json_ok_end(pj);
	return true;
}

static void backend_script_teardown(RzFridaBackendSession *backend) {
	if (!backend) {
		return;
	}
	if (backend->script && backend->message_handler) {
		g_signal_handler_disconnect(backend->script, backend->message_handler);
	}
	backend->message_handler = 0;
	g_mutex_lock(&backend->lock);
	backend->await_id = 0;
	backend->reply_ready = false;
	rz_frida_response_fini(&backend->reply);
	g_cond_broadcast(&backend->reply_cond);
	g_mutex_unlock(&backend->lock);
	if (backend->script) {
		if (!frida_script_is_destroyed(backend->script)) {
			frida_script_unload_sync(backend->script, NULL, NULL);
		}
		frida_unref(backend->script);
		backend->script = NULL;
	}
}

// match an agent msg to the in-flight req or buffer it as async output.
static void backend_on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user) {
	(void)script;
	RzFridaBackendSession *backend = user;
	if (!backend || !message) {
		return;
	}
	RzFridaAgentMessage parsed = { 0 };
	if (!rz_frida_agent_message_parse(message, &parsed)) {
		return;
	}
	g_mutex_lock(&backend->lock);
	// send may answer in-flight req, capture it as reply.
	if (parsed.kind == RZ_FRIDA_AGENT_MESSAGE_SEND && parsed.payload) {
		RzFridaResponse response = { 0 };
		if (rz_frida_response_parse(parsed.payload, &response)) {
			if (response.id == backend->await_id && rz_frida_pending_take(backend->pending, response.id)) {
				rz_frida_response_fini(&backend->reply);
				backend->reply = response;
				backend->reply_ready = true;
				rz_mem_memzero(&response, sizeof(response));
				g_cond_signal(&backend->reply_cond);
				g_mutex_unlock(&backend->lock);
				rz_frida_agent_message_fini(&parsed);
				return;
			}
			rz_frida_response_fini(&response);
		}
	}
	// anything else is async script output, keep it with its binary data.
	if (data) {
		gsize size = 0;
		gconstpointer bytes = g_bytes_get_data(data, &size);
		if (bytes && size > 0) {
			parsed.data = rz_buf_new_with_bytes(bytes, size);
		}
	}
	if (!backend->messages || !rz_frida_msgbuf_push(backend->messages, &parsed)) {
		rz_frida_agent_message_fini(&parsed);
	}
	g_mutex_unlock(&backend->lock);
}

typedef enum {
	BACKEND_DRAIN_REPLY = 0,
	BACKEND_DRAIN_TIMEOUT,
	BACKEND_DRAIN_CANCELLED,
	BACKEND_DRAIN_GONE,
} BackendDrainResult;

// wait until reply lands, deadline passes, or caller cancels.
static BackendDrainResult backend_drain_reply(RzFridaBackendSession *backend, RzFridaSession *session, ut64 timeout_ms) {
	const gint64 deadline = g_get_monotonic_time() + (gint64)timeout_ms * 1000;
	BackendDrainResult result = BACKEND_DRAIN_TIMEOUT;

	g_mutex_lock(&backend->lock);
	while (!backend->reply_ready) {
		if (rz_frida_session_is_cancelled(session) ||
			(backend->cancellable && g_cancellable_is_cancelled(backend->cancellable))) {
			result = BACKEND_DRAIN_CANCELLED;
			goto beach;
		}
		if (!backend->script || frida_script_is_destroyed(backend->script)) {
			result = BACKEND_DRAIN_GONE;
			goto beach;
		}
		const gint64 now = g_get_monotonic_time();
		if (now >= deadline) {
			result = BACKEND_DRAIN_TIMEOUT;
			goto beach;
		}
		// wake atleast every poll interval so cancel & destroyed script are seen before deadline.
		gint64 wake = now + (gint64)RZ_FRIDA_DRAIN_POLL_MS * 1000;
		if (wake > deadline) {
			wake = deadline;
		}
		g_cond_wait_until(&backend->reply_cond, &backend->lock, wake);
	}
	result = BACKEND_DRAIN_REPLY;

beach:
	g_mutex_unlock(&backend->lock);
	return result;
}

// post a {id, type, params} req and block for the matching reply, moved into *out on success.
static bool backend_request(RzFridaBackendSession *backend, RzFridaSession *session,
	const char *type, const char *params_json, RzFridaResponse *out, RzFridaError *fail_code, const char **fail_msg) {
	ut64 id = rz_frida_pending_next_id(backend->pending);

	PJ *request = pj_new();
	if (!request) {
		*fail_code = RZ_FRIDA_ERROR_INTERNAL;
		*fail_msg = "cannot build the request";
		return false;
	}
	pj_o(request);
	pj_kn(request, "id", id);
	pj_ks(request, "type", type);
	if (RZ_STR_ISNOTEMPTY(params_json)) {
		pj_k(request, "params");
		pj_raw(request, params_json);
	}
	pj_end(request);
	char *request_json = pj_drain(request);
	if (!request_json) {
		*fail_code = RZ_FRIDA_ERROR_INTERNAL;
		*fail_msg = "cannot build the request";
		return false;
	}

	g_mutex_lock(&backend->lock);
	if (!rz_frida_pending_add(backend->pending, id)) {
		g_mutex_unlock(&backend->lock);
		free(request_json);
		*fail_code = RZ_FRIDA_ERROR_INTERNAL;
		*fail_msg = "cannot track the request";
		return false;
	}
	backend->await_id = id;
	backend->reply_ready = false;
	rz_frida_response_fini(&backend->reply);
	g_mutex_unlock(&backend->lock);

	frida_script_post(backend->script, request_json, NULL);
	free(request_json);

	BackendDrainResult drained = backend_drain_reply(backend, session, rz_frida_session_timeout(session));

	g_mutex_lock(&backend->lock);
	backend->await_id = 0;
	if (drained != BACKEND_DRAIN_REPLY) {
		// drop the in-flight id, a late reply for it is ignored after this.
		rz_frida_pending_take(backend->pending, id);
		backend->reply_ready = false;
		g_mutex_unlock(&backend->lock);
		switch (drained) {
		case BACKEND_DRAIN_CANCELLED:
			*fail_code = RZ_FRIDA_ERROR_CANCELLED;
			*fail_msg = "the request was cancelled";
			break;
		case BACKEND_DRAIN_GONE:
			*fail_code = RZ_FRIDA_ERROR_INTERNAL;
			*fail_msg = "the agent script is no longer loaded";
			break;
		case BACKEND_DRAIN_TIMEOUT:
		default:
			*fail_code = RZ_FRIDA_ERROR_TIMEOUT;
			*fail_msg = "the request timed out";
			break;
		}
		return false;
	}

	*out = backend->reply;
	rz_mem_memzero(&backend->reply, sizeof(backend->reply));
	backend->reply_ready = false;
	g_mutex_unlock(&backend->lock);
	return true;
}

// fwd the agent reply as our envelope, the agent's obj becomes the result body as is.
static bool backend_emit_response(PJ *pj, const RzFridaResponse *response) {
	if (!response->ok) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL,
			response->error ? response->error : "the agent reported an error");
		return false;
	}
	pj_o(pj);
	pj_kb(pj, "ok", true);
	pj_k(pj, "result");
	if (response->result) {
		pj_raw(pj, response->result);
	} else {
		pj_o(pj);
		pj_end(pj);
	}
	pj_end(pj);
	return true;
}

// create and load the agent script once per session, reload if died.
static bool backend_ensure_script(RzFridaBackendSession *backend, RzFridaSession *session, PJ *pj) {
	// start each req with a clean cancellation state.
	if (backend->cancellable) {
		g_cancellable_reset(backend->cancellable);
	}
	rz_frida_session_reset_cancel(session);
	if (backend->script && !frida_script_is_destroyed(backend->script)) {
		return true;
	}
	if (backend->script) {
		// died, so drop before reload.
		backend_script_teardown(backend);
	}
	if (!backend->session || frida_session_is_detached(backend->session)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "the session is not attached");
		return false;
	}
	if (!backend->pending) {
		backend->pending = rz_frida_pending_new();
		if (!backend->pending) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate the request registry");
			return false;
		}
	}
	if (!backend->messages) {
		backend->messages = rz_frida_msgbuf_new(0);
		if (!backend->messages) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate the message buffer");
			return false;
		}
	}
	GError *error = NULL;
	FridaScriptOptions *options = frida_script_options_new();
	if (!options) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot create the script options");
		return false;
	}
	frida_script_options_set_name(options, "rzfrida");
	// embedded agent is unsigned byte array, frida needs c string.
	FridaScript *script = frida_session_create_script_sync(backend->session, (const char *)rz_frida_agent_source, options, backend->cancellable, &error);
	frida_unref(options);
	if (!script) {
		rz_frida_json_error(pj, backend_error_code(backend->cancellable, error),
			error ? error->message : "cannot create the agent script");
		if (error) {
			g_error_free(error);
		}
		return false;
	}

	gulong handler = g_signal_connect(script, "message", G_CALLBACK(backend_on_message), backend);
	frida_script_load_sync(script, backend->cancellable, &error);
	if (error) {
		rz_frida_json_error(pj, backend_error_code(backend->cancellable, error),
			error->message ? error->message : "cannot load the agent script");
		g_signal_handler_disconnect(script, handler);
		frida_unref(script);
		g_error_free(error);
		return false;
	}

	backend->script = script;
	backend->message_handler = handler;
	return true;
}

/**
 * \brief Evaluate a JavaScript snippet inside the target through the agent.
 *
 * Loads the agent on first use, sends an eval request, and writes an ok:true
 * envelope carrying the value and its type, or an ok:false envelope on
 * timeout, cancel, or an agent error. When the plugin is built without
 * frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param source JavaScript expression to evaluate.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied with a result, false on any error.
 */
RZ_IPI bool rz_frida_backend_eval(RzFridaSession *session, const char *source, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	if (!RZ_STR_ISNOTEMPTY(source)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "missing script source");
		return false;
	}
	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	PJ *params = pj_new();
	if (!params) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}
	pj_o(params);
	pj_ks(params, "source", source);
	pj_end(params);
	char *params_json = pj_drain(params);
	if (!params_json) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot build the request");
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "eval", params_json, &response, &fail_code, &fail_msg);
	free(params_json);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Ping the agent loaded in the target and report what it sees.
 *
 * Loads the agent on first use, sends a ping request, and writes an ok:true
 * envelope carrying the agent version and the target platform, architecture,
 * and pointer size, or an ok:false envelope on timeout, cancel, or an agent
 * error. This doubles as a round-trip check of the host-agent message channel.
 * When the plugin is built without frida-core, a self-contained implementation
 * reports \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the agent replied, false on any error.
 */
RZ_IPI bool rz_frida_backend_ping(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	if (!backend_ensure_script(backend, session, pj)) {
		return false;
	}

	RzFridaResponse response = { 0 };
	RzFridaError fail_code = RZ_FRIDA_ERROR_INTERNAL;
	const char *fail_msg = NULL;
	bool got = backend_request(backend, session, "ping", NULL, &response, &fail_code, &fail_msg);
	if (!got) {
		rz_frida_json_error(pj, fail_code, fail_msg);
		return false;
	}
	bool ok = backend_emit_response(pj, &response);
	rz_frida_response_fini(&response);
	return ok;
}

/**
 * \brief Drain the asynchronous messages captured from the injected agent.
 *
 * Writes the buffered console output, script errors, and unsolicited send()
 * notifications as a JSON array and clears the buffer. When the plugin is built
 * without frida-core, a self-contained implementation reports
 * \ref RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE instead.
 *
 * \param session Session holding the attached backend handles.
 * \param pj JSON builder that receives the reply envelope.
 * \return true when the buffer was drained into an ok envelope.
 */
RZ_IPI bool rz_frida_backend_messages(RZ_NONNULL RZ_BORROW RzFridaSession *session, RZ_NONNULL RZ_BORROW PJ *pj) {
	rz_return_val_if_fail(session && pj, false);

	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return false;
	}
	rz_frida_json_ok_begin(pj);
	g_mutex_lock(&backend->lock);
	if (backend->messages) {
		rz_frida_msgbuf_drain_json(backend->messages, pj);
	} else {
		pj_ka(pj, "messages");
		pj_end(pj);
		pj_kn(pj, "dropped", 0);
	}
	g_mutex_unlock(&backend->lock);
	rz_frida_json_ok_end(pj);
	return true;
}
