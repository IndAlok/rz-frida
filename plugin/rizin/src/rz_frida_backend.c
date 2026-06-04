// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// Frida-backed device backend. meson compiles this translation unit only when
// frida-core is available and linkable, builds without frida-core compile
// rz_frida_backend_null.c in its place.

#include <rz_frida.h>

#include <frida-core.h>

RZ_IPI void rz_frida_backend_init(void) {
	frida_init();
}

RZ_IPI void rz_frida_backend_deinit(void) {
	frida_deinit();
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
} RzFridaBackendSession;

static void backend_session_dispose(RzFridaSession *session) {
	RzFridaBackendSession *backend = rz_frida_session_backend_state(session);
	if (!backend) {
		return;
	}
	rz_frida_session_set_cancel_hook(session, NULL, NULL);
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
