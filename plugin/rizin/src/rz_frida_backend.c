// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#ifndef RZ_FRIDA_HAVE_FRIDA_CORE
#define RZ_FRIDA_HAVE_FRIDA_CORE 0
#endif

#if RZ_FRIDA_HAVE_FRIDA_CORE
#include <frida-core.h>

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
#endif

#if RZ_FRIDA_HAVE_FRIDA_CORE
RZ_IPI bool rz_frida_devices_json(PJ *pj) {
	rz_return_val_if_fail(pj, false);

	bool ok = false;
	GError *error = NULL;
	FridaDeviceManager *manager = NULL;
	FridaDeviceList *devices = NULL;

	frida_init();

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
	frida_deinit();
	return ok;
}
#else
RZ_IPI bool rz_frida_devices_json(PJ *pj) {
	rz_return_val_if_fail(pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}
#endif
