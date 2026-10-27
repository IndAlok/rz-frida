#include <frida-core.h>
#include <stdio.h>

static void clear_error(GError **error) {
	if (*error) {
		g_printerr("error: %s\n", (*error)->message);
		g_error_free(*error);
		*error = NULL;
	}
}

int main(void) {
	frida_init();

	FridaDeviceManager *manager = frida_device_manager_new();
	if (!manager) {
		g_printerr("no manager\n");
		frida_deinit();
		return 2;
	}

	GError *error = NULL;
	g_print("usb lookup...\n");
	FridaDevice *usb = frida_device_manager_get_device_by_type_sync(manager, FRIDA_DEVICE_TYPE_USB, 5000, NULL, &error);
	g_print("usb lookup done: %s\n", usb ? "device" : "none");
	clear_error(&error);
	if (usb) {
		frida_unref(usb);
	}

	g_print("local lookup...\n");
	FridaDevice *local = frida_device_manager_get_device_by_type_sync(manager, FRIDA_DEVICE_TYPE_LOCAL, 5000, NULL, &error);
	g_print("local lookup done: %s\n", local ? "device" : "none");
	if (local) {
		g_print("attach invalid pid...\n");
		FridaSession *session = frida_device_attach_sync(local, 2147483647, NULL, NULL, &error);
		g_print("attach done: %s\n", session ? "session" : "none");
		clear_error(&error);
		if (session) {
			frida_unref(session);
		}
	}
	clear_error(&error);

	g_print("close manager...\n");
	frida_device_manager_close_sync(manager, NULL, NULL);
	frida_unref(manager);
	g_print("deinit...\n");
	frida_deinit();
	g_print("done\n");
	return 0;
}
