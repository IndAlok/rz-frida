// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <assert.h>
#include <string.h>

int main(void) {
	RzFridaUri uri = { 0 };

	assert(rz_frida_uri_parse("frida://attach/local//1234", &uri));
	assert(!strcmp(uri.action, "attach"));
	assert(!strcmp(uri.transport, "local"));
	assert(!strcmp(uri.device, ""));
	assert(!strcmp(uri.target, "1234"));
	rz_frida_uri_fini(&uri);

	assert(rz_frida_uri_parse("frida://spawn/usb/device-1/com.example.app", &uri));
	assert(!strcmp(uri.action, "spawn"));
	assert(!strcmp(uri.transport, "usb"));
	assert(!strcmp(uri.device, "device-1"));
	assert(!strcmp(uri.target, "com.example.app"));
	rz_frida_uri_fini(&uri);

	assert(!rz_frida_uri_parse("gdb://attach/local//1234", &uri));
	assert(!rz_frida_uri_parse("frida://", &uri));

	return 0;
}

