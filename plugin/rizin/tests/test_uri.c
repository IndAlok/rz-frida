// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <assert.h>

int main(void) {
	RzFridaUri uri = { 0 };

	assert(rz_frida_uri_parse("frida://attach/local//1234", &uri));
	assert(uri.action_type == RZ_FRIDA_ACTION_ATTACH);
	assert(uri.transport_type == RZ_FRIDA_TRANSPORT_LOCAL);
	assert(RZ_STR_EQ(uri.action, "attach"));
	assert(RZ_STR_EQ(uri.transport, "local"));
	assert(RZ_STR_EQ(uri.device, ""));
	assert(RZ_STR_EQ(uri.target, "1234"));
	rz_frida_uri_fini(&uri);

	assert(rz_frida_uri_parse("frida://spawn/usb/device-1/com.example.app", &uri));
	assert(uri.action_type == RZ_FRIDA_ACTION_SPAWN);
	assert(uri.transport_type == RZ_FRIDA_TRANSPORT_USB);
	assert(RZ_STR_EQ(uri.action, "spawn"));
	assert(RZ_STR_EQ(uri.transport, "usb"));
	assert(RZ_STR_EQ(uri.device, "device-1"));
	assert(RZ_STR_EQ(uri.target, "com.example.app"));
	rz_frida_uri_fini(&uri);

	assert(rz_frida_uri_parse("frida://list/local//", &uri));
	assert(uri.action_type == RZ_FRIDA_ACTION_LIST);
	assert(RZ_STR_EQ(uri.target, ""));
	rz_frida_uri_fini(&uri);

	assert(rz_frida_uri_parse("frida://launch/local///bin/ls", &uri));
	assert(RZ_STR_EQ(uri.target, "/bin/ls"));
	rz_frida_uri_fini(&uri);

	assert(rz_frida_uri_parse("frida://attach/remote/127.0.0.1:27042/4321", &uri));
	assert(uri.transport_type == RZ_FRIDA_TRANSPORT_REMOTE);
	assert(RZ_STR_EQ(uri.device, "127.0.0.1:27042"));
	rz_frida_uri_fini(&uri);

	assert(RZ_STR_EQ(rz_frida_action_string(RZ_FRIDA_ACTION_APPS), "apps"));
	assert(rz_frida_action_from_string("launch") == RZ_FRIDA_ACTION_LAUNCH);
	assert(RZ_STR_EQ(rz_frida_transport_string(RZ_FRIDA_TRANSPORT_USB), "usb"));
	assert(rz_frida_transport_from_string("remote") == RZ_FRIDA_TRANSPORT_REMOTE);

	assert(!rz_frida_uri_parse("gdb://attach/local//1234", &uri));
	assert(!rz_frida_uri_parse("frida://", &uri));
	assert(!rz_frida_uri_parse("frida://attach/local//", &uri));
	assert(!rz_frida_uri_parse("frida://attach/usb//1234", &uri));
	assert(!rz_frida_uri_parse("frida://attach/remote/localhost/1234", &uri));
	assert(!rz_frida_uri_parse("frida://attach/other//1234", &uri));
	assert(!rz_frida_uri_parse("frida://other/local//1234", &uri));
	assert(!rz_frida_uri_parse("frida://attach/local/device/1234", &uri));

	return 0;
}
