// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>
#include "minunit.h"

static bool test_devices_unavailable(void) {
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_devices_json(pj), "device enumeration fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	mu_end;
}

static bool test_processes_unavailable(void) {
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_processes_json(pj), "process enumeration fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_devices_unavailable);
	mu_run_test(test_processes_unavailable);
	return tests_passed != tests_run;
}

mu_main(all_tests)
