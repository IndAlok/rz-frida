// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_lib.h>
#include <rz_types.h>

#undef RZ_API
#define RZ_API static
#undef RZ_IPI
#define RZ_IPI static

static const RzCmdDescHelp cmd_frida_help = {
	.summary = "Interact with Frida targets",
};

RZ_IPI RzCmdStatus rz_cmd_frida_handler(RzCore *core, int argc, const char **argv) {
	(void)core;
	(void)argc;
	(void)argv;
	RZ_LOG_INFO("rz-frida skeleton loaded; implementation is in progress\n");
	return RZ_CMD_STATUS_OK;
}

static bool rz_frida_plugin_init(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		return false;
	}

	RzCmdDesc *cd = rz_cmd_desc_argv_new(rcmd, root_cd, "frida", rz_cmd_frida_handler, &cmd_frida_help);
	if (!cd) {
		rz_warn_if_reached();
		return false;
	}

	return true;
}

static bool rz_frida_plugin_fini(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *desc = rz_cmd_get_desc(rcmd, "frida");
	return !desc || rz_cmd_desc_remove(rcmd, desc);
}

RzCorePlugin rz_core_plugin_frida = {
	.name = "rz_frida",
	.desc = "Frida integration for Rizin",
	.license = "LGPL-3.0",
	.author = "Alok Kumar Mishra",
	.version = "0.1.0",
	.init = rz_frida_plugin_init,
	.fini = rz_frida_plugin_fini,
};

#ifdef _MSC_VER
#define RZ_EXPORT __declspec(dllexport)
#else
#define RZ_EXPORT
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_EXPORT RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_frida,
	.version = RZ_VERSION,
};
#endif

