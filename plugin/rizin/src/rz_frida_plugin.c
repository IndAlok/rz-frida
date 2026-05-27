// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_frida.h>
#include <rz_lib.h>
#include <rz_types.h>

#include <stdlib.h>
#include <string.h>

#undef RZ_API
#define RZ_API static
#undef RZ_IPI
#define RZ_IPI static

extern RzCorePlugin rz_core_plugin_frida;

typedef struct rz_frida_core_context_t {
	RzCmdDesc *cmd_desc;
	RzFridaSession *session;
} RzFridaCoreContext;

static const RzCmdDescArg cmd_frida_args[] = {
	{
		.name = "args",
		.optional = true,
		.type = RZ_CMD_ARG_TYPE_STRING,
		.flags = RZ_CMD_ARG_FLAG_ARRAY,
	},
	{ 0 },
};

static const RzCmdDescHelp cmd_frida_help = {
	.summary = "Interact with Frida targets",
	.usage = "frida [status|statusj|uri|urij|devicesj]",
	.args = cmd_frida_args,
};

static void print_pj(PJ *pj) {
	if (!pj) {
		return;
	}
	rz_cons_println(pj_string(pj));
	pj_free(pj);
}

static RzFridaCoreContext *frida_context(RzCore *core) {
	return core ? (RzFridaCoreContext *)rz_core_plugin_context_get(core, &rz_core_plugin_frida) : NULL;
}

static RzCmdStatus print_status(RzCore *core, bool json) {
	RzFridaCoreContext *ctx = frida_context(core);
	const RzFridaSession *session = ctx ? ctx->session : NULL;
	const bool active = session != NULL;
	const char *state = session ? rz_frida_session_state_string(rz_frida_session_state(session)) : "closed";

	if (json) {
		PJ *pj = pj_new();
		if (!pj) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_frida_json_ok_begin(pj);
		pj_kb(pj, "active", active);
		pj_ks(pj, "state", state);
		rz_frida_json_ok_end(pj);
		print_pj(pj);
		return RZ_CMD_STATUS_OK;
	}

	rz_cons_printf("active: %s\n", active ? "true" : "false");
	rz_cons_printf("state: %s\n", state);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus print_uri(const char *uri_string, bool json) {
	if (!uri_string || !*uri_string) {
		if (json) {
			PJ *pj = pj_new();
			if (!pj) {
				return RZ_CMD_STATUS_ERROR;
			}
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_URI, "missing URI");
			print_pj(pj);
		} else {
			RZ_LOG_ERROR("missing URI\n");
		}
		return RZ_CMD_STATUS_INVALID;
	}

	RzFridaUri uri = { 0 };
	if (!rz_frida_uri_parse(uri_string, &uri)) {
		if (json) {
			PJ *pj = pj_new();
			if (!pj) {
				return RZ_CMD_STATUS_ERROR;
			}
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_URI, "invalid Frida URI");
			print_pj(pj);
		} else {
			RZ_LOG_ERROR("invalid Frida URI\n");
		}
		return RZ_CMD_STATUS_INVALID;
	}

	if (json) {
		PJ *pj = pj_new();
		if (!pj) {
			rz_frida_uri_fini(&uri);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_frida_json_ok_begin(pj);
		pj_ks(pj, "action", uri.action);
		pj_ks(pj, "transport", uri.transport);
		pj_ks(pj, "device", uri.device);
		pj_ks(pj, "target", uri.target);
		rz_frida_json_ok_end(pj);
		print_pj(pj);
	} else {
		rz_cons_printf("action: %s\n", uri.action);
		rz_cons_printf("transport: %s\n", uri.transport);
		rz_cons_printf("device: %s\n", uri.device);
		rz_cons_printf("target: %s\n", uri.target);
	}

	rz_frida_uri_fini(&uri);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus print_devices_json(void) {
	PJ *pj = pj_new();
	if (!pj) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool ok = rz_frida_devices_json(pj);
	print_pj(pj);
	return ok ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_frida_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2 || !strcmp(argv[1], "status")) {
		return print_status(core, false);
	}
	if (!strcmp(argv[1], "statusj")) {
		return print_status(core, true);
	}
	if (!strcmp(argv[1], "uri")) {
		return argc == 3 ? print_uri(argv[2], false) : RZ_CMD_STATUS_WRONG_ARGS;
	}
	if (!strcmp(argv[1], "urij")) {
		return argc == 3 ? print_uri(argv[2], true) : RZ_CMD_STATUS_WRONG_ARGS;
	}
	if (!strcmp(argv[1], "devicesj")) {
		return argc == 2 ? print_devices_json() : RZ_CMD_STATUS_WRONG_ARGS;
	}
	return RZ_CMD_STATUS_WRONG_ARGS;
}

static RzFridaCoreContext *frida_context_new(void) {
	return RZ_NEW0(RzFridaCoreContext);
}

static void frida_context_free(RzFridaCoreContext *ctx) {
	if (!ctx) {
		return;
	}
	rz_frida_session_free(ctx->session);
	free(ctx);
}

static bool rz_frida_plugin_init(RzCore *core, void **user) {
	if (!core || !user) {
		return false;
	}

	RzFridaCoreContext *ctx = frida_context_new();
	if (!ctx) {
		return false;
	}
	ctx->cmd_desc = rz_core_plugin_cmd_desc_argv_new(core, "frida", rz_cmd_frida_handler, &cmd_frida_help);
	if (!ctx->cmd_desc) {
		frida_context_free(ctx);
		rz_warn_if_reached();
		return false;
	}

	*user = ctx;
	return true;
}

static bool rz_frida_plugin_fini(RzCore *core, void *user) {
	RzFridaCoreContext *ctx = user;
	if (!ctx) {
		return true;
	}
	bool ok = rz_core_plugin_cmd_desc_remove(core, ctx->cmd_desc);
	ctx->cmd_desc = NULL;
	frida_context_free(ctx);
	return ok;
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
