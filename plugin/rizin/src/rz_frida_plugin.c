// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_frida.h>
#include <rz_lib.h>
#include <rz_types.h>
#include <cmd_descs.h>

extern RzCorePlugin rz_core_plugin_frida;

typedef struct rz_frida_core_context_t {
	RzCmdDesc *cmd_desc;
	RzFridaSession *session;
} RzFridaCoreContext;

static RzFridaCoreContext *frida_context(RzCore *core) {
	rz_return_val_if_fail(core, NULL);
	return (RzFridaCoreContext *)rz_core_plugin_context_get(core, &rz_core_plugin_frida);
}

static RzCmdStatus print_status(RzCore *core, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, RZ_CMD_STATUS_ERROR);

	RzFridaCoreContext *ctx = frida_context(core);
	const RzFridaSession *session = ctx ? ctx->session : NULL;
	const bool active = session != NULL;
	const char *state_string = session ? rz_frida_session_state_string(rz_frida_session_state(session)) : "closed";

	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("active: %s\n", rz_str_bool(active));
		rz_cons_printf("state: %s\n", state_string);
		return RZ_CMD_STATUS_OK;
	case RZ_OUTPUT_MODE_JSON:
		rz_frida_json_ok_begin(state->d.pj);
		pj_kb(state->d.pj, "active", active);
		pj_ks(state->d.pj, "state", state_string);
		rz_frida_json_ok_end(state->d.pj);
		return RZ_CMD_STATUS_OK;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
}

static RzCmdStatus print_uri(const char *uri_string, RzCmdStateOutput *state) {
	rz_return_val_if_fail(state, RZ_CMD_STATUS_ERROR);

	RzFridaUri uri = { 0 };

	// JSON replies accumulate in the state buffer, which RzCmd only prints when the
	// handler returns RZ_CMD_STATUS_OK. We return OK after writing an error envelope so
	// the ok:false reply still reaches the caller and plain text reports errors via the log.
	if (!RZ_STR_ISNOTEMPTY(uri_string)) {
		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			rz_frida_json_error(state->d.pj, RZ_FRIDA_ERROR_INVALID_URI, "missing URI");
			return RZ_CMD_STATUS_OK;
		}
		RZ_LOG_ERROR("missing URI\n");
		return RZ_CMD_STATUS_INVALID;
	}

	if (!rz_frida_uri_parse(uri_string, &uri)) {
		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			rz_frida_json_error(state->d.pj, RZ_FRIDA_ERROR_INVALID_URI, "invalid Frida URI");
			return RZ_CMD_STATUS_OK;
		}
		RZ_LOG_ERROR("invalid Frida URI\n");
		return RZ_CMD_STATUS_INVALID;
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("action: %s\n", uri.action);
		rz_cons_printf("transport: %s\n", uri.transport);
		rz_cons_printf("device: %s\n", uri.device);
		rz_cons_printf("target: %s\n", uri.target);
		break;
	case RZ_OUTPUT_MODE_JSON:
		rz_frida_json_ok_begin(state->d.pj);
		pj_ks(state->d.pj, "action", uri.action);
		pj_ks(state->d.pj, "transport", uri.transport);
		pj_ks(state->d.pj, "device", uri.device);
		pj_ks(state->d.pj, "target", uri.target);
		rz_frida_json_ok_end(state->d.pj);
		break;
	default:
		rz_frida_uri_fini(&uri);
		rz_warn_if_reached();
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	rz_frida_uri_fini(&uri);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridas_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	return print_status(core, state);
}

RZ_IPI RzCmdStatus rz_cmd_fridau_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	return print_uri(argv[1], state);
}

RZ_IPI RzCmdStatus rz_cmd_fridad_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	// rz_frida_devices_json always writes a JSON envelope (ok:true with devices, or
	// ok:false on failure). Return OK either way so RzCmd prints the envelope and the
	// ok flag inside carries the outcome to scripts and Cutter.
	rz_frida_devices_json(state->d.pj);
	return RZ_CMD_STATUS_OK;
}

static RzFridaCoreContext *frida_context_new(void) {
	return RZ_NEW0(RzFridaCoreContext);
}

static void frida_context_free(RzFridaCoreContext *ctx) {
	if (!ctx) {
		return;
	}
	rz_frida_session_free(ctx->session);
	RZ_FREE(ctx);
}

static bool rz_frida_plugin_init(RzCore *core, void **user) {
	rz_return_val_if_fail(core && core->rcmd && user, false);

	RzFridaCoreContext *ctx = frida_context_new();
	if (!ctx) {
		return false;
	}

	// The cmd tree is there in src/cmd_descs/cmd_descs.yaml and emitted by
	// Rizin's cmd_descs_generate.py into cmd_descs.c. rzshell_cmddescs_init registers
	// the frida group and its subcmds under the cmd root, and we keep the group
	// descriptor so fini can detach the whole subtree.
	rzshell_cmddescs_init(core);
	ctx->cmd_desc = rz_cmd_get_desc(core->rcmd, "frida");
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
	rz_return_val_if_fail(ctx, false);
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
