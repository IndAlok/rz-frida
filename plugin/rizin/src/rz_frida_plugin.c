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
	const RzFridaUri *uri = session ? rz_frida_session_uri(session) : NULL;

	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("active: %s\n", rz_str_bool(active));
		rz_cons_printf("state: %s\n", state_string);
		if (session) {
			rz_cons_printf("pid: %u\n", rz_frida_session_target_pid(session));
			rz_cons_printf("action: %s\n", uri->action);
			rz_cons_printf("target: %s\n", uri->target);
		}
		return RZ_CMD_STATUS_OK;
	case RZ_OUTPUT_MODE_JSON:
		rz_frida_json_ok_begin(state->d.pj);
		pj_kb(state->d.pj, "active", active);
		pj_ks(state->d.pj, "state", state_string);
		if (session) {
			pj_kn(state->d.pj, "pid", rz_frida_session_target_pid(session));
			pj_ks(state->d.pj, "action", uri->action);
			pj_ks(state->d.pj, "target", uri->target);
		}
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

static RzCmdStatus run_device_listing(int argc, const char **argv, RzCmdStateOutput *state,
	RzFridaAction action, bool (*list)(const RzFridaUri *uri, PJ *pj)) {
	rz_return_val_if_fail(argv && state && list, RZ_CMD_STATUS_ERROR);

	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	const char *uri_string = (argc > 1) ? argv[1] : NULL;
	if (!RZ_STR_ISNOTEMPTY(uri_string)) {
		list(NULL, pj);
		return RZ_CMD_STATUS_OK;
	}

	RzFridaUri uri = { 0 };
	if (!rz_frida_uri_parse(uri_string, &uri)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_URI, "invalid Frida URI");
		return RZ_CMD_STATUS_OK;
	}
	if (uri.action_type != action) {
		rz_frida_uri_fini(&uri);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_URI, "URI action does not match the command");
		return RZ_CMD_STATUS_OK;
	}
	list(&uri, pj);
	rz_frida_uri_fini(&uri);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridap_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	return run_device_listing(argc, argv, state, RZ_FRIDA_ACTION_LIST, rz_frida_processes_json);
}

RZ_IPI RzCmdStatus rz_cmd_fridaa_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	return run_device_listing(argc, argv, state, RZ_FRIDA_ACTION_APPS, rz_frida_apps_json);
}

RZ_IPI RzCmdStatus rz_cmd_fridao_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "frida plugin context is unavailable");
		return RZ_CMD_STATUS_OK;
	}
	if (ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "a session is already open");
		return RZ_CMD_STATUS_OK;
	}

	RzFridaUri uri = { 0 };
	if (!rz_frida_uri_parse(argv[1], &uri)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_URI, "invalid Frida URI");
		return RZ_CMD_STATUS_OK;
	}

	RzFridaSession *session = rz_frida_session_new();
	if (!session) {
		rz_frida_uri_fini(&uri);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate session");
		return RZ_CMD_STATUS_OK;
	}

	bool stored = rz_frida_session_set_uri(session, &uri);
	rz_frida_uri_fini(&uri);
	if (!stored) {
		rz_frida_session_free(session);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot store the session URI");
		return RZ_CMD_STATUS_OK;
	}

	// backend_open writes the envelope either way. only keep the session if it opened.
	if (!rz_frida_backend_open(session, pj)) {
		rz_frida_session_free(session);
		return RZ_CMD_STATUS_OK;
	}

	ctx->session = session;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridar_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_frida_backend_resume(ctx->session, pj);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridac_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	// close writes reply, free releases backend state and clears slot
	if (rz_frida_backend_close(ctx->session, pj)) {
		rz_frida_session_free(ctx->session);
		ctx->session = NULL;
	}
	return RZ_CMD_STATUS_OK;
}

// cancel in-flight agent req after Ctrl-C.
static void frida_cancel_on_break(void *user) {
	rz_frida_session_request_cancel((RzFridaSession *)user);
}

RZ_IPI RzCmdStatus rz_cmd_fridae_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_eval(ctx->session, argv[1], pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridal_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	char *source = rz_file_slurp(argv[1], NULL);
	if (!source) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "cannot read the script file");
		return RZ_CMD_STATUS_OK;
	}
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_eval(ctx->session, source, pj);
	rz_cons_break_pop();
	free(source);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridai_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_ping(ctx->session, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridam_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	rz_frida_backend_messages(ctx->session, pj);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridax_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	ut64 address = rz_num_math(core->num, argv[1]);
	ut64 size = rz_num_math(core->num, argv[2]);
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_mem_read(ctx->session, address, size, pj);
	rz_cons_break_pop();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_fridaw_handler(RzCore *core, RZ_UNUSED int argc, const char **argv, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && argv && state, RZ_CMD_STATUS_ERROR);
	if (state->mode != RZ_OUTPUT_MODE_JSON) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	PJ *pj = state->d.pj;
	RzFridaCoreContext *ctx = frida_context(core);
	if (!ctx || !ctx->session) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "no session is open");
		return RZ_CMD_STATUS_OK;
	}

	const char *hex = argv[2];
	int hexlen = strlen(hex);
	if (hexlen == 0 || (hexlen % 2)) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "expected an even-length hex byte string");
		return RZ_CMD_STATUS_OK;
	}
	ut8 *bytes = malloc(hexlen / 2);
	if (!bytes) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "cannot allocate the write buffer");
		return RZ_CMD_STATUS_OK;
	}
	int len = rz_hex_str2bin(hex, bytes);
	if (len < 1) {
		free(bytes);
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "invalid hex byte string");
		return RZ_CMD_STATUS_OK;
	}
	ut64 address = rz_num_math(core->num, argv[1]);
	rz_cons_break_push(frida_cancel_on_break, ctx->session);
	rz_frida_backend_mem_write(ctx->session, address, bytes, (size_t)len, pj);
	rz_cons_break_pop();
	free(bytes);
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

	// The cmd tree is there in src/cmd_descs/cmd_descs.yaml and emitted by
	// Rizin's cmd_descs_generate.py into cmd_descs.c. rzshell_cmddescs_init registers
	// the frida group and its subcmds under the cmd root, and we keep the group
	// descriptor so fini can detach the whole subtree.
	rz_frida_backend_init();

	*user = ctx;
	return true;
}

static bool rz_frida_plugin_fini(RzCore *core, void *user) {
	RzFridaCoreContext *ctx = user;
	rz_return_val_if_fail(core && ctx, false);
	bool ok = rz_core_plugin_cmd_desc_remove(core, ctx->cmd_desc);
	ctx->cmd_desc = NULL;
	frida_context_free(ctx);
	rz_frida_backend_deinit();
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
