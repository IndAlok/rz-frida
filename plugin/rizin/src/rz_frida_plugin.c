// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_frida.h>
#include <rz_lib.h>
#include <rz_types.h>

#undef RZ_API
#define RZ_API static
#undef RZ_IPI
#define RZ_IPI static

extern RzCorePlugin rz_core_plugin_frida;

typedef struct rz_frida_core_context_t {
	RzCmdDesc *cmd_desc;
	RzFridaSession *session;
} RzFridaCoreContext;

static const RzCmdDescArg cmd_no_args[] = {
	{ 0 },
};

static const RzCmdDescDetailEntry cmd_frida_group_session_entries[] = {
	{ .text = "fridas", .arg_str = NULL, .comment = "Print plugin/session status in plain text" },
	{ .text = "fridasj", .arg_str = NULL, .comment = "Print plugin/session status as JSON" },
	{ 0 },
};

static const RzCmdDescDetailEntry cmd_frida_group_uri_entries[] = {
	{ .text = "fridau ", .arg_str = "frida://attach/local//1234", .comment = "Validate URI for attaching to local PID 1234" },
	{ .text = "fridau ", .arg_str = "frida://spawn/usb/device-1/com.example.app", .comment = "Validate URI for spawning an Android package over USB" },
	{ .text = "fridau ", .arg_str = "frida://attach/remote/127.0.0.1:27042/4321", .comment = "Validate URI for attaching to PID 4321 over remote frida-server" },
	{ .text = "fridauj ", .arg_str = "frida://launch/local///bin/ls", .comment = "Validate launch URI for /bin/ls and emit JSON" },
	{ 0 },
};

static const RzCmdDescDetailEntry cmd_frida_group_devices_entries[] = {
	{ .text = "fridadj", .arg_str = NULL, .comment = "Enumerate connected Frida devices as JSON" },
	{ 0 },
};

static const RzCmdDescDetail cmd_frida_group_details[] = {
	{ .name = "Session status", .entries = cmd_frida_group_session_entries },
	{ .name = "frida:// URI grammar", .entries = cmd_frida_group_uri_entries },
	{ .name = "Device enumeration", .entries = cmd_frida_group_devices_entries },
	{ 0 },
};

static const RzCmdDescHelp cmd_frida_group_help = {
	.summary = "Interact with Frida targets",
	.description = "Commands for the rz-frida integration covering plugin and session "
		       "status, frida:// URI validation, and Frida device enumeration.",
	.details = cmd_frida_group_details,
	.args = cmd_no_args,
};

static const RzCmdDescDetailEntry cmd_fridas_entries[] = {
	{ .text = "fridas", .arg_str = NULL, .comment = "active and state lines in plain text" },
	{ .text = "fridasj", .arg_str = NULL, .comment = "Same data wrapped in the rz-frida JSON envelope" },
	{ 0 },
};

static const RzCmdDescDetail cmd_fridas_details[] = {
	{ .name = "Examples", .entries = cmd_fridas_entries },
	{ 0 },
};

static const RzCmdDescHelp cmd_fridas_help = {
	.summary = "Print Frida session status",
	.description = "Reports whether a session is active and prints the current session state "
		       "(new, resolved, connecting, attached, detaching, closed, or error).",
	.details = cmd_fridas_details,
	.args = cmd_no_args,
};

static const RzCmdDescArg cmd_fridau_args[] = {
	{
		.name = "uri",
		.type = RZ_CMD_ARG_TYPE_STRING,
	},
	{ 0 },
};

static const RzCmdDescDetailEntry cmd_fridau_grammar_entries[] = {
	{ .text = "frida://", .arg_str = "<action>/<transport>/<device>/<target>", .comment = "Full grammar for the frida:// URI" },
	{ .text = "action   ", .arg_str = "= list | apps | attach | spawn | launch", .comment = "Operation requested for the session" },
	{ .text = "transport", .arg_str = "= local | usb | remote", .comment = "Transport used to reach the Frida target" },
	{ .text = "device   ", .arg_str = "= empty | device-id | host:port", .comment = "Empty for local, id for USB, host:port for remote" },
	{ .text = "target   ", .arg_str = "= pid | process-name | package-name | executable-path", .comment = "Target selector required by attach/spawn/launch" },
	{ 0 },
};

static const RzCmdDescDetailEntry cmd_fridau_example_entries[] = {
	{ .text = "fridau ", .arg_str = "frida://attach/local//1234", .comment = "Attach to local PID 1234" },
	{ .text = "fridau ", .arg_str = "frida://spawn/usb/device-1/com.example.app", .comment = "Spawn an Android package on a USB device" },
	{ .text = "fridau ", .arg_str = "frida://launch/local///bin/ls", .comment = "Launch /bin/ls locally (note the leading slash in the path)" },
	{ .text = "fridauj ", .arg_str = "frida://attach/remote/127.0.0.1:27042/4321", .comment = "Validate remote-attach URI and emit JSON" },
	{ 0 },
};

static const RzCmdDescDetail cmd_fridau_details[] = {
	{ .name = "frida:// URI grammar", .entries = cmd_fridau_grammar_entries },
	{ .name = "Examples", .entries = cmd_fridau_example_entries },
	{ 0 },
};

static const RzCmdDescHelp cmd_fridau_help = {
	.summary = "Validate a frida:// URI",
	.description = "Parses and validates a frida:// URI without contacting any Frida device. "
		       "Useful for verifying URI syntax in scripts or CI before attempting to attach.",
	.details = cmd_fridau_details,
	.args = cmd_fridau_args,
};

static const RzCmdDescDetailEntry cmd_fridad_entries[] = {
	{ .text = "fridadj", .arg_str = NULL, .comment = "List devices as JSON; returns a frida_unavailable error if built without frida-core" },
	{ 0 },
};

static const RzCmdDescDetail cmd_fridad_details[] = {
	{ .name = "Examples", .entries = cmd_fridad_entries },
	{ 0 },
};

static const RzCmdDescHelp cmd_fridad_help = {
	.summary = "List Frida devices",
	.description = "Enumerates devices known to the Frida device manager (local, USB, and "
		       "remote) and emits a structured JSON reply.",
	.details = cmd_fridad_details,
	.args = cmd_no_args,
};

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
	ctx->cmd_desc = rz_core_plugin_cmd_desc_group_new(core, "frida", NULL, NULL, &cmd_frida_group_help);
	if (!ctx->cmd_desc) {
		frida_context_free(ctx);
		rz_warn_if_reached();
		return false;
	}

	RzCmdDesc *fridas = rz_cmd_desc_argv_state_new(core->rcmd, ctx->cmd_desc, "fridas",
		RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON, rz_cmd_fridas_handler, &cmd_fridas_help);
	if (!fridas) {
		rz_core_plugin_cmd_desc_remove(core, ctx->cmd_desc);
		frida_context_free(ctx);
		return false;
	}

	RzCmdDesc *fridau = rz_cmd_desc_argv_state_new(core->rcmd, ctx->cmd_desc, "fridau",
		RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON, rz_cmd_fridau_handler, &cmd_fridau_help);
	if (!fridau) {
		rz_core_plugin_cmd_desc_remove(core, ctx->cmd_desc);
		frida_context_free(ctx);
		return false;
	}

	RzCmdDesc *fridad = rz_cmd_desc_argv_state_new(core->rcmd, ctx->cmd_desc, "fridad",
		RZ_OUTPUT_MODE_JSON, rz_cmd_fridad_handler, &cmd_fridad_help);
	if (!fridad) {
		rz_core_plugin_cmd_desc_remove(core, ctx->cmd_desc);
		frida_context_free(ctx);
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
