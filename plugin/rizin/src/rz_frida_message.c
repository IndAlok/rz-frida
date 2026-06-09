// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// Host side of agent message protocol. Decodes messages the injected
// script gives and tracks ids of requests still waiting for reply.

#include <rz_frida.h>

#include <rz_util/rz_json.h>

struct rz_frida_pending_t {
	RzSetU *ids; ///< Ids of requests still awaiting a reply.
	ut64 next_id; ///< Next id handed out, increases by one each time.
};

static char *dup_str_field(const RzJson *object, const char *key) {
	const RzJson *field = rz_json_get(object, key);
	if (!field || field->type != RZ_JSON_STRING) {
		return NULL;
	}
	return rz_str_dup(field->str_value);
}

RZ_IPI bool rz_frida_agent_message_parse(const char *message, RzFridaAgentMessage *out) {
	rz_return_val_if_fail(message && out, false);

	rz_mem_memzero(out, sizeof(*out));

	char *text = rz_str_dup(message);
	if (!text) {
		return false;
	}

	bool ok = false;
	RzJson *json = rz_json_parse(text);
	if (!json || json->type != RZ_JSON_OBJECT) {
		goto beach;
	}

	const RzJson *type = rz_json_get(json, "type");
	if (!type || type->type != RZ_JSON_STRING) {
		goto beach;
	}

	if (RZ_STR_EQ(type->str_value, "send")) {
		out->kind = RZ_FRIDA_AGENT_MESSAGE_SEND;
		const RzJson *payload = rz_json_get(json, "payload");
		if (payload) {
			out->payload = rz_json_as_string(payload, false);
		}
		ok = true;
	} else if (RZ_STR_EQ(type->str_value, "error")) {
		out->kind = RZ_FRIDA_AGENT_MESSAGE_ERROR;
		out->description = dup_str_field(json, "description");
		out->stack = dup_str_field(json, "stack");
		ok = true;
	} else if (RZ_STR_EQ(type->str_value, "log")) {
		out->kind = RZ_FRIDA_AGENT_MESSAGE_LOG;
		out->level = dup_str_field(json, "level");
		out->text = dup_str_field(json, "payload");
		ok = true;
	}

beach:
	rz_json_free(json);
	free(text);
	if (!ok) {
		rz_frida_agent_message_fini(out);
	}
	return ok;
}

RZ_IPI void rz_frida_agent_message_fini(RzFridaAgentMessage *message) {
	if (!message) {
		return;
	}
	RZ_FREE(message->payload);
	RZ_FREE(message->description);
	RZ_FREE(message->stack);
	RZ_FREE(message->level);
	RZ_FREE(message->text);
	rz_mem_memzero(message, sizeof(*message));
}

RZ_IPI bool rz_frida_response_parse(const char *payload, RzFridaResponse *out) {
	rz_return_val_if_fail(payload && out, false);

	rz_mem_memzero(out, sizeof(*out));

	char *text = rz_str_dup(payload);
	if (!text) {
		return false;
	}

	bool ok = false;
	RzJson *json = rz_json_parse(text);
	if (!json || json->type != RZ_JSON_OBJECT) {
		goto beach;
	}

	// a reply has to carry id it answers, anything else is a plain
	// notification and is not our concern here.
	const RzJson *id = rz_json_get(json, "id");
	if (!id || id->type != RZ_JSON_INTEGER) {
		goto beach;
	}
	out->id = id->num.u_value;

	const RzJson *status = rz_json_get(json, "ok");
	out->ok = status && status->type == RZ_JSON_BOOLEAN && status->num.u_value;

	if (out->ok) {
		const RzJson *result = rz_json_get(json, "result");
		if (result) {
			out->result = rz_json_as_string(result, false);
		}
	} else {
		const RzJson *error = rz_json_get(json, "error");
		if (error) {
			out->error = rz_json_as_string(error, false);
		}
	}
	ok = true;

beach:
	rz_json_free(json);
	free(text);
	if (!ok) {
		rz_frida_response_fini(out);
	}
	return ok;
}

RZ_IPI void rz_frida_response_fini(RzFridaResponse *response) {
	if (!response) {
		return;
	}
	RZ_FREE(response->result);
	RZ_FREE(response->error);
	rz_mem_memzero(response, sizeof(*response));
}

RZ_IPI RzFridaPending *rz_frida_pending_new(void) {
	RzFridaPending *pending = RZ_NEW0(RzFridaPending);
	if (!pending) {
		return NULL;
	}
	pending->ids = rz_set_u_new();
	if (!pending->ids) {
		free(pending);
		return NULL;
	}
	// 0 for invalid req, so here start with 1.
	pending->next_id = 1;
	return pending;
}

RZ_IPI void rz_frida_pending_free(RzFridaPending *pending) {
	if (!pending) {
		return;
	}
	rz_set_u_free(pending->ids);
	free(pending);
}

RZ_IPI ut64 rz_frida_pending_next_id(RzFridaPending *pending) {
	rz_return_val_if_fail(pending, 0);
	return pending->next_id++;
}

RZ_IPI bool rz_frida_pending_add(RzFridaPending *pending, ut64 id) {
	rz_return_val_if_fail(pending && pending->ids, false);
	if (rz_set_u_contains(pending->ids, id)) {
		return false;
	}
	rz_set_u_add(pending->ids, id);
	return true;
}

RZ_IPI bool rz_frida_pending_contains(const RzFridaPending *pending, ut64 id) {
	rz_return_val_if_fail(pending && pending->ids, false);
	return rz_set_u_contains(pending->ids, id);
}

RZ_IPI bool rz_frida_pending_take(RzFridaPending *pending, ut64 id) {
	rz_return_val_if_fail(pending && pending->ids, false);
	if (!rz_set_u_contains(pending->ids, id)) {
		return false;
	}
	rz_set_u_delete(pending->ids, id);
	return true;
}

RZ_IPI size_t rz_frida_pending_count(const RzFridaPending *pending) {
	rz_return_val_if_fail(pending && pending->ids, 0);
	return rz_set_u_size(pending->ids);
}

RZ_IPI void rz_frida_pending_clear(RzFridaPending *pending) {
	rz_return_if_fail(pending && pending->ids);
	rz_set_u_clear(pending->ids);
}
