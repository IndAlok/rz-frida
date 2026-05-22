'use strict';

const RZ_FRIDA_AGENT_VERSION = 1;

rpc.exports = {
  ping() {
    return {
      version: RZ_FRIDA_AGENT_VERSION,
      platform: Process.platform,
      arch: Process.arch,
      pointerSize: Process.pointerSize
    };
  }
};

send({
  type: 'agent.ready',
  version: RZ_FRIDA_AGENT_VERSION
});

