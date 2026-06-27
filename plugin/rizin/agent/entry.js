const Java = require('frida-java-bridge');
globalThis.Java = Java.default || Java;
require('./rzfrida_agent.js');
