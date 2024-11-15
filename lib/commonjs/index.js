"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
var _exportNames = {
  setThreatListeners: true,
  removeThreatListeners: true,
  talsecStart: true,
  useFreeRasp: true,
  addToWhitelist: true
};
exports.useFreeRasp = exports.talsecStart = exports.setThreatListeners = exports.removeThreatListeners = exports.default = exports.addToWhitelist = void 0;
var _react = require("react");
var _reactNative = require("react-native");
var _utils = require("./utils");
var _buffer = require("buffer");
var _threat = require("./threat");
var _types = require("./types");
Object.keys(_types).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
  if (key in exports && exports[key] === _types[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function () {
      return _types[key];
    }
  });
});
const {
  FreeraspReactNative
} = _reactNative.NativeModules;
const eventEmitter = new _reactNative.NativeEventEmitter(FreeraspReactNative);
let eventsListener;
const onInvalidCallback = () => {
  FreeraspReactNative.onInvalidCallback();
};
const getThreatIdentifiers = async () => {
  let identifiers = await FreeraspReactNative.getThreatIdentifiers();
  if (identifiers.length !== (0, _utils.getThreatCount)() || !(0, _utils.itemsHaveType)(identifiers, 'number')) {
    onInvalidCallback();
  }
  return identifiers;
};
const getThreatChannelData = async () => {
  const dataLength = _reactNative.Platform.OS === 'ios' ? 2 : 3;
  let data = await FreeraspReactNative.getThreatChannelData();
  if (data.length !== dataLength || !(0, _utils.itemsHaveType)(data, 'string')) {
    onInvalidCallback();
  }
  return data;
};
const prepareMapping = async () => {
  const newValues = await getThreatIdentifiers();
  const threats = _threat.Threat.getValues();
  threats.map((threat, index) => {
    threat.value = newValues[index];
  });
};

// parses base64-encoded malware data to SuspiciousAppInfo[]
const parseMalwareData = data => {
  return data.map(entry => toSuspiciousAppInfo(entry));
};
const toSuspiciousAppInfo = base64Value => {
  const data = JSON.parse(_buffer.Buffer.from(base64Value, 'base64').toString('utf8'));
  const packageInfo = data.packageInfo;
  return {
    packageInfo,
    reason: data.reason
  };
};
const setThreatListeners = async config => {
  const [channel, key, malwareKey] = await getThreatChannelData();
  await prepareMapping();
  eventsListener = eventEmitter.addListener(channel, event => {
    var _config$privilegedAcc, _config$debug, _config$simulator, _config$appIntegrity, _config$unofficialSto, _config$hooks, _config$deviceBinding, _config$passcode, _config$secureHardwar, _config$obfuscationIs, _config$deviceID, _config$devMode, _config$systemVPN, _config$malware;
    if (event[key] === undefined) {
      onInvalidCallback();
    }
    switch (event[key]) {
      case _threat.Threat.PrivilegedAccess.value:
        (_config$privilegedAcc = config.privilegedAccess) === null || _config$privilegedAcc === void 0 || _config$privilegedAcc.call(config);
        break;
      case _threat.Threat.Debug.value:
        (_config$debug = config.debug) === null || _config$debug === void 0 || _config$debug.call(config);
        break;
      case _threat.Threat.Simulator.value:
        (_config$simulator = config.simulator) === null || _config$simulator === void 0 || _config$simulator.call(config);
        break;
      case _threat.Threat.AppIntegrity.value:
        (_config$appIntegrity = config.appIntegrity) === null || _config$appIntegrity === void 0 || _config$appIntegrity.call(config);
        break;
      case _threat.Threat.UnofficialStore.value:
        (_config$unofficialSto = config.unofficialStore) === null || _config$unofficialSto === void 0 || _config$unofficialSto.call(config);
        break;
      case _threat.Threat.Hooks.value:
        (_config$hooks = config.hooks) === null || _config$hooks === void 0 || _config$hooks.call(config);
        break;
      case _threat.Threat.DeviceBinding.value:
        (_config$deviceBinding = config.deviceBinding) === null || _config$deviceBinding === void 0 || _config$deviceBinding.call(config);
        break;
      case _threat.Threat.Passcode.value:
        (_config$passcode = config.passcode) === null || _config$passcode === void 0 || _config$passcode.call(config);
        break;
      case _threat.Threat.SecureHardwareNotAvailable.value:
        (_config$secureHardwar = config.secureHardwareNotAvailable) === null || _config$secureHardwar === void 0 || _config$secureHardwar.call(config);
        break;
      case _threat.Threat.ObfuscationIssues.value:
        (_config$obfuscationIs = config.obfuscationIssues) === null || _config$obfuscationIs === void 0 || _config$obfuscationIs.call(config);
        break;
      case _threat.Threat.DeviceID.value:
        (_config$deviceID = config.deviceID) === null || _config$deviceID === void 0 || _config$deviceID.call(config);
        break;
      case _threat.Threat.DevMode.value:
        (_config$devMode = config.devMode) === null || _config$devMode === void 0 || _config$devMode.call(config);
        break;
      case _threat.Threat.SystemVPN.value:
        (_config$systemVPN = config.systemVPN) === null || _config$systemVPN === void 0 || _config$systemVPN.call(config);
        break;
      case _threat.Threat.Malware.value:
        (_config$malware = config.malware) === null || _config$malware === void 0 || _config$malware.call(config, parseMalwareData(event[malwareKey]));
        break;
      default:
        onInvalidCallback();
        break;
    }
  });
};
exports.setThreatListeners = setThreatListeners;
const removeThreatListeners = () => {
  eventsListener.remove();
};
exports.removeThreatListeners = removeThreatListeners;
const talsecStart = async options => {
  return FreeraspReactNative.talsecStart(options);
};
exports.talsecStart = talsecStart;
const useFreeRasp = (config, actions) => {
  (0, _react.useEffect)(() => {
    (async () => {
      await setThreatListeners(actions);
      try {
        let response = await talsecStart(config);
        if (response !== 'freeRASP started') {
          onInvalidCallback();
        }
        console.log(response);
      } catch (e) {
        console.error(`${e.code}: ${e.message}`);
      }
      return () => {
        removeThreatListeners();
      };
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
};
exports.useFreeRasp = useFreeRasp;
const addToWhitelist = async packageName => {
  if (_reactNative.Platform.OS === 'ios') {
    return Promise.reject('Malware detection not available on iOS');
  }
  return FreeraspReactNative.addToWhitelist(packageName);
};
exports.addToWhitelist = addToWhitelist;
var _default = exports.default = FreeraspReactNative;
//# sourceMappingURL=index.js.map