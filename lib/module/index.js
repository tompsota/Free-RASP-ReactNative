import { useEffect } from 'react';
import { NativeEventEmitter, NativeModules, Platform } from 'react-native';
import { getThreatCount, itemsHaveType } from './utils';
import { Buffer } from 'buffer';
import { Threat } from './threat';
const {
  FreeraspReactNative
} = NativeModules;
const eventEmitter = new NativeEventEmitter(FreeraspReactNative);
let eventsListener;
const onInvalidCallback = () => {
  FreeraspReactNative.onInvalidCallback();
};
const getThreatIdentifiers = async () => {
  let identifiers = await FreeraspReactNative.getThreatIdentifiers();
  if (identifiers.length !== getThreatCount() || !itemsHaveType(identifiers, 'number')) {
    onInvalidCallback();
  }
  return identifiers;
};
const getThreatChannelData = async () => {
  const dataLength = Platform.OS === 'ios' ? 2 : 3;
  let data = await FreeraspReactNative.getThreatChannelData();
  if (data.length !== dataLength || !itemsHaveType(data, 'string')) {
    onInvalidCallback();
  }
  return data;
};
const prepareMapping = async () => {
  const newValues = await getThreatIdentifiers();
  const threats = Threat.getValues();
  threats.map((threat, index) => {
    threat.value = newValues[index];
  });
};

// parses base64-encoded malware data to SuspiciousAppInfo[]
const parseMalwareData = data => {
  return data.map(entry => toSuspiciousAppInfo(entry));
};
const toSuspiciousAppInfo = base64Value => {
  const data = JSON.parse(Buffer.from(base64Value, 'base64').toString('utf8'));
  const packageInfo = data.packageInfo;
  return {
    packageInfo,
    reason: data.reason
  };
};
export const setThreatListeners = async config => {
  const [channel, key, malwareKey] = await getThreatChannelData();
  await prepareMapping();
  eventsListener = eventEmitter.addListener(channel, event => {
    var _config$privilegedAcc, _config$debug, _config$simulator, _config$appIntegrity, _config$unofficialSto, _config$hooks, _config$deviceBinding, _config$passcode, _config$secureHardwar, _config$obfuscationIs, _config$deviceID, _config$devMode, _config$systemVPN, _config$malware;
    if (event[key] === undefined) {
      onInvalidCallback();
    }
    switch (event[key]) {
      case Threat.PrivilegedAccess.value:
        (_config$privilegedAcc = config.privilegedAccess) === null || _config$privilegedAcc === void 0 || _config$privilegedAcc.call(config);
        break;
      case Threat.Debug.value:
        (_config$debug = config.debug) === null || _config$debug === void 0 || _config$debug.call(config);
        break;
      case Threat.Simulator.value:
        (_config$simulator = config.simulator) === null || _config$simulator === void 0 || _config$simulator.call(config);
        break;
      case Threat.AppIntegrity.value:
        (_config$appIntegrity = config.appIntegrity) === null || _config$appIntegrity === void 0 || _config$appIntegrity.call(config);
        break;
      case Threat.UnofficialStore.value:
        (_config$unofficialSto = config.unofficialStore) === null || _config$unofficialSto === void 0 || _config$unofficialSto.call(config);
        break;
      case Threat.Hooks.value:
        (_config$hooks = config.hooks) === null || _config$hooks === void 0 || _config$hooks.call(config);
        break;
      case Threat.DeviceBinding.value:
        (_config$deviceBinding = config.deviceBinding) === null || _config$deviceBinding === void 0 || _config$deviceBinding.call(config);
        break;
      case Threat.Passcode.value:
        (_config$passcode = config.passcode) === null || _config$passcode === void 0 || _config$passcode.call(config);
        break;
      case Threat.SecureHardwareNotAvailable.value:
        (_config$secureHardwar = config.secureHardwareNotAvailable) === null || _config$secureHardwar === void 0 || _config$secureHardwar.call(config);
        break;
      case Threat.ObfuscationIssues.value:
        (_config$obfuscationIs = config.obfuscationIssues) === null || _config$obfuscationIs === void 0 || _config$obfuscationIs.call(config);
        break;
      case Threat.DeviceID.value:
        (_config$deviceID = config.deviceID) === null || _config$deviceID === void 0 || _config$deviceID.call(config);
        break;
      case Threat.DevMode.value:
        (_config$devMode = config.devMode) === null || _config$devMode === void 0 || _config$devMode.call(config);
        break;
      case Threat.SystemVPN.value:
        (_config$systemVPN = config.systemVPN) === null || _config$systemVPN === void 0 || _config$systemVPN.call(config);
        break;
      case Threat.Malware.value:
        (_config$malware = config.malware) === null || _config$malware === void 0 || _config$malware.call(config, parseMalwareData(event[malwareKey]));
        break;
      default:
        onInvalidCallback();
        break;
    }
  });
};
export const removeThreatListeners = () => {
  eventsListener.remove();
};
export const talsecStart = async options => {
  return FreeraspReactNative.talsecStart(options);
};
export const useFreeRasp = (config, actions) => {
  useEffect(() => {
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
export const addToWhitelist = async packageName => {
  if (Platform.OS === 'ios') {
    return Promise.reject('Malware detection not available on iOS');
  }
  return FreeraspReactNative.addToWhitelist(packageName);
};
export * from './types';
export default FreeraspReactNative;
//# sourceMappingURL=index.js.map