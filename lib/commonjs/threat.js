"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Threat = void 0;
var _reactNative = require("react-native");
class Threat {
  static AppIntegrity = new Threat(0);
  static PrivilegedAccess = new Threat(0);
  static Debug = new Threat(0);
  static Hooks = new Threat(0);
  static Passcode = new Threat(0);
  static Simulator = new Threat(0);
  static SecureHardwareNotAvailable = new Threat(0);
  static SystemVPN = new Threat(0);
  static DeviceBinding = new Threat(0);
  static DeviceID = new Threat(0);
  static UnofficialStore = new Threat(0);
  static ObfuscationIssues = new Threat(0);
  static DevMode = new Threat(0);
  static Malware = new Threat(0);
  constructor(value) {
    this.value = value;
  }
  static getValues() {
    return _reactNative.Platform.OS === 'android' ? [this.AppIntegrity, this.PrivilegedAccess, this.Debug, this.Hooks, this.Passcode, this.Simulator, this.SecureHardwareNotAvailable, this.SystemVPN, this.DeviceBinding, this.UnofficialStore, this.ObfuscationIssues, this.DevMode, this.Malware] : [this.AppIntegrity, this.PrivilegedAccess, this.Debug, this.Hooks, this.Passcode, this.Simulator, this.SecureHardwareNotAvailable, this.SystemVPN, this.DeviceBinding, this.DeviceID, this.UnofficialStore];
  }
}
exports.Threat = Threat;
//# sourceMappingURL=threat.js.map