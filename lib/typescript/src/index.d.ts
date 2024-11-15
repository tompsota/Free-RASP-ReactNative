import type { NativeEventEmitterActions, TalsecConfig } from './types';
declare const FreeraspReactNative: any;
export declare const setThreatListeners: <T extends NativeEventEmitterActions>(config: T & Record<Exclude<keyof T, keyof NativeEventEmitterActions>, []>) => Promise<void>;
export declare const removeThreatListeners: () => void;
export declare const talsecStart: (options: TalsecConfig) => Promise<string>;
export declare const useFreeRasp: <T extends NativeEventEmitterActions>(config: TalsecConfig, actions: T & Record<Exclude<keyof T, keyof NativeEventEmitterActions>, []>) => void;
export declare const addToWhitelist: (packageName: string) => Promise<boolean>;
export * from './types';
export default FreeraspReactNative;
//# sourceMappingURL=index.d.ts.map