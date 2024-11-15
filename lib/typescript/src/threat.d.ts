export declare class Threat {
    value: number;
    static AppIntegrity: Threat;
    static PrivilegedAccess: Threat;
    static Debug: Threat;
    static Hooks: Threat;
    static Passcode: Threat;
    static Simulator: Threat;
    static SecureHardwareNotAvailable: Threat;
    static SystemVPN: Threat;
    static DeviceBinding: Threat;
    static DeviceID: Threat;
    static UnofficialStore: Threat;
    static ObfuscationIssues: Threat;
    static DevMode: Threat;
    static Malware: Threat;
    constructor(value: number);
    static getValues(): Threat[];
}
//# sourceMappingURL=threat.d.ts.map