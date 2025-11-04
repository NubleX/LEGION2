
export interface ProtocolInfo {
    name: string;
    family: ProtocolFamily;
    layer: ProtocolLayer;
    defaultPort?: number;
    capabilities: ProtocolCapabilities;
    description: string;
}

export enum ProtocolLayer {
    Physical = "physical",
    DataLink = "datalink",
    Network = "network",
    Transport = "transport",
    Session = "session",
    Presentation = "presentation",
    Application = "application",
}

export enum ProtocolFamily {
    Internet = "internet",
    Lan = "lan",
    Wan = "wan",
    Iot = "iot",
    Industrial = "industrial",
    Wireless = "wireless",
    Security = "security",
    Discovery = "discovery",
    Streaming = "streaming",
    Messaging = "messaging",
}

export interface ProtocolCapabilities {
    multicast: boolean;
    broadcast: boolean;
    unicast: boolean;
    encryption: boolean;
    authentication: boolean;
    compression: boolean;
    qos: boolean;
    natTraversal: boolean;
    firewallTraversal: boolean;
    discovery: boolean;
    routing: boolean;
    meshNetworking: boolean;
}