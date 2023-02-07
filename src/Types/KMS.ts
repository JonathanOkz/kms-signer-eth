import { ECDSASignature } from "./ECDSASignature";

export interface KMS {
    getPublickey(KeyId: string): Promise<Buffer>;
    getAddress(KeyId: string) : Promise<Buffer>;
    getAddressHex(KeyId: string) : Promise<string>;
    ecsign(address: Buffer, KeyId: string, digest: Buffer, chainId?: bigint): Promise<ECDSASignature>;
}