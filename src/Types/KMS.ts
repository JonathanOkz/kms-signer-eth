import { ECDSASignature } from "./ECDSASignature";

export interface KMS {
    getPublickey(KeyId: string): Promise<Buffer>;
    getAddress(KeyId: string) : Promise<Buffer>;
    ecsign(address: Buffer, KeyId: string, msgHash: Buffer, chainId?: number): Promise<ECDSASignature>;
}