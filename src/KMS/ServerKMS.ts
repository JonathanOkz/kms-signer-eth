import { KMS } from "../Types/KMS";
import { ECDSASignature } from "../Types/ECDSASignature";
import { UPublickey } from "../Utils/UPublickey";
import { USignatureECDSA } from "../Utils/USignatureECDSA";
import { UAddress } from "../Utils/UAddress";

export abstract class ServerKMS implements KMS {
    abstract kmsGetDerPublickey(KeyId: string) : Promise<Buffer>;
    abstract kmsSignDigest(KeyId: string, msgHash: Buffer) : Promise<Buffer>;

    async getPublickey(KeyId: string) : Promise<Buffer>  { console.log("ServerKMS getPublickey...");
        const derPublickey = await this.kmsGetDerPublickey(KeyId);
        return UPublickey.fromPublickeyDerEncoding(derPublickey).getPublickey();
    }

    async getAddress(KeyId: string) : Promise<Buffer>  { console.log("ServerKMS getAddress...");
        return UAddress.fromPublickey(await this.getPublickey(KeyId)).getAddress();
    }

    async ecsign(address: Buffer, KeyId: string, msgHash: Buffer, chainId?: number) : Promise<ECDSASignature> { console.log("ServerKMS sign...", KeyId, chainId);

        const {r, s} = USignatureECDSA.decodeRS(await this.kmsSignDigest(KeyId, msgHash));

        const v = USignatureECDSA.calculateV(address, msgHash, r, s, chainId);
        if (v == -1) {
            throw new Error("ServerKMS: v is invalid.");
        }

        return {r, s, v}
    }
}

