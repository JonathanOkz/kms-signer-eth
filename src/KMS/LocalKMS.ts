import { KMS } from "../Types/KMS";
import { UPublickey } from "../Utils/UPublickey";
import { UBuffer } from "../Utils/UBuffer";
import * as ethutil from "ethereumjs-util";
import { ECDSASignature } from "../Types/ECDSASignature";
import { UAddress } from "../Utils/UAddress";

export class LocalKMS implements KMS {
    public static KEY_ID = "LOCAL_KEY_ID";

    private privatekey: Buffer;

    constructor(privatekey: Buffer | string) {
        this.privatekey = UBuffer.bufferOrHex(privatekey);
    }

    async getPublickey(KeyId: string) : Promise<Buffer> { console.log("LocalKMS getPublickey...");
        return UPublickey.fromPrivatekey(this.privatekey).getPublickey();
    }

    async getAddress(KeyId: string) : Promise<Buffer>  { console.log("ServerKMS getAddress...");
        return UAddress.fromPublickey(await this.getPublickey(KeyId)).getAddress();
    }

    async ecsign(address: Buffer, KeyId: string, msgHash: Buffer, chainId?: number) : Promise<ECDSASignature> { console.log("LocalKMS sign...");
        return ethutil.ecsign(msgHash, this.privatekey, chainId);
    }
}