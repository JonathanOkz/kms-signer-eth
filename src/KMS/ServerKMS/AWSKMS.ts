import { ServerKMS } from "../ServerKMS";
import {
    KMSClient,
    SignCommand,
    GetPublicKeyCommand,
    KMSClientConfig,
    CreateKeyCommand,
  } from "@aws-sdk/client-kms";

export class AWSKMS extends ServerKMS {
    private kms: KMSClient;

    constructor(config: KMSClientConfig) {
        super();
        this.kms = new KMSClient(config);
    }

    /**
     * 
     * @returns a DER-encoded object as defined by ANS X9.62–2005.
     */
    async kmsGetDerPublickey(KeyId: string) : Promise<Buffer>  { console.log("AWSKMS kmsGetDerPublickey...");
        const key = await this.kms.send(new GetPublicKeyCommand({
            KeyId: KeyId
        }));
        if (!key.PublicKey) {
            throw new Error("AWSKMS: PublicKey is undefined.");
        }
        return Buffer.from(key.PublicKey);
    }

    /**
     * 
     * @returns a DER-encoded object as defined by ANS X9.62–2005.
     */
    async kmsSignDigest(KeyId: string, digest: Buffer) : Promise<Buffer> { console.log("AWSKMS kmsSignDigest...");
        const response = await this.kms.send(new SignCommand({
            KeyId: KeyId,
            Message: digest,
            MessageType: "DIGEST",
            SigningAlgorithm: "ECDSA_SHA_256",
        }));
        if (!response.Signature) {
            throw new Error("AWSKMS: Signature is undefined.");
        }
        return Buffer.from(response.Signature);
    }

    async kmsCreateKey() : Promise<string> { console.log("AWSKMS kmsCreateKey...");
        const response = await this.kms.send(new CreateKeyCommand({
            KeySpec: "ECC_SECG_P256K1",
            KeyUsage: "SIGN_VERIFY"
        }));
        if (!response.KeyMetadata?.KeyId) {
            throw new Error("AWSKMS: KeyId not exist.");
        }
        return response.KeyMetadata?.KeyId;
    }
}


