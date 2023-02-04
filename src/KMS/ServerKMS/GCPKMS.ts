import { ServerKMS } from "../ServerKMS";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import crypto from 'crypto';
import crc32c from 'fast-crc32c';
import { v4 as uuidv4 } from 'uuid';

interface KeyManagementServiceClientPath {
    projectId: string;
    locationId: string;
    keyRingId: string;
}

export class GCPKMS extends ServerKMS {
    private kms: KeyManagementServiceClient;
    private path: KeyManagementServiceClientPath

    constructor(config: {keyFilename: string, path: KeyManagementServiceClientPath}) {
        super();
        this.kms = new KeyManagementServiceClient({keyFilename: config.keyFilename});
        this.path = config.path;
    }

    /**
     * 
     * @returns a DER-encoded object as defined by ANS X9.62–2005.
     */
    async kmsGetDerPublickey(KeyId: string) : Promise<Buffer>  { console.log("GCPKMS kmsGetDerPublickey...", this.kms.cryptoKeyVersionPath(this.path.projectId, this.path.locationId, this.path.keyRingId, KeyId, '1'));
        const pubKey = await this.kms.getPublicKey({name: this.kms.cryptoKeyVersionPath(this.path.projectId, this.path.locationId, this.path.keyRingId, KeyId, '1')})
        if (!pubKey[0].pem) {
            throw new Error("GCPKMS: pubKey[0].pem is undefined.");
        }
        const p2 = crypto.createPublicKey(pubKey[0].pem);
        return p2.export({format:"der", type:"spki"});
    }

    /**
     * 
     * @returns a DER-encoded object as defined by ANS X9.62–2005.
     */
    async kmsSignDigest(KeyId: string, msgHash: Buffer) : Promise<Buffer> { console.log("GCPKMS kmsSignDigest...", this.kms.cryptoKeyVersionPath(this.path.projectId, this.path.locationId, this.path.keyRingId, KeyId, '1'));
        const [signResponse] = await this.kms.asymmetricSign({
            name: this.kms.cryptoKeyVersionPath(this.path.projectId, this.path.locationId, this.path.keyRingId, KeyId, '1'),
            digest: {
                sha256: msgHash
            },
            digestCrc32c: {
                value: crc32c.calculate(msgHash),
            }
        });
        if (!signResponse.signature || !signResponse.signatureCrc32c) {
            throw new Error("GCPKMS: signResponse is undefined.");
        }
        if (!signResponse.verifiedDigestCrc32c) {
            throw new Error('GCPKMS: request corrupted in-transit');
        }
        if (crc32c.calculate(Buffer.from(signResponse.signature)) !== Number(signResponse.signatureCrc32c.value)) {
            throw new Error('GCPKMS: response corrupted in-transit');
        }
        return Buffer.from(signResponse.signature);
    }

    async kmsCreateKey(cryptoKeyId = uuidv4()) : Promise<string> { console.log("AWSKMS kmsCreateKey...", this.kms.keyRingPath(this.path.projectId, this.path.locationId, this.path.keyRingId));
        const [key] = await this.kms.createCryptoKey({
            parent: this.kms.keyRingPath(this.path.projectId, this.path.locationId, this.path.keyRingId),
            cryptoKeyId: cryptoKeyId,
            cryptoKey: {
                purpose: 'ASYMMETRIC_SIGN',
                versionTemplate: {
                    algorithm: 'EC_SIGN_SECP256K1_SHA256',
                    protectionLevel: 'HSM'
                },
                // Optional: customize how long key versions should be kept before destroying.
                // destroyScheduledDuration: {seconds: 60 * 60 * 24},
            }
        });
        if (!key.name) {
            throw new Error("GCPKMS: key.name not exist.");
        }
        return cryptoKeyId;
    }

    async kmsCreateKeyRing(keyRingId: string) { console.log("AWSKMS createKeyRing...", this.kms.locationPath(this.path.projectId, this.path.locationId));
        const [keyRing] = await this.kms.createKeyRing({
            parent: this.kms.locationPath(this.path.projectId, this.path.locationId),
            keyRingId: keyRingId,
        });
        if (!keyRing.name) {
            throw new Error("GCPKMS: keyRing.name not exist.");
        }
        return keyRingId;
    }
}