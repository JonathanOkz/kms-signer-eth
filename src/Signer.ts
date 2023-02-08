import { addHexPrefix, fromSigned, toUnsigned, bigIntToBuffer, hashPersonalMessage } from '@ethereumjs/util'
import { Transaction, TxData } from '@ethereumjs/tx';
import { Common } from '@ethereumjs/common'
import { KMS } from './Types/KMS';
import { Account } from './Account';
import { UBuffer } from './Utils/UBuffer';

export class Signer {
    kms: KMS;
    common?: Common;

    constructor(kms: KMS, chainId?: number) {
        this.kms = kms;
        this.common = (chainId) ? Common.custom({ chainId: chainId, networkId: chainId }) : undefined;
    }

     /**
     * @returns The tnx serialized ECDSA signature as a '0x'-prefixed string.
     */
    public async signTransaction(account: Account | { address: Buffer, KeyId: string }, txData: TxData) {
        const digest     = Transaction.fromTxData(txData, { common: this.common }).getMessageToSign();
        const {r, s, v}  = await this.kms.ecsign(account.address, account.KeyId, digest, this.common?.chainId());
        const signed     = Transaction.fromTxData({...txData, r, s, v}, { common: this.common });
    
        return addHexPrefix(signed.serialize().toString('hex'));
    }

    /**
     * @returns The concatenated ECDSA signature as a '0x'-prefixed string.
     */
    public async signDigestHex(account: Account | { address: Buffer, KeyId: string }, digestHex: string) {
        const digest = UBuffer.bufferOrHex(digestHex)
        return this.signDigest(account, digest);
    }

    /**
     * @returns The concatenated ECDSA signature as a '0x'-prefixed string.
     */
    public async signMessage(account: Account | { address: Buffer, KeyId: string }, message: string) {
        const digest = hashPersonalMessage(Buffer.from(message));
        return this.signDigest(account, digest);
    }

    /**
     * @returns The concatenated ECDSA signature as a '0x'-prefixed string.
     */
    public async signDigest(account: Account | { address: Buffer, KeyId: string }, digest: Buffer) {
        const {r, s, v} = await this.kms.ecsign(account.address, account.KeyId, digest);

        const rStr = toUnsigned(fromSigned(r)).toString('hex');
        const sStr = toUnsigned(fromSigned(s)).toString('hex');
        const vStr = bigIntToBuffer(v).toString('hex');

        return addHexPrefix(rStr.concat(sStr, vStr));
    }
}