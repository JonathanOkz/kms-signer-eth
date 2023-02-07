import { addHexPrefix } from '@ethereumjs/util'
import { Transaction, TxData } from '@ethereumjs/tx';
import { Common } from '@ethereumjs/common'
import { KMS } from './Types/KMS';
import { Account } from './Account';

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
}