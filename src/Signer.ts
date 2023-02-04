import { KMS } from './Types/KMS';
import { Transaction, TxData } from '@ethereumjs/tx';
import { Common } from '@ethereumjs/common'
import { Account } from './Account';

export class Signer {
    kms: KMS;
    chainId?: number;
    common?: Common;

    constructor(kms: KMS, chainId?: number) {
        this.kms = kms;
        this.chainId = chainId;
        this.common = (chainId) ? new Common({ chain: chainId }) : undefined;
    }

    public async signTransaction(account: Account | { address: Buffer, KeyId: string }, txData: TxData) {
        const unsignedTx = Transaction.fromTxData(txData, { common: this.common }).getMessageToSign();
        const {r, s, v}  = await this.kms.ecsign(account.address, account.KeyId, unsignedTx, this.chainId);
        const signedTx   = Transaction.fromTxData({...txData, r, s, v}, { common: this.common });
    
        return `0x${signedTx.serialize().toString('hex')}`;
    }
}