import { UBuffer } from "./Utils/UBuffer";
import { UAddress } from "./Utils/UAddress";

export class Account {
    public KeyId: string;
    public address: Buffer;

    constructor(KeyId: string, address: string | Buffer) {
        this.KeyId = KeyId;
        this.address = UBuffer.bufferOrHex(address);
    }

    getKeyId(): string {
        return this.KeyId;
    }

    getAddress(): Buffer {
        return this.address;
    }

    getAddressHex() : string {
        return UAddress.fromAddress(this.address).getAddressHex();
    }

    getChecksumAddress() : string {
        return UAddress.fromAddress(this.address).getChecksumAddress()
    }
}