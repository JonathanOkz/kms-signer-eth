export interface ECDSASignature {
    v: number;
    r: Buffer;
    s: Buffer;
}