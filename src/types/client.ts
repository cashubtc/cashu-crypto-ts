import { ProjPointType } from '@noble/curves/abstract/weierstrass';

export type BlindedMessage = {
	B_: ProjPointType<bigint>;
	r: bigint;
	secret: Uint8Array;
};
