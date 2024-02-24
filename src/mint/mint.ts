import { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToNumber } from '../util/utils';
import { BlindSignature, IntRange, MintKeys, Proof } from '../types/common';
import { KeysetPair } from '../types/mint';
import { createRandomPrivateKey, deriveKeysetId, hashToCurve } from '../common/common';
import { HDKey } from '@scure/bip32';
import { bytesToHex } from '@noble/hashes/utils';

const DERIVATION_PATH = "m/0'/0'/0'";

export function createBlindSignature(
	B_: ProjPointType<bigint>,
	privateKey: Uint8Array,
	amount: number,
	id: string
): BlindSignature {
	const C_: ProjPointType<bigint> = B_.multiply(bytesToNumber(privateKey));
	return { C_, amount, id };
}

export function getPubKeyFromPrivKey(privKey: Uint8Array) {
	return secp256k1.getPublicKey(privKey, true);
}

export function createNewMintKeys(pow2height: IntRange<0, 65>, seed?: Uint8Array): KeysetPair {
	let counter = 0n;
	const pubKeys: MintKeys = {};
	const privKeys: MintKeys = {};
	let masterKey;
	if (seed) {
		masterKey = HDKey.fromMasterSeed(seed);
	}
	while (counter < pow2height) {
		const index: string = (2n ** counter).toString();
		privKeys[index] = masterKey
			? masterKey.derive(`${DERIVATION_PATH}/${counter}`).privateKey
			: createRandomPrivateKey();
		pubKeys[index] = getPubKeyFromPrivKey(privKeys[index]);
		counter++;
	}
	const keysetId = deriveKeysetId(pubKeys);
	return { pubKeys, privKeys, keysetId };
}

export function verifyProof(proof: Proof, privKey: Uint8Array): boolean {
	const Y: ProjPointType<bigint> = hashToCurve(proof.secret);
	const aY: ProjPointType<bigint> = Y.multiply(bytesToNumber(privKey));
	return aY.equals(proof.C);
}
