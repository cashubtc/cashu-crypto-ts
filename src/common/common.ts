import { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { bytesToNumber, encodeBase64toUint8, hexToNumber } from '../util/utils';
import { MintKeys, SerializedMintKeys } from '../types/common';

const DOMAIN_SEPARATOR = hexToBytes('536563703235366b315f48617368546f43757276655f43617368755f');

export function hashToCurve(secret: Uint8Array): ProjPointType<bigint> {
	const msgToHash = sha256(Buffer.concat([DOMAIN_SEPARATOR, secret]));
	const counter = new Uint32Array(1);
	const maxIterations = 2 ** 16;
	for (let i = 0; i < maxIterations; i++) {
		const counterBytes = new Uint8Array(counter.buffer);
		const hash = sha256(Buffer.concat([msgToHash, counterBytes]));
		try {
			return pointFromHex(bytesToHex(Buffer.concat([new Uint8Array([0x02]), hash])));
		} catch (error) {
			counter[0]++;
		}
	}
	throw new Error('No valid point found');
}

export function pointFromHex(hex: string) {
	return secp256k1.ProjectivePoint.fromHex(hex);
}

export const getKeysetIdInt = (keysetId: string): bigint => {
	let keysetIdInt: bigint;
	if (/^[a-fA-F0-9]+$/.test(keysetId)) {
		keysetIdInt = hexToNumber(keysetId) % BigInt(2 ** 31 - 1);
	} else {
		//legacy keyset compatibility
		keysetIdInt = bytesToNumber(encodeBase64toUint8(keysetId)) % BigInt(2 ** 31 - 1);
	}
	return keysetIdInt;
};

export function createRandomPrivateKey() {
	return secp256k1.utils.randomPrivateKey();
}

export function serializeMintKeys(mintKeys: MintKeys): SerializedMintKeys {
	const serializedMintKeys: SerializedMintKeys = {};
	Object.keys(mintKeys).forEach((p)=>{		
			serializedMintKeys[p] = bytesToHex(mintKeys[p]);
	})
	return serializedMintKeys;
}

export function deserializeMintKeys(serializedMintKeys: SerializedMintKeys): MintKeys {
	const mintKeys: MintKeys = {};
	Object.keys(serializedMintKeys).forEach((p)=>{		
		mintKeys[p] = hexToBytes(serializedMintKeys[p]);
})
	return mintKeys;
}

export function deriveKeysetId(keys: MintKeys): string {
	const KEYSET_VERSION = '00'
	const mapBigInt = (k: [string, string]):[bigint,string]=>{return [BigInt(k[0]),k[1]]}
	const pubkeysConcat = Object.entries(serializeMintKeys(keys)).map(mapBigInt)
		.sort((a, b) => (a[0] < b[0]) ? -1 : ((a[0] > b[0]) ? 1 : 0))
		.map(([, pubKey]) => pubKey)
		.join('');
	const hash = sha256(pubkeysConcat);
	// return Buffer.from(hash).toString('base64').slice(0, 12);
	return KEYSET_VERSION + bytesToHex(hash).slice(0, 14); // new version
}