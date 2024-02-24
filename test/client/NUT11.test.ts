import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { createP2PKsecret, getSignedProof } from '../../src/client/NUT11';
import { bytesToHex } from '@noble/curves/abstract/utils';
import { Proof } from '../../src/types/common';
import { pointFromHex } from '../../src/common/common';
import { parseSecret } from '../../src/common/NUT11';
import { verifyP2PKSig } from '../../src/mint/NUT11';

const PRIVKEY = schnorr.utils.randomPrivateKey();
const PUBKEY = schnorr.getPublicKey(PRIVKEY);

describe('test create p2pk secret', () => {
	test('create from key', async () => {
		const secret = createP2PKsecret(bytesToHex(PUBKEY));
		const decodedSecret = parseSecret(secret);

		expect(decodedSecret[0]).toBe('P2PK');
		// console.log(JSON.stringify(decodedSecret))
		expect(Object.keys(decodedSecret[1]).includes('nonce')).toBe(true);
		expect(Object.keys(decodedSecret[1]).includes('data')).toBe(true);
	});
	test('sign and verify proof', async () => {
		const secretStr = `["P2PK",{"nonce":"76f5bf3e36273bf1a09006ef32d4551c07a34e218c2fc84958425ad00abdfe06","data":"${bytesToHex(
			PUBKEY
		)}"}]`;
		const proof: Proof = {
			amount: 1,
			C: pointFromHex('034268c0bd30b945adf578aca2dc0d1e26ef089869aaf9a08ba3a6da40fda1d8be'),
			id: '00000000000',
			secret: new TextEncoder().encode(secretStr)
		};
		const signedProof = getSignedProof(proof, PRIVKEY);
		const verify = verifyP2PKSig(signedProof);
		expect(verify).toBe(true);
	});
});
