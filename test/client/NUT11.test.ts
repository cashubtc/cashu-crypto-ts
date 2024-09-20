import { schnorr } from '@noble/curves/secp256k1';
import { createP2PKsecret, getSignedProof } from '../../src/client/NUT11.js';
import { bytesToHex } from '@noble/curves/abstract/utils';
import { Proof, pointFromHex } from '../../src/common';
import { parseSecret } from '../../src/common/NUT11.js';
import { verifyP2PKSig, verifyP2PKSigOutput } from '../../src/mint/NUT11.js';
import { createRandomBlindedMessage } from '../../src/client/index.js';

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
	test('sign and verify blindedMessage', async () => {
		const blindedMessage = createRandomBlindedMessage(PRIVKEY);
		const verify = verifyP2PKSigOutput(blindedMessage, bytesToHex(PUBKEY));
		expect(verify).toBe(true);
	});
});
