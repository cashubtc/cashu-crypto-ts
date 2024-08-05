import { createBlindSignature } from '../../src/mint';
import { createDLEQProof } from '../../src/mint/NUT12';
import { verifyDLEQProof, verifyDLEQProof_reblind } from '../../src/client/NUT12';
import { constructProofFromPromise, createRandomBlindedMessage } from '../../src/client';
import { secp256k1 } from '@noble/curves/secp256k1';
import { pointFromBytes } from '../../src/common';

describe('test DLEQ scheme', () => {
    test('test DLEQ scheme: Alice verifies', async () => {
        const mintPrivKey = secp256k1.utils.randomPrivateKey();
		const mintPubKey = pointFromBytes(secp256k1.getPublicKey(mintPrivKey, true));

        // Wallet(Alice)
		const blindMessage = createRandomBlindedMessage();

        // Mint
        const blindSignature = createBlindSignature(blindMessage.B_, mintPrivKey, 1, '');
		const dleqProof = createDLEQProof(blindMessage.B_, mintPrivKey);

        // Wallet(Alice)
        const isValid = verifyDLEQProof(dleqProof, blindMessage.B_, blindSignature.C_, mintPubKey);
        expect(isValid).toBe(true);
    });
    test('test DLEQ scheme: Carol verifies', async () => {
        const mintPrivKey = secp256k1.utils.randomPrivateKey();
		const mintPubKey = pointFromBytes(secp256k1.getPublicKey(mintPrivKey, true));

        // Wallet(Alice)
		const blindMessage = createRandomBlindedMessage();

        // Mint
        const blindSignature = createBlindSignature(blindMessage.B_, mintPrivKey, 1, '');
		let dleqProof = createDLEQProof(blindMessage.B_, mintPrivKey);

        // Wallet(Alice)
        const proof = constructProofFromPromise(
			blindSignature,
			blindMessage.r,
			blindMessage.secret,
			mintPubKey
		);
        dleqProof.r = blindMessage.r;

        // Wallet(Carol)
        const isValid = verifyDLEQProof_reblind(blindMessage.secret, dleqProof, proof.C, mintPubKey);
        expect(isValid).toBe(true);
    });
});