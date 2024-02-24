import { Keyset, MintKeys } from './common.js';

export type KeysetPair = {
	keysetId: string;
	pubKeys: MintKeys;
	privKeys: MintKeys;
};

export type KeysetWithKeys = Keyset & {
	pubKeys: MintKeys;
};
