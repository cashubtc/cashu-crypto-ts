import { Keyset, MintKeys } from './common';

export type KeysetPair = {
	keysetId: string;
	pubKeys: MintKeys;
	privKeys: MintKeys;
};

export type KeysetWithKeys = Keyset & {
	pubKeys: MintKeys;
};
