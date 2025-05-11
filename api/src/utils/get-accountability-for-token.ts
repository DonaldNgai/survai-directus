import { InvalidCredentialsError } from '@directus/errors';
import type { Accountability } from '@directus/types';
import getDatabase from '../database/index.js';
import { fetchRolesTree } from '../permissions/lib/fetch-roles-tree.js';
import { fetchGlobalAccess } from '../permissions/modules/fetch-global-access/fetch-global-access.js';
import { createDefaultAccountability } from '../permissions/utils/create-default-accountability.js';
import { getSecret } from './get-secret.js';
import isDirectusJWT from './is-directus-jwt.js';
import { verifyAccessJWT } from './jwt.js';
import { verifySessionJWT } from './verify-session-jwt.js';
import { useLogger } from '../logger/index.js';

async function tryExternalId(token: string){
	const logger = useLogger();
	const jwt = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
	const identifier = jwt.sub ? String(jwt.sub) : null;

	logger.info('JWT:', jwt);

	if (!identifier) {
		logger.warn(`[OpenID] Failed to find user identifier"`);
		throw new InvalidCredentialsError();
	}

	logger.info('Identifier:', identifier);

	const userId = await this.fetchUserId(identifier);

	logger.info('User ID:', userId);

	return userId
}

export async function getAccountabilityForToken(
	token?: string | null,
	accountability?: Accountability,
): Promise<Accountability> {
	if (!accountability) {
		accountability = createDefaultAccountability();
	}

	// Try finding the user with the provided token
	const database = getDatabase();
	const logger = useLogger();

	logger.info("Token:", token?.toString());

	if (token) {
		if (isDirectusJWT(token)) {
			const payload = verifyAccessJWT(token, getSecret());
			logger.info('Accountability payload inside DirectusJWT:', payload.toString());

			if ('session' in payload) {
				await verifySessionJWT(payload);
				accountability.session = payload.session;
			}

			if (payload.share) accountability.share = payload.share;

			if (payload.id) accountability.user = payload.id;

			accountability.role = payload.role;
			accountability.roles = await fetchRolesTree(payload.role, database);

			const { admin, app } = await fetchGlobalAccess(accountability, database);

			accountability.admin = admin;
			accountability.app = app;
		} else {
			let user = await database
				.select('directus_users.id', 'directus_users.role')
				.from('directus_users')
				.where({
					'directus_users.token': token,
					status: 'active',
				})
				.first();

			logger.info("In Else for Accountability");
			logger.info('User:', user);


			if (!user) {
				user = await tryExternalId(token);

				if (!user) {
					throw new InvalidCredentialsError();
				}
			}

			logger.info('User ID:', user.id);
			logger.info('User ID:', user.role);

			accountability.user = user.id;
			accountability.role = user.role;
			accountability.roles = await fetchRolesTree(user.role, database);

			const { admin, app } = await fetchGlobalAccess(accountability, database);

			accountability.admin = admin;
			accountability.app = app;
		}

		logger.info('Accountability User:', accountability.user);
	}

	return accountability;
}
