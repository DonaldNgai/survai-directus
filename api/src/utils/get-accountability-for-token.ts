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

	logger.info("Token:", token.toString());

	if (token) {
		if (isDirectusJWT(token)) {
			const payload = verifyAccessJWT(token, getSecret());
			logger.info('Accountability payload:', payload);

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
			const user = await database
				.select('directus_users.id', 'directus_users.role')
				.from('directus_users')
				.where({
					'directus_users.token': token,
					status: 'active',
				})
				.first();

			logger.info("In Else for Accountability");
			logger.info('User:', user);
			logger.info('User ID:', user.id);
			logger.info('User ID:', user.role);

			if (!user) {
				throw new InvalidCredentialsError();
			}

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
