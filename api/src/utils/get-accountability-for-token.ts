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
import type { Knex } from 'knex';
import jwt from 'jsonwebtoken';

async function tryExternalId(token: string, database: Knex)  {
	const logger = useLogger();

	let jwtPayload;

    try {

        jwtPayload = jwt.decode(token) as { sub?: string };

	} catch (err) {
		if (err instanceof Error) {
			logger.error(`[OpenID] Failed to decode JWT: ${err.message}`);
		} else {
			logger.error(`[OpenID] Failed to decode JWT: Unknown error`);
		}

		throw new InvalidCredentialsError();
	}

	const identifier = jwtPayload?.sub ? String(jwtPayload.sub) : null;

	logger.debug(`Sub Identifier:${identifier}`);

	if (!identifier) {
		logger.warn(`[OpenID] Failed to find user identifier"`);
		throw new InvalidCredentialsError();
	}

	const user = await database
		.select('id', 'role')
		.from('directus_users')
		.whereRaw('LOWER(??) = ?', ['external_identifier', identifier.toLowerCase()])
		.first();

	logger.debug(`external id User ID: ${user}`);

	return user
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

	logger.debug(`get Accountability Token JWT: ${token}`);

	if (token) {
		if (isDirectusJWT(token)) {
			const payload = verifyAccessJWT(token, getSecret());

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

			logger.debug(`User By Token: ${JSON.stringify(user)}`);


			if (!user) {
				user = await tryExternalId(token, database);

				if (!user) {
					throw new InvalidCredentialsError();
				}
			}

			logger.debug(`User ID: ${user.id}`);
			logger.debug(`User Role: ${user.role}`);

			accountability.user = user.id;
			accountability.role = user.role;
			accountability.roles = await fetchRolesTree(user.role, database);

			const { admin, app } = await fetchGlobalAccess(accountability, database);

			accountability.admin = admin;
			accountability.app = app;
		}
	}

	return accountability;
}
