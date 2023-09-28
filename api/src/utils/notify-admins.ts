import type { Notification } from '@directus/types';
import { isInstalled } from '../database/index.js';
import { NotificationsService } from '../services/notifications.js';
import { UsersService } from '../services/users.js';
import { getSchema } from './get-schema.js';

/**
 * Creates a new notification for all admin users
 * @param title The subject of the notification
 * @param message The message of the notification
 * @param uid A unique identifier for the notification to not send it multiple times. Should not start with '/'.
 */
export async function notifyAdmins(title: string, message: string, uid: string) {
	if ((await isInstalled()) === false) return;

	const schema = await getSchema();

	const notificationsService = new NotificationsService({ schema });

	const usersService = new UsersService({ schema });

	const adminUsers = await usersService.readByQuery({
		filter: {
			role: {
				admin_access: {
					_eq: true,
				},
			},
		},
	});

	const receivedAdminUsers = (
		await notificationsService.readByQuery({
			filter: {
				recipient: {
					_in: adminUsers.map((user) => user['id']),
				},
				item: {
					_eq: uid,
				},
			},
		})
	).map((notification) => notification['recipient']);

	const messages = adminUsers.reduce<Partial<Notification>[]>((acc, user) => {
		if (receivedAdminUsers.includes(user['id']) === false) {
			acc.push({
				recipient: user['id'],
				subject: title,
				message,
				status: 'inbox',
				item: uid,
			});
		}

		return acc;
	}, []);

	notificationsService.createMany(messages);
}
