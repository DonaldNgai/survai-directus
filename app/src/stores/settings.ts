import { createStore } from 'pinia';
import api from '@/api';
import { i18n } from '@/lang';
import { merge } from 'lodash';
import { notify } from '@/utils/notify';

export const useSettingsStore = createStore({
	id: 'settingsStore',
	state: () => ({
		settings: null as null | Record<string, any>,
	}),
	actions: {
		async hydrate() {
			try {
				const response = await api.get(`/settings`);
				this.state.settings = response.data.data;
			} catch (err) {
				console.error(err);
			}
		},

		async dehydrate() {
			this.reset();
		},

		async updateSettings(updates: { [key: string]: any }) {
			const settingsCopy = { ...this.state.settings };
			const newSettings = merge({}, this.state.settings, updates);

			this.state.settings = newSettings;

			try {
				const response = await api.patch(`/settings`, updates);

				this.state.settings = response.data.data;

				notify({
					title: i18n.t('settings_update_success'),
					type: 'success',
				});
			} catch (error) {
				console.error(error);
				this.state.settings = settingsCopy;
			}
		},
	},
});
