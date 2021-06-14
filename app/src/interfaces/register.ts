import api from '@/api';
import { getRootPath } from '@/utils/get-root-path';
import { asyncPool } from '@/utils/async-pool';
import { App } from 'vue';
import { getInterfaces } from './index';
import { InterfaceConfig } from './types';

const { interfacesRaw } = getInterfaces();

export async function registerInterfaces(app: App): Promise<void> {
	const interfaceModules = import.meta.globEager('./*/**/index.ts');

	const interfaces: InterfaceConfig[] = Object.values(interfaceModules).map((module) => module.default);

	try {
		const customResponse = await api.get('/extensions/interfaces/');
		const customInterfaces: string[] = customResponse.data.data || [];

		await asyncPool(5, customInterfaces, async (interfaceName) => {
			try {
				const result = await import(
					/* @vite-ignore */ `${getRootPath()}extensions/interfaces/${interfaceName}/index.js`
				);
				interfaces.push(result.default);
			} catch (err) {
				// eslint-disable-next-line no-console
				console.warn(`Couldn't load custom interface "${interfaceName}":`, err);
			}
		});
	} catch {
		// eslint-disable-next-line no-console
		console.warn(`Couldn't load custom interfaces`);
	}

	interfacesRaw.value = interfaces;

	interfacesRaw.value.forEach((inter: InterfaceConfig) => {
		app.component('interface-' + inter.id, inter.component);

		if (typeof inter.options !== 'function' && Array.isArray(inter.options) === false) {
			app.component(`interface-options-${inter.id}`, inter.options);
		}
	});
}
