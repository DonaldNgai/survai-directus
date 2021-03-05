import KnexMSSQL from 'knex-schema-inspector/dist/dialects/mssql';
import { SchemaOverview } from '../types/overview';
import { SchemaInspector } from '../types/schema';

export default class MSSQL extends KnexMSSQL implements SchemaInspector {
	// Overview
	// ===============================================================================================
	async overview(): Promise<SchemaOverview> {
		const columns = await this.knex.raw(
			`
			SELECT
				c.TABLE_NAME as table_name,
				c.COLUMN_NAME as column_name,
				c.COLUMN_DEFAULT as default_value,
				c.IS_NULLABLE as is_nullable,
				c.DATA_TYPE as data_type,
				pk.PK_SET as column_key
			FROM
				[${this.knex.client.database()}].INFORMATION_SCHEMA.COLUMNS as c
			LEFT JOIN (
				SELECT
					PK_SET = CASE WHEN CONSTRAINT_NAME LIKE '%pk%' THEN 'PRIMARY' ELSE NULL END
				FROM [${this.knex.client.database()}].INFORMATION_SCHEMA.KEY_COLUMN_USAGE
			) as pk
			ON [c].[TABLE_NAME] = [pk].[CONSTRAINT_TABLE_NAME]
			AND [c].[TABLE_CATALOG] = [pk].[CONSTRAINT_CATALOG]
			AND [c].[COLUMN_NAME] = [pk].[CONSTRAINT_COLUMN_NAME]
			`
		);
		const overview: SchemaOverview = {};
		for (const column of columns[0]) {
			if (column.table_name in overview === false) {
				overview[column.table_name] = {
					primary: columns[0].find((nested: { column_key: string; table_name: string }) => {
						return nested.table_name === column.table_name && nested.column_key === 'PRIMARY';
					})?.column_name,
					columns: {},
				};
			}
			overview[column.table_name].columns[column.column_name] = {
				...column,
				is_nullable: column.is_nullable === 'YES',
			};
		}
		return overview;
	}
}
