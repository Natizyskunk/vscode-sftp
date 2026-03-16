import * as mysql from 'mysql2/promise';
import { DatabaseConfig, TableInfo, ColumnInfo, IndexInfo, QueryResult } from './types';
import logger from '../../logger';

export class DatabaseClient {
  private _pool: mysql.Pool | null = null;
  private _config: DatabaseConfig;
  private _connectHost: string;
  private _connectPort: number;

  constructor(config: DatabaseConfig, connectHost?: string, connectPort?: number) {
    this._config = config;
    this._connectHost = connectHost || config.host;
    this._connectPort = connectPort || config.port;
  }

  private _getPool(): mysql.Pool {
    if (!this._pool) {
      this._pool = mysql.createPool({
        host: this._connectHost,
        port: this._connectPort,
        user: this._config.username,
        password: this._config.password,
        database: this._config.database,
        connectionLimit: 5,
        connectTimeout: 10000,
      });
    }
    return this._pool;
  }

  async getTables(): Promise<TableInfo[]> {
    const pool = this._getPool();
    const [rows] = await pool.query(
      `SELECT TABLE_NAME as name, ENGINE as engine,
              TABLE_ROWS as rowCount, DATA_LENGTH as dataLength,
              TABLE_COMMENT as comment
       FROM INFORMATION_SCHEMA.TABLES
       WHERE TABLE_SCHEMA = ?
       ORDER BY TABLE_NAME`,
      [this._config.database]
    );
    return rows as TableInfo[];
  }

  async getColumns(table: string): Promise<ColumnInfo[]> {
    const pool = this._getPool();
    const [rows] = await pool.query(
      `SELECT COLUMN_NAME as name, COLUMN_TYPE as type,
              IS_NULLABLE as nullable, COLUMN_KEY as \`key\`,
              COLUMN_DEFAULT as defaultValue, EXTRA as extra,
              COLUMN_COMMENT as comment
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
       ORDER BY ORDINAL_POSITION`,
      [this._config.database, table]
    );
    return rows as ColumnInfo[];
  }

  async getIndexes(table: string): Promise<IndexInfo[]> {
    const pool = this._getPool();
    const [rows] = await pool.query('SHOW INDEX FROM ??', [table]) as any;
    const grouped: Map<string, IndexInfo> = new Map();
    for (const row of rows as any[]) {
      const name = row.Key_name;
      if (!grouped.has(name)) {
        grouped.set(name, {
          name,
          columns: [],
          unique: row.Non_unique === 0,
          type: row.Index_type,
        });
      }
      grouped.get(name)!.columns.push(row.Column_name);
    }
    return Array.from(grouped.values());
  }

  async getData(
    table: string,
    page: number,
    pageSize: number
  ): Promise<{ columns: string[]; rows: any[][]; total: number }> {
    const pool = this._getPool();
    const offset = (page - 1) * pageSize;

    const [countResult] = await pool.query(
      'SELECT COUNT(*) as cnt FROM ??',
      [table]
    );
    const total = (countResult as any[])[0].cnt;

    const [rows, fields] = await pool.query(
      'SELECT * FROM ?? LIMIT ? OFFSET ?',
      [table, pageSize, offset]
    );
    const columns = (fields as any[]).map(f => f.name);
    const dataRows = (rows as any[]).map(row =>
      columns.map(col => row[col])
    );

    return { columns, rows: dataRows, total };
  }

  async executeQuery(sql: string): Promise<QueryResult> {
    const pool = this._getPool();
    const start = Date.now();
    const [result, fields] = await pool.query(sql);
    const executionTime = Date.now() - start;

    if (Array.isArray(result)) {
      const columns = fields ? (fields as any[]).map(f => f.name) : [];
      const rows = (result as any[]).map(row =>
        columns.map(col => row[col])
      );
      return {
        columns,
        rows,
        rowCount: rows.length,
        affectedRows: 0,
        executionTime,
      };
    }

    return {
      columns: [],
      rows: [],
      rowCount: 0,
      affectedRows: (result as any).affectedRows || 0,
      executionTime,
    };
  }

  async testConnection(): Promise<boolean> {
    try {
      const pool = this._getPool();
      await pool.query('SELECT 1');
      return true;
    } catch (err) {
      logger.error(err, 'Database connection test failed');
      return false;
    }
  }

  async dispose() {
    if (this._pool) {
      await this._pool.end();
      this._pool = null;
    }
  }
}
