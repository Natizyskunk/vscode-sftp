export interface DatabaseConfig {
  host: string;
  port: number;
  username: string;
  password: string;
  database: string;
}

export interface TableInfo {
  name: string;
  engine: string;
  rowCount: number;
  dataLength: number;
  comment: string;
}

export interface ColumnInfo {
  name: string;
  type: string;
  nullable: string;
  key: string;
  defaultValue: string | null;
  extra: string;
  comment: string;
}

export interface IndexInfo {
  name: string;
  columns: string[];
  unique: boolean;
  type: string;
}

export interface QueryResult {
  columns: string[];
  rows: any[][];
  rowCount: number;
  affectedRows: number;
  executionTime: number;
}
