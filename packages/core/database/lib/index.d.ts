import { LifecycleProvider } from './lifecycles';
import { MigrationProvider } from './migrations';
import { SchemaProvideer } from './schema';

type BooleanWhere<T> = {
  $and?: WhereParams<T>[];
  $or?: WhereParams<T>[];
  $not?: WhereParams<T>;
};

type WhereParams<T> = {
  [K in keyof T]?: T[K];
} &
  BooleanWhere<T>;

type Sortables<T> = {
  // check sortable
  [P in keyof T]: P;
}[keyof T];

type Direction = 'asc' | 'ASC' | 'DESC' | 'desc';

interface FindParams<T> {
  select?: (keyof T)[];
  // TODO: add nested operators & relations
  where?: WhereParams<T>;
  limit?: number;
  offset?: number;
  orderBy?: // TODO: add relations
  | Sortables<T>
    | Sortables<T>[]
    | { [K in Sortables<T>]?: Direction }
    | { [K in Sortables<T>]?: Direction }[];
  // TODO: define nested obj
  populate?: (keyof T)[];
}

interface CreateParams<T> {
  select?: (keyof T)[];
  populate?: (keyof T)[];
  data: T[keyof T];
}

interface CreateManyParams<T> {
  select?: (keyof T)[];
  populate?: (keyof T)[];
  data: T[keyof T][];
}

interface Pagination {
  page: number;
  pageSize: number;
  pageCount: number;
  total: number;
}

interface PopulateParams {}
interface EntityManager {
  findOne<K extends keyof AllTypes>(uid: K, params: FindParams<AllTypes[K]>): Promise<any>;
  findMany<K extends keyof AllTypes>(uid: K, params: FindParams<AllTypes[K]>): Promise<any[]>;

  create<K extends keyof AllTypes>(uid: K, params: CreateParams<AllTypes[K]>): Promise<any>;
  createMany<K extends keyof AllTypes>(
    uid: K,
    params: CreateManyParams<AllTypes[K]>
  ): Promise<{ count: number }>;

  update<K extends keyof AllTypes>(uid: K, params: any): Promise<any>;
  updateMany<K extends keyof AllTypes>(uid: K, params: any): Promise<{ count: number }>;

  delete<K extends keyof AllTypes>(uid: K, params: any): Promise<any>;
  deleteMany<K extends keyof AllTypes>(uid: K, params: any): Promise<{ count: number }>;

  count<K extends keyof AllTypes>(uid: K, params: any): Promise<number>;

  attachRelations<K extends keyof AllTypes>(uid: K, id: ID, data: any): Promise<any>;
  updateRelations<K extends keyof AllTypes>(uid: K, id: ID, data: any): Promise<any>;
  deleteRelations<K extends keyof AllTypes>(uid: K, id: ID): Promise<any>;

  populate<K extends keyof AllTypes, T extends AllTypes[K]>(
    uid: K,
    entity: T,
    populate: PopulateParams
  ): Promise<T>;

  load<K extends keyof AllTypes, T extends AllTypes[K], SK extends keyof T>(
    uid: K,
    entity: T,
    field: SK,
    populate: PopulateParams
  ): Promise<T[SK]>;
}

interface QueryFromContentType<T extends keyof AllTypes> {
  findOne(params: FindParams<AllTypes[T]>): Promise<any>;
  findMany(params: FindParams<AllTypes[T]>): Promise<any[]>;
  findWithCount(params: FindParams<AllTypes[T]>): Promise<[any[], number]>;
  findPage(params: FindParams<AllTypes[T]>): Promise<{ results: any[]; pagination: Pagination }>;

  create(params: CreateParams<AllTypes[T]>): Promise<any>;
  createMany(params: CreateManyParams<AllTypes[T]>): Promise<{ count: number }>;

  update(params: any): Promise<any>;
  updateMany(params: any): Promise<{ count: number }>;

  delete(params: any): Promise<any>;
  deleteMany(params: any): Promise<{ count: number }>;

  count(params: any): Promise<number>;

  attachRelations(id: ID, data: any): Promise<any>;
  updateRelations(id: ID, data: any): Promise<any>;
  deleteRelations(id: ID): Promise<any>;

  populate<S extends AllTypes[T]>(entity: S, populate: PopulateParams): Promise<S>;

  load<S extends AllTypes[T], K extends keyof S>(
    entity: S,
    field: K,
    populate: PopulateParams
  ): Promise<S[K]>;
}

interface ModelConfig {
  tableName: string;
  [k: string]: any;
}

interface ConnectionConfig {}

interface DatabaseConfig {
  connection: ConnectionConfig;
  models: ModelConfig[];
}
export interface Database {
  schema: SchemaProvideer;
  lifecycles: LifecycleProvider;
  migrations: MigrationProvider;
  entityManager: EntityManager;

  query<T extends keyof AllTypes>(uid: T): QueryFromContentType<T>;
}
export class Database implements Database {
  static transformContentTypes(contentTypes: any[]): ModelConfig[];
  static init(config: DatabaseConfig): Promise<Database>;
}
