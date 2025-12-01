/**
 * Storage adapters for cross-platform credential persistence
 * Supports IndexedDB (browser), AsyncStorage (React Native), and in-memory (Node.js)
 */

import type { StorageAdapter } from "../types";
import { StorageError } from "../errors";

const STORAGE_PREFIX = "l8zk:";

/**
 * IndexedDB storage adapter for browsers
 */
export class IndexedDBAdapter implements StorageAdapter {
    private dbName = "l8zk-sdk";
    private storeName = "credentials";
    private db: IDBDatabase | null = null;

    private async getDB(): Promise<IDBDatabase> {
        if (this.db) return this.db;

        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, 1);

            request.onerror = () => {
                reject(new StorageError("Failed to open IndexedDB"));
            };

            request.onsuccess = () => {
                this.db = request.result;
                resolve(this.db);
            };

            request.onupgradeneeded = (event) => {
                const db = (event.target as IDBOpenDBRequest).result;
                if (!db.objectStoreNames.contains(this.storeName)) {
                    db.createObjectStore(this.storeName);
                }
            };
        });
    }

    async get(key: string): Promise<Uint8Array | null> {
        const db = await this.getDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(this.storeName, "readonly");
            const store = transaction.objectStore(this.storeName);
            const request = store.get(STORAGE_PREFIX + key);

            request.onerror = () =>
                reject(new StorageError(`Failed to get key: ${key}`));
            request.onsuccess = () => {
                const result = request.result;
                resolve(result ? new Uint8Array(result) : null);
            };
        });
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        const db = await this.getDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(this.storeName, "readwrite");
            const store = transaction.objectStore(this.storeName);
            const request = store.put(Array.from(value), STORAGE_PREFIX + key);

            request.onerror = () =>
                reject(new StorageError(`Failed to set key: ${key}`));
            request.onsuccess = () => resolve();
        });
    }

    async delete(key: string): Promise<void> {
        const db = await this.getDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(this.storeName, "readwrite");
            const store = transaction.objectStore(this.storeName);
            const request = store.delete(STORAGE_PREFIX + key);

            request.onerror = () =>
                reject(new StorageError(`Failed to delete key: ${key}`));
            request.onsuccess = () => resolve();
        });
    }

    async keys(): Promise<string[]> {
        const db = await this.getDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(this.storeName, "readonly");
            const store = transaction.objectStore(this.storeName);
            const request = store.getAllKeys();

            request.onerror = () =>
                reject(new StorageError("Failed to get keys"));
            request.onsuccess = () => {
                const allKeys = request.result as string[];
                const filteredKeys = allKeys
                    .filter(
                        (k) =>
                            typeof k === "string" &&
                            k.startsWith(STORAGE_PREFIX)
                    )
                    .map((k) => k.slice(STORAGE_PREFIX.length));
                resolve(filteredKeys);
            };
        });
    }
}

/**
 * In-memory storage adapter for Node.js and testing
 */
export class MemoryAdapter implements StorageAdapter {
    private store = new Map<string, Uint8Array>();

    async get(key: string): Promise<Uint8Array | null> {
        return this.store.get(key) || null;
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        this.store.set(key, value);
    }

    async delete(key: string): Promise<void> {
        this.store.delete(key);
    }

    async keys(): Promise<string[]> {
        return Array.from(this.store.keys());
    }

    clear(): void {
        this.store.clear();
    }
}

/**
 * React Native AsyncStorage adapter
 * Requires @react-native-async-storage/async-storage to be installed
 */
export class AsyncStorageAdapter implements StorageAdapter {
    private asyncStorage: any;

    constructor() {
        try {
            this.asyncStorage =
                require("@react-native-async-storage/async-storage").default;
        } catch {
            throw new StorageError(
                "AsyncStorage not available. Install @react-native-async-storage/async-storage for React Native support."
            );
        }
    }

    async get(key: string): Promise<Uint8Array | null> {
        const value = await this.asyncStorage.getItem(STORAGE_PREFIX + key);
        if (!value) return null;

        const parsed = JSON.parse(value);
        return new Uint8Array(parsed);
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        const serialized = JSON.stringify(Array.from(value));
        await this.asyncStorage.setItem(STORAGE_PREFIX + key, serialized);
    }

    async delete(key: string): Promise<void> {
        await this.asyncStorage.removeItem(STORAGE_PREFIX + key);
    }

    async keys(): Promise<string[]> {
        const allKeys: string[] = await this.asyncStorage.getAllKeys();
        return allKeys
            .filter((k) => k.startsWith(STORAGE_PREFIX))
            .map((k) => k.slice(STORAGE_PREFIX.length));
    }
}

/**
 * Detect and create the appropriate storage adapter for the current environment
 */
export function createDefaultAdapter(): StorageAdapter {
    // Browser with IndexedDB
    if (typeof indexedDB !== "undefined") {
        return new IndexedDBAdapter();
    }

    // React Native
    if (
        typeof navigator !== "undefined" &&
        navigator.product === "ReactNative"
    ) {
        try {
            return new AsyncStorageAdapter();
        } catch {
            // Fall through to memory adapter
        }
    }

    // Node.js or fallback
    return new MemoryAdapter();
}
