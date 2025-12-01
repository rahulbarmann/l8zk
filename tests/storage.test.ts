import { describe, it, expect, beforeEach } from "vitest";
import { MemoryAdapter } from "../src/storage/adapter";

describe("MemoryAdapter", () => {
    let adapter: MemoryAdapter;

    beforeEach(() => {
        adapter = new MemoryAdapter();
    });

    it("should store and retrieve values", async () => {
        const key = "test-key";
        const value = new Uint8Array([1, 2, 3, 4, 5]);

        await adapter.set(key, value);
        const retrieved = await adapter.get(key);

        expect(retrieved).toEqual(value);
    });

    it("should return null for non-existent keys", async () => {
        const result = await adapter.get("non-existent");
        expect(result).toBeNull();
    });

    it("should delete values", async () => {
        const key = "to-delete";
        const value = new Uint8Array([1, 2, 3]);

        await adapter.set(key, value);
        expect(await adapter.get(key)).toEqual(value);

        await adapter.delete(key);
        expect(await adapter.get(key)).toBeNull();
    });

    it("should list all keys", async () => {
        await adapter.set("key1", new Uint8Array([1]));
        await adapter.set("key2", new Uint8Array([2]));
        await adapter.set("key3", new Uint8Array([3]));

        const keys = await adapter.keys();

        expect(keys).toHaveLength(3);
        expect(keys).toContain("key1");
        expect(keys).toContain("key2");
        expect(keys).toContain("key3");
    });

    it("should overwrite existing values", async () => {
        const key = "overwrite";
        const value1 = new Uint8Array([1, 2, 3]);
        const value2 = new Uint8Array([4, 5, 6]);

        await adapter.set(key, value1);
        await adapter.set(key, value2);

        const retrieved = await adapter.get(key);
        expect(retrieved).toEqual(value2);
    });

    it("should clear all values", () => {
        adapter.set("key1", new Uint8Array([1]));
        adapter.set("key2", new Uint8Array([2]));

        adapter.clear();

        expect(adapter.keys()).resolves.toHaveLength(0);
    });
});
