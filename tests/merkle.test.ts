import { describe, it, expect } from "vitest";
import { test as fcTest } from "@fast-check/vitest";
import fc from "fast-check";
import {
    makeMerkleTree,
    getProof,
    processProof,
    getMultiProof,
    processMultiProof,
    isValidMerkleTree,
    renderMerkleTree,
    type JsMultiProof,
} from "../index.js";

const ZERO_NODE: number[] = Array.from({ length: 32 }, () => 0);

function bytesEqual(a: number[], b: number[]): boolean {
    if (a.length !== b.length) return false;
    return a.every((v, i) => v === b[i]);
}

const leaf = fc
    .uint8Array({ minLength: 32, maxLength: 32 })
    .map((arr) => Array.from(arr));
const leaves = fc.array(leaf, { minLength: 1 });
const leavesAndIndex = leaves.chain((xs) =>
    fc.tuple(fc.constant(xs), fc.nat({ max: xs.length - 1 }))
);
const leavesAndIndices = leaves.chain((xs) =>
    fc.tuple(fc.constant(xs), fc.uniqueArray(fc.nat({ max: xs.length - 1 })))
);

fc.configureGlobal({ numRuns: process.env.CI ? 10000 : 100 });

describe("Property-based tests", () => {
    // @ts-ignore
    fcTest.prop([leavesAndIndex])(
        "a leaf of a tree is provable",
        ([leaves, leafIndex]) => {
            const tree = makeMerkleTree(leaves);
            const root = tree[0];
            expect(root).toBeDefined();

            const treeIndex = tree.length - 1 - leafIndex;
            const proof = getProof(tree, treeIndex);
            const leafNode = leaves[leafIndex]!;
            const computed = processProof(leafNode, proof);

            expect(bytesEqual(root, computed)).toBe(true);
        }
    );

    // @ts-ignore
    fcTest.prop([leavesAndIndices])(
        "a subset of leaves of a tree are provable",
        ([leaves, leafIndices]) => {
            const tree = makeMerkleTree(leaves);
            const root = tree[0];
            expect(root).toBeDefined();

            const treeIndices = leafIndices.map((i) => tree.length - 1 - i);
            const proof = getMultiProof(tree, treeIndices);

            expect(proof.leaves.length).toBe(leafIndices.length);
            expect(
                leafIndices.every((i) =>
                    proof.leaves.some((l) => bytesEqual(l, leaves[i]!))
                )
            ).toBe(true);

            const computed = processMultiProof(proof);
            expect(bytesEqual(root, computed)).toBe(true);
        }
    );
});

describe("Error cases", () => {
    it("zero leaves", () => {
        expect(() => makeMerkleTree([])).toThrow(
            "Expected non-zero number of leaves"
        );
    });

    it("invalid leaf format", () => {
        expect(() => makeMerkleTree([[0]])).toThrow();
    });

    it("multiproof duplicate index", () => {
        const tree = makeMerkleTree([ZERO_NODE, ZERO_NODE]);
        expect(() => getMultiProof(tree, [1, 1])).toThrow(
            "Cannot prove duplicated index"
        );
    });

    it("getProof for internal node", () => {
        const tree = makeMerkleTree([ZERO_NODE, ZERO_NODE]);
        expect(() => getProof(tree, 0)).toThrow("Expected leaf node");
    });
});

describe("Tree validity", () => {
    it("returns false for empty tree", () => {
        expect(isValidMerkleTree([])).toBe(false);
    });

    it("returns false for invalid node (wrong length)", () => {
        expect(isValidMerkleTree([[0]])).toBe(false);
    });

    it("returns false for even number of nodes", () => {
        expect(isValidMerkleTree([ZERO_NODE, ZERO_NODE])).toBe(false);
    });

    it("returns false when inner node is not hash of children", () => {
        expect(isValidMerkleTree([ZERO_NODE, ZERO_NODE, ZERO_NODE])).toBe(
            false
        );
    });

    it("renderMerkleTree throws on empty tree", () => {
        expect(() => renderMerkleTree([])).toThrow(
            "Expected non-zero number of nodes"
        );
    });
});

describe("Multiproof invariants", () => {
    it("throws on invalid proof flags", () => {
        const badMp: JsMultiProof = {
            leaves: [ZERO_NODE, ZERO_NODE],
            proof: [ZERO_NODE, ZERO_NODE],
            proofFlags: [true, true, false],
        };
        expect(() => processMultiProof(badMp)).toThrow("Invariant error");
    });
});

describe("Render tree", () => {
    it("should render a valid tree without throwing", () => {
        const tree = makeMerkleTree([ZERO_NODE, ZERO_NODE]);
        const output = renderMerkleTree(tree);
        expect(typeof output).toBe("string");
        expect(output.length).toBeGreaterThan(0);
    });
});
