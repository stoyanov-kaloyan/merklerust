import { bench, describe } from "vitest";
import { randomBytes, createHash } from "node:crypto";

// Our Rust-powered implementation
import {
    makeMerkleTree as rustMakeMerkleTree,
    getProof as rustGetProof,
    processProof as rustProcessProof,
    getMultiProof as rustGetMultiProof,
    processMultiProof as rustProcessMultiProof,
} from "../index.js";

import { StandardMerkleTree } from "@openzeppelin/merkle-tree";

import { MerkleTree } from "merkletreejs";

function generateLeaves(count: number): number[][] {
    return Array.from({ length: count }, () => Array.from(randomBytes(32)));
}

function generateOzLeaves(count: number): [string][] {
    return Array.from({ length: count }, () => [
        "0x" + randomBytes(32).toString("hex"),
    ]);
}

function generateBufferLeaves(count: number): Buffer[] {
    return Array.from({ length: count }, () => randomBytes(32));
}

function sha256(data: Buffer): Buffer {
    return createHash("sha256").update(data).digest();
}

const SIZES = [100, 1_000, 10_000, 100_000];

for (const size of SIZES) {
    describe(`Tree construction (${size.toLocaleString()} leaves)`, () => {
        const rustLeaves = generateLeaves(size);
        const ozLeaves = generateOzLeaves(size);
        const bufferLeaves = generateBufferLeaves(size);

        bench("merklerust (Rust/napi)", () => {
            rustMakeMerkleTree(rustLeaves);
        });

        bench("@openzeppelin/merkle-tree (JS)", () => {
            StandardMerkleTree.of(ozLeaves, ["bytes32"]);
        });

        bench("merkletreejs (JS)", () => {
            new MerkleTree(bufferLeaves, sha256, { sortPairs: true });
        });
    });

    describe(`Single proof generation (${size.toLocaleString()} leaves)`, () => {
        const rustLeaves = generateLeaves(size);
        const ozLeaves = generateOzLeaves(size);
        const bufferLeaves = generateBufferLeaves(size);

        const rustTree = rustMakeMerkleTree(rustLeaves);
        const ozTree = StandardMerkleTree.of(ozLeaves, ["bytes32"]);
        const mjsTree = new MerkleTree(bufferLeaves, sha256, {
            sortPairs: true,
        });

        const leafIndex = Math.floor(size / 2);
        const rustTreeIndex = rustTree.length - 1 - leafIndex;

        bench("merklerust (Rust/napi)", () => {
            rustGetProof(rustTree, rustTreeIndex);
        });

        bench("@openzeppelin/merkle-tree (JS)", () => {
            ozTree.getProof(leafIndex);
        });

        bench("merkletreejs (JS)", () => {
            mjsTree.getProof(bufferLeaves[leafIndex]);
        });
    });

    describe(`Single proof verification (${size.toLocaleString()} leaves)`, () => {
        const rustLeaves = generateLeaves(size);
        const ozLeaves = generateOzLeaves(size);
        const bufferLeaves = generateBufferLeaves(size);

        const rustTree = rustMakeMerkleTree(rustLeaves);
        const ozTree = StandardMerkleTree.of(ozLeaves, ["bytes32"]);
        const mjsTree = new MerkleTree(bufferLeaves, sha256, {
            sortPairs: true,
        });

        const leafIndex = Math.floor(size / 2);
        const rustTreeIndex = rustTree.length - 1 - leafIndex;

        const rustProof = rustGetProof(rustTree, rustTreeIndex);
        const rustLeaf = rustLeaves[leafIndex];

        const ozProof = ozTree.getProof(leafIndex);
        const ozLeaf = ozLeaves[leafIndex];

        const mjsProof = mjsTree.getProof(bufferLeaves[leafIndex]);
        const mjsRoot = mjsTree.getRoot();

        bench("merklerust (Rust/napi)", () => {
            rustProcessProof(rustLeaf, rustProof);
        });

        bench("@openzeppelin/merkle-tree (JS)", () => {
            StandardMerkleTree.verify(
                ozTree.root,
                ["bytes32"],
                ozLeaf,
                ozProof
            );
        });

        bench("merkletreejs (JS)", () => {
            mjsTree.verify(mjsProof, bufferLeaves[leafIndex], mjsRoot);
        });
    });
}

const MULTI_SIZES = [100, 1_000, 10_000];
const PROOF_SUBSET_RATIO = 0.1;

for (const size of MULTI_SIZES) {
    const subsetSize = Math.max(1, Math.floor(size * PROOF_SUBSET_RATIO));

    describe(`Multi-proof generation (${size.toLocaleString()} leaves, ${subsetSize} proofs)`, () => {
        const rustLeaves = generateLeaves(size);
        const bufferLeaves = generateBufferLeaves(size);

        const rustTree = rustMakeMerkleTree(rustLeaves);
        const mjsTree = new MerkleTree(bufferLeaves, sha256, {
            sortPairs: true,
        });

        const leafIndices = Array.from({ length: subsetSize }, (_, i) =>
            Math.floor((i * size) / subsetSize)
        );
        const rustTreeIndices = leafIndices.map((i) => rustTree.length - 1 - i);
        const mjsLeafSubset = leafIndices.map((i) => bufferLeaves[i]);

        bench("merklerust (Rust/napi)", () => {
            rustGetMultiProof(rustTree, rustTreeIndices);
        });

        bench("merkletreejs (JS)", () => {
            mjsTree.getMultiProof(mjsLeafSubset);
        });
    });

    describe(`Multi-proof verification (${size.toLocaleString()} leaves, ${subsetSize} proofs)`, () => {
        const rustLeaves = generateLeaves(size);
        const bufferLeaves = generateBufferLeaves(size);

        const rustTree = rustMakeMerkleTree(rustLeaves);
        const mjsTree = new MerkleTree(bufferLeaves, sha256, {
            sortPairs: true,
        });

        const leafIndices = Array.from({ length: subsetSize }, (_, i) =>
            Math.floor((i * size) / subsetSize)
        );
        const rustTreeIndices = leafIndices.map((i) => rustTree.length - 1 - i);
        const mjsLeafSubset = leafIndices.map((i) => bufferLeaves[i]);

        const rustMultiProof = rustGetMultiProof(rustTree, rustTreeIndices);
        const mjsMultiProof = mjsTree.getMultiProof(mjsLeafSubset);
        const mjsRoot = mjsTree.getRoot();
        const mjsProofFlags = mjsTree.getProofFlags(
            mjsLeafSubset,
            mjsMultiProof
        );

        bench("merklerust (Rust/napi)", () => {
            rustProcessMultiProof(rustMultiProof);
        });

        // bench("merkletreejs (JS)", () => {
        //     mjsTree.verifyMultiProof(
        //         mjsRoot,
        //         mjsLeafSubset,
        //         mjsMultiProof,
        //         mjsProofFlags
        //     );
        // });
    });
}
