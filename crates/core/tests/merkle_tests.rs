use merklerust_core::hashes::keccak256;
use merklerust_core::merkle::{
    get_multi_proof, get_proof, is_valid_merkle_tree, make_merkle_tree_bytes, process_multi_proof,
    process_proof, render_merkle_tree, Bytes,
};
use proptest::prelude::*;

fn node_hash(a: &[u8], b: &[u8]) -> Bytes {
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    keccak256(&[left, right].concat()).to_vec()
}

proptest! {
    #[test]
    fn leaf_of_tree_is_provable(leaves in prop::collection::vec(prop::collection::vec(any::<u8>(), 32), 1..=8)) {
        // pick an index within range
        let leaf_index = 0usize % leaves.len();
        let leaves_bytes: Vec<Bytes> = leaves.clone();

        let tree = make_merkle_tree_bytes(leaves_bytes.clone(), node_hash);
        let root = tree[0].clone();
        prop_assert!(root.len() > 0);

        // test for every leaf index we could pick one — here choose 0 to keep test simple
        let tree_index = tree.len() - 1 - leaf_index;
        let proof = get_proof(&tree, tree_index);
        let leaf = &leaves_bytes[leaf_index];
        let computed = process_proof(leaf, &proof, node_hash);
        prop_assert_eq!(root, computed);
    }

    #[test]
    fn subset_of_leaves_are_provable(leaves in prop::collection::vec(prop::collection::vec(any::<u8>(), 32), 1..=8)) {
        // build a random mask to select indices
        let len = leaves.len();
        let leaves_bytes: Vec<Bytes> = leaves.clone();

        // choose some indices deterministically for simplicity: pick first half non-empty
        let mut leaf_indices: Vec<usize> = (0..len).collect();
        leaf_indices.truncate((len+1)/2);

        let tree = make_merkle_tree_bytes(leaves_bytes.clone(), node_hash);
        let root = tree[0].clone();
        let tree_indices: Vec<usize> = leaf_indices.iter().map(|&i| tree.len()-1-i).collect();
        let proof = get_multi_proof(&tree, tree_indices.clone());
        assert_eq!(leaf_indices.len(), proof.leaves.len());
        for &idx in leaf_indices.iter() {
            assert!(proof.leaves.contains(&leaves_bytes[idx]));
        }
        let computed = process_multi_proof(&proof, node_hash);
        assert_eq!(root, computed);
    }
}

#[test]
#[should_panic(expected = "Expected non-zero number of leaves")]
fn zero_leaves() {
    let _ = make_merkle_tree_bytes(Vec::new(), node_hash);
}

#[test]
#[should_panic(expected = "Expected valid merkle node")]
fn invalid_leaf_format() {
    // leaf of wrong length
    let bad_leaf: Bytes = vec![0u8; 1];
    let _ = make_merkle_tree_bytes(vec![bad_leaf], node_hash);
}

#[test]
#[should_panic(expected = "Cannot prove duplicated index")]
fn multiproof_duplicate_index() {
    let zero: Bytes = vec![0u8; 32];
    let tree = make_merkle_tree_bytes(vec![zero.clone(), zero.clone()], node_hash);
    let _ = get_multi_proof(&tree, vec![1, 1]);
}

#[test]
fn tree_validity() {
    let zero: Bytes = vec![0u8; 32];
    assert_eq!(is_valid_merkle_tree(&Vec::new(), node_hash), false);
    assert_eq!(is_valid_merkle_tree(&vec![vec![0u8; 1]], node_hash), false);
    assert_eq!(
        is_valid_merkle_tree(&vec![zero.clone(), zero.clone()], node_hash),
        false
    );
    assert_eq!(
        is_valid_merkle_tree(&vec![zero.clone(), zero.clone(), zero.clone()], node_hash),
        false
    );
    // render empty should panic
    let res = std::panic::catch_unwind(|| render_merkle_tree(&Vec::new()));
    assert!(res.is_err());
}

#[test]
#[should_panic(expected = "Invariant error")]
fn multiproof_invariants() {
    let zero: Bytes = vec![0u8; 32];
    // tamper the proof to an invalid flags length and content (constructed directly)
    let bad_mp = &merklerust_core::merkle::MultiProof::new(
        vec![zero.clone(), zero.clone()],
        vec![zero.clone(), zero.clone()],
        vec![true, true, false],
    );
    let _ = process_multi_proof(bad_mp, node_hash);
}

#[test]
#[should_panic(expected = "Expected leaf node at index 0")]
fn get_proof_for_internal_node() {
    let zero: Bytes = vec![0u8; 32];
    let tree = make_merkle_tree_bytes(vec![zero.clone(), zero.clone()], node_hash);
    let _ = get_proof(&tree, 0);
}
