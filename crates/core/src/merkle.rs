/// Binary data (owned)
pub type Bytes = Vec<u8>;

/// Returns true if the provided slice has length 32 (a standard hash length like SHA-256).
pub fn is_valid_merkle_node(data: &[u8]) -> bool {
    data.len() == 32
}

pub struct MultiProof {
    pub leaves: Vec<Bytes>,
    pub proof: Vec<Bytes>,
    pub proof_flags: Vec<bool>,
}

impl MultiProof {
    pub fn new(leaves: Vec<Bytes>, proof: Vec<Bytes>, proof_flags: Vec<bool>) -> Self {
        Self {
            leaves,
            proof,
            proof_flags,
        }
    }
}

fn left_child_index(index: usize) -> usize {
    2 * index + 1
}
fn right_child_index(index: usize) -> usize {
    2 * index + 2
}
fn parent_index(index: usize) -> usize {
    (index - 1) / 2
}
fn sibling_index(index: usize) -> usize {
    if index % 2 == 0 {
        index - 1
    } else {
        index + 1
    }
}

fn is_tree_node(index: usize, tree_len: usize) -> bool {
    index < tree_len
}
fn is_internal_node(index: usize, tree_len: usize) -> bool {
    is_tree_node(left_child_index(index), tree_len)
}
fn is_leaf_node(index: usize, tree_len: usize) -> bool {
    !is_internal_node(index, tree_len) && is_tree_node(index, tree_len)
}

fn assert_leaf_node(tree_len: usize, index: usize) {
    assert!(
        is_leaf_node(index, tree_len),
        "Expected leaf node at index {}",
        index
    );
}
fn assert_merkle_node(node: &[u8]) {
    assert!(
        is_valid_merkle_node(node),
        "Expected valid merkle node, got length {}",
        node.len(),
    );
}

/// Generic Merkle-tree builder: takes an iterator of leaves (owned values `T`) and a node-hash
/// function that combines two children into a parent. Returns the flat vector representing the
/// tree stored as a binary heap (root at index 0, leaves at the end).
pub fn make_merkle_tree<T, F>(leaves: Vec<T>, node_hash: F) -> Vec<T>
where
    F: Fn(&T, &T) -> T,
    T: Clone,
{
    assert!(!leaves.is_empty(), "Expected non-zero number of leaves");

    let mut tree = vec![leaves[0].clone(); 2 * leaves.len() - 1];
    let tree_len = tree.len();

    for (i, leaf) in leaves.iter().enumerate() {
        tree[tree_len - 1 - i] = leaf.clone();
    }
    for i in (0..(tree_len - leaves.len())).rev() {
        let left = tree[left_child_index(i)].clone();
        let right = tree[right_child_index(i)].clone();
        tree[i] = node_hash(&left, &right);
    }

    tree
}

pub fn get_proof(tree: &Vec<Bytes>, leaf_index: usize) -> Vec<Bytes> {
    assert_leaf_node(tree.len(), leaf_index);

    let mut proof = Vec::new();
    let mut index = leaf_index;

    while index > 0 {
        let s = sibling_index(index);
        if s < tree.len() {
            proof.push(tree[s].clone());
        }

        index = parent_index(index);
    }

    proof
}

/// Process a standard single-proof: start from `leaf` and apply the `node_hash` reductions
/// using the provided `proof` nodes. The `node_hash` function receives left/right child
/// byte slices and returns an owned `Bytes`.
pub fn process_proof<F>(leaf: &[u8], proof: &[Bytes], node_hash: F) -> Bytes
where
    F: Fn(&[u8], &[u8]) -> Bytes,
{
    // assert valid merkle node for leaf and each proof
    assert_merkle_node(leaf);
    for p in proof.iter() {
        assert_merkle_node(&p);
    }

    let mut computed_hash: Bytes = leaf.to_vec();

    for p in proof.iter() {
        // Use deterministic ordering of the pair so callers don't need to know tree index.
        // Compare bytewise and always pass the smaller-first to `node_hash`.
        computed_hash = if computed_hash.as_slice() <= p.as_slice() {
            node_hash(computed_hash.as_slice(), p.as_slice())
        } else {
            node_hash(p.as_slice(), computed_hash.as_slice())
        };
    }

    computed_hash
}

pub fn get_multi_proof(tree: &Vec<Bytes>, mut indices: Vec<usize>) -> MultiProof {
    for &i in indices.iter() {
        assert_leaf_node(tree.len(), i);
    }
    indices.sort_by(|a, b| b.cmp(a));

    for i in 1..indices.len() {
        assert!(
            indices[i] != indices[i - 1],
            "Cannot prove duplicated index"
        );
    }

    let mut stack = indices.clone(); // copy
    let mut proof: Vec<Bytes> = Vec::new();
    let mut proof_flags: Vec<bool> = Vec::new();

    while !stack.is_empty() && stack[0] > 0 {
        let j = stack.remove(0); // take from the beginning
        let s = sibling_index(j);
        let p = parent_index(j);

        if !stack.is_empty() && s == stack[0] {
            proof_flags.push(true);
            stack.remove(0); // consume from the stack
        } else {
            proof_flags.push(false);
            proof.push(tree[s].clone());
        }
        stack.push(p);
    }

    if indices.is_empty() {
        proof.push(tree[0].clone());
    }

    let leaves: Vec<Bytes> = indices.iter().map(|&i| tree[i].clone()).collect();

    MultiProof::new(leaves, proof, proof_flags)
}

use std::collections::VecDeque;

/// Reconstruct the Merkle root from a multi-proof. Panics with an "Invariant error" message
/// if the provided proof is malformed.
pub fn process_multi_proof<F>(mp: &MultiProof, node_hash: F) -> Bytes
where
    F: Fn(&[u8], &[u8]) -> Bytes,
{
    // Validate basic compatibility similar to the TypeScript implementation
    let required_proofs = mp.proof_flags.iter().filter(|&&b| !b).count();
    if mp.proof.len() < required_proofs
        || (mp.leaves.len() + mp.proof.len()) != (mp.proof_flags.len() + 1)
    {
        panic!("Invariant error");
    }

    let mut stack: VecDeque<Bytes> = VecDeque::from(mp.leaves.clone());
    let mut proof: VecDeque<Bytes> = VecDeque::from(mp.proof.clone());

    for &flag in mp.proof_flags.iter() {
        let a = stack
            .pop_front()
            .unwrap_or_else(|| panic!("Invariant error"));
        let b = if flag {
            stack
                .pop_front()
                .unwrap_or_else(|| panic!("Invariant error"))
        } else {
            proof
                .pop_front()
                .unwrap_or_else(|| panic!("Invariant error"))
        };

        stack.push_back(node_hash(&a, &b));
    }

    if stack.len() + proof.len() != 1 {
        panic!("Invariant error");
    }

    if !stack.is_empty() {
        stack.pop_front().unwrap()
    } else {
        proof.pop_front().unwrap()
    }
}

/// Convenience helper for byte-oriented trees: validates leaf size and delegates to generic constructor.
pub fn make_merkle_tree_bytes<F>(leaves: Vec<Bytes>, node_hash: F) -> Vec<Bytes>
where
    F: Fn(&[u8], &[u8]) -> Bytes,
{
    assert!(!leaves.is_empty(), "Expected non-zero number of leaves");
    for l in leaves.iter() {
        assert_merkle_node(l);
    }

    make_merkle_tree(leaves, |a, b| node_hash(&a, &b))
}

pub fn is_valid_merkle_tree<F>(tree: &Vec<Bytes>, node_hash: F) -> bool
where
    F: Fn(&[u8], &[u8]) -> Bytes,
{
    for (i, node) in tree.iter().enumerate() {
        if !is_valid_merkle_node(node) {
            return false;
        }

        let l = left_child_index(i);
        let r = right_child_index(i);

        if r >= tree.len() {
            if l < tree.len() {
                return false;
            }
        } else {
            let expected_node = node_hash(&tree[l], &tree[r]);
            if *node != expected_node {
                return false;
            }
        }
    }

    tree.len() > 0
}

pub fn render_merkle_tree(tree: &Vec<Bytes>) -> String {
    assert!(
        !tree.is_empty(),
        "Expected non-zero number of nodes in merkle tree"
    );

    let mut stack: Vec<(usize, Vec<usize>)> = vec![(0, vec![])];

    let mut lines: Vec<String> = Vec::new();

    while let Some((i, path)) = stack.pop() {
        let mut line = String::new();

        for p in path.iter().take(path.len().saturating_sub(1)) {
            line.push_str(if *p == 0 { "   " } else { "│  " });
        }

        if let Some(last) = path.last() {
            line.push_str(if *last == 0 { "└─ " } else { "├─ " });
        }

        line.push_str(&format!("{}) {:?}", i, tree[i]));
        lines.push(line);

        if right_child_index(i) < tree.len() {
            stack.push((right_child_index(i), {
                let mut new_path = path.clone();
                new_path.push(0);
                new_path
            }));
            stack.push((left_child_index(i), {
                let mut new_path = path.clone();
                new_path.push(1);
                new_path
            }));
        }
    }

    lines.join("\n")
}
