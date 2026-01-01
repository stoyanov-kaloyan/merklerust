use napi_derive::napi;
use sha2::{Digest, Sha256};

fn default_node_hash(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

fn catch_unwind_result<T, F>(f: F) -> napi::Result<T>
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "panic in Rust code".to_string()
            };
            Err(napi::Error::from_reason(msg))
        }
    }
}

#[napi(object)]
pub struct JsMultiProof {
    pub leaves: Vec<Vec<u8>>,
    pub proof: Vec<Vec<u8>>,
    pub proof_flags: Vec<bool>,
}

#[napi]
pub fn hello() -> String {
    "hello from napi".to_string()
}

#[napi]
pub fn make_merkle_tree(leaves: Vec<Vec<u8>>) -> napi::Result<Vec<Vec<u8>>> {
    catch_unwind_result(|| {
        merklerust_core::merkle::make_merkle_tree_bytes(leaves, |a, b| default_node_hash(a, b))
    })
}

#[napi]
pub fn get_proof(tree: Vec<Vec<u8>>, leaf_index: u32) -> napi::Result<Vec<Vec<u8>>> {
    catch_unwind_result(|| {
        let idx = leaf_index as usize;
        merklerust_core::merkle::get_proof(&tree, idx)
    })
}

#[napi]
pub fn process_proof(leaf: Vec<u8>, proof: Vec<Vec<u8>>) -> napi::Result<Vec<u8>> {
    catch_unwind_result(|| {
        merklerust_core::merkle::process_proof(leaf.as_slice(), &proof, |a, b| {
            default_node_hash(a, b)
        })
    })
}

#[napi]
pub fn get_multi_proof(tree: Vec<Vec<u8>>, indices: Vec<u32>) -> napi::Result<JsMultiProof> {
    catch_unwind_result(|| {
        let idxs: Vec<usize> = indices.into_iter().map(|i| i as usize).collect();
        let mp = merklerust_core::merkle::get_multi_proof(&tree, idxs);
        JsMultiProof {
            leaves: mp.leaves,
            proof: mp.proof,
            proof_flags: mp.proof_flags,
        }
    })
}

#[napi]
pub fn process_multi_proof(mp: JsMultiProof) -> napi::Result<Vec<u8>> {
    catch_unwind_result(|| {
        let core_mp = merklerust_core::merkle::MultiProof::new(mp.leaves, mp.proof, mp.proof_flags);
        merklerust_core::merkle::process_multi_proof(&core_mp, |a, b| default_node_hash(a, b))
    })
}

#[napi]
pub fn is_valid_merkle_tree(tree: Vec<Vec<u8>>) -> bool {
    merklerust_core::merkle::is_valid_merkle_tree(&tree, |a, b| default_node_hash(a, b))
}

#[napi]
pub fn render_merkle_tree(tree: Vec<Vec<u8>>) -> napi::Result<String> {
    catch_unwind_result(|| merklerust_core::merkle::render_merkle_tree(&tree))
}
