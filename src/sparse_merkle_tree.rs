use crate::common::*;
use crate::kv_trait::AuthenticatedKV;
use sha2::{Sha256, Digest as _}; // importing the Digest trait

// First, let's implement a way to create an empty digest
impl Digest {
    fn zero() -> Self {
        // Create a digest filled with zeros
        Digest(sha2::Sha256::digest(&[0u8; 32]))
    }
}

/*
 *  *******************************************
 *                  TASK 5 (type)
 *  *******************************************
 */

 /*The nodes in our sparse merkle tree can either be empty,
 have a leaf node containing a key value pair or a branch node
 with left and right children.
 */
#[derive(Debug, Clone)]
enum Node {
    Empty, 
    Leaf {
        key: String,
        value: String,
    },
    Branch {
        left: Box<Node>,
        right: Box<Node>,
    },
}

#[derive(Debug, Clone)]
struct SparseMerkleTree {
    root: Node,
}

//The proof consists of sibling hashes along the path from the root to the target node
#[derive(Debug, Clone)]
struct SparseMerkleTreeProof{
    /* Each element here is of the form (bit, sibling_hash)
    the bit value indicates whether we went left or right at 
    each level, depending on 0 or 1 respectively
    sibling_hash is the hash of the sibling node at this level
     */
    path: Vec<(bool, Digest)>,
    //if we find the key, we include it's value
    leaf_value: Option<String>,
}

impl Node {
    //calculating the digest of this node 
    fn digest(&self) -> Digest {
        match self {
            Node::Empty => Digest::zero(), // Empty nodes have all-zero digest
            Node::Leaf { key, value } => {
                // Hash the key-value pair for leaf nodes
                let mut hasher = Sha256::new();
                hasher.update(b"leaf");
                hasher.update(key.as_bytes());
                hasher.update(value.as_bytes());
                hasher.finalize().into()
            }
            Node::Branch { left, right } => {
                // Hash the concatenation of child digests for branch nodes
                let mut hasher = Sha256::new();
                hasher.update(b"branch");
                hasher.update(&left.digest());
                hasher.update(&right.digest());
                hasher.finalize().into()
            }
        }
    }

        // Get key-value pair and generate proof
    fn get(&self, search_key: &str, path: &[bool]) -> (Option<String>, Vec<(bool, Digest)>) {
        match self {
            Node::Empty => (None, vec![]),
            Node::Leaf { key, value } => {
                if key == search_key {
                    (Some(value.clone()), vec![])
                } else {
                    (None, vec![])
                }
            }
            Node::Branch { left, right } => {
                if path.is_empty() {
                // We've run out of path bits but haven't found a leaf
                    (None, vec![])
                } else {
                    let (next_node, sibling, went_right) = if path[0] {
                        (right.as_ref(), left.digest(), true)
                    } else {
                        (left.as_ref(), right.digest(), false)
                    };
                
                    let (value, mut proof) = next_node.get(search_key, &path[1..]);
                    proof.insert(0, (went_right, sibling));
                    (value, proof)
                }
            }
        }
    }
}


impl SparseMerkleTree {
    // Helper to get path bits from key
    fn get_path_bits(key: &str) -> Vec<bool> {
        // Hash the key to get path
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let digest = hasher.finalize();
        
        // Convert each byte to bits
        digest.iter()
            .flat_map(|&byte| {
                (0..8).map(move |i| ((byte >> i) & 1) == 1)
            })
            .collect()
    }
}



impl AuthenticatedKV for SparseMerkleTree {
    type K = String;
    type V = String;
    type LookupProof = SparseMerkleTreeProof;
    type Commitment = Digest;

    /*
     *  *******************************************
     *                  TASK 5 (methods)
     *  *******************************************
     */
    fn new() -> Self {
        // Start with an empty tree
        SparseMerkleTree {
            root: Node::Empty
        }
    }
    fn commit(&self) -> Self::Commitment {
        // The commitment is just the root hash
        self.root.digest()
    }
    fn check_proof(
        key: Self::K,
        res: Option<Self::V>,
        pf: &Self::LookupProof,
        comm: &Self::Commitment,
    ) -> Option<()> {
        // Get path bits for the key
        let path_bits = Self::get_path_bits(&key);
        
        // Start from either a leaf node or empty node
        let mut current_hash = match &res {
            Some(v) => {
                // If we found the key, start from its leaf hash
                let mut hasher = Sha256::new();
                hasher.update(b"leaf");
                hasher.update(key.as_bytes());
                hasher.update(v.as_bytes());
                Digest(hasher.finalize())
            }
            None => Digest::zero() // If not found, start from empty hash
        };
        
        // Walk up the tree using proof
        if pf.path.len() != path_bits.len() {
            return None; // Proof length should match path length
        }
        
        // Verify each level matches the stored path
        for ((proof_bit, sibling_hash), path_bit) in pf.path.iter().zip(path_bits.iter()).rev() {
            if *proof_bit != *path_bit {
                return None; // Path taken doesn't match key's path
            }
            
            // Combine with sibling hash in correct order
            let mut hasher = Sha256::new();
            hasher.update(b"branch");
            if *proof_bit {
                hasher.update(sibling_hash);
                hasher.update(&current_hash);
            } else {
                hasher.update(&current_hash);
                hasher.update(sibling_hash);
            }
            current_hash = Digest(hasher.finalize());
        }
        
        // Check if we arrived at the committed root
        if &current_hash == comm {
            Some(())
        } else {
            None
        }
    }

    fn get(&self, key: Self::K) -> (Option<Self::V>, Self::LookupProof) {
        // Get the path bits from the key
        let path_bits = Self::get_path_bits(&key);
        
        // Get value and proof from root
        let (value, path) = self.root.get(&key, &path_bits);
        
        (value.clone(), SparseMerkleTreeProof {
            path,
            leaf_value: value
        })
    }

    /*
     *  *******************************************
     *                  TASK 6
     *  *******************************************
     */
    fn insert(self, _key: Self::K, _value: Self::V) -> Self {
        todo!()
    }

    /*
     *  *******************************************
     *                  TASK 6
     *  *******************************************
     */
    fn remove(self, _key: Self::K) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
