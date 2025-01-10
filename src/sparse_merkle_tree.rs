use crate::common::*;
use crate::kv_trait::AuthenticatedKV;

/*
 *  *******************************************
 *                  TASK 5 (type)
 *  *******************************************
 */
#[derive(Debug, Clone)]
struct SparseMerkleTree();
#[derive(Debug, Clone)]
struct SparseMerkleTreeProof();

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
        todo!()
    }
    fn commit(&self) -> Self::Commitment {
        todo!()
    }
    fn check_proof(
        _key: Self::K,
        _res: Option<Self::V>,
        _pf: &Self::LookupProof,
        _comm: &Self::Commitment,
    ) -> Option<()> {
        todo!()
    }
    fn get(&self, _key: Self::K) -> (Option<Self::V>, Self::LookupProof) {
        todo!()
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
