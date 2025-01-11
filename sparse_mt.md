Reasons why SMT data_structure would work:

1) Each key in the tree is unique:
Given the same input K, the output digest H(K) is always the same. For a 256-bit hash function, the probability of two distinct keys producing the same has is negligible. Also the output of the hash function appears uniformly distributed across its range, with little chance for collisions.

2)Which hash function assumption does representing the empty subtree
  by the all-`0` digest rely upon? 
  It relies on the pre image resistance property of the hash function. Preimage resistance ensures that the attacker cannot find an input theat hashes to all-0 digest. This ensures that empty subtree representation cannot be forged or confused with a valid (K, V) pair or brnch code.

3) Collision resistance: If there are two SMTs that differ exactly by one key, but produce that same root digest, then it would break the collision-resistance property of the hash function.

 This is because if they differ in just one key then there must be atleast one hash in the path determined by that key that differs between both keys. Then this would imply that the hash function produced two different output for the same input.(Collision resistance assumption is violated here).