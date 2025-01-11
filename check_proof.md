Reasons why check_proof should be:

1) complete: Here we mean that if the 'get' function is able to return a true result, then the system can always create a proof that check_proof will accept. This works. The justification is provided in the following two cases;

If the key exists:
'get" provides an actual path to the key and its values. The path includes all the hashes needed to reconstruct the root and this proves that the key is in the right position by showing it's neighbors.

If the key doesn't exist:
'get' function shows the gap where the key would've existed and it proves the existense of the gap using the surrounding entries.


2) sound: Here we want to justify that no one would be able to create a fake proof. To achive this, firstly one needs to create a proof showing that a key exists where it doesn't. Secondly, reconstruct all the hashes leading upto the root through the path.

The above two tasks are not possible without breaking sha-256. And as mentioned in the literature provided the forger would need to find different data that produces the same hash, where sha-256 makes this impossible. Also the different data would need to maintain the sorting property.