# Diffie-Hellman-Key-Exchange
Diffie-Hellman Key Exchange Algorithm Implemented in C with OpenSSL

[Diffie Hellman Key Exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) is a method of securely exchanging keys over a public channel and was one of the
first public-key protocols. It allows people with no prior knowledge of each other to establish a shared secret key over an insecure channel.
It should be noted that no one ever uses this algorithm because of how easy it is to brute force with technology today, and with the fact that 
large amounts of data/work has to be done by both parties.

My code is commented well to help anyone who is having trouble understanding this algorithm. So go ahead and take a look.

![](https://github.com/TroyFernandes/Diffie-Hellman-Key-Exchange/blob/master/Demo/demo.gif)

# Merkle's Puzzle

Merkle's Puzzle is a concept used in this algorithm. It works as follows ...

Pi ∈{0,1}<sup>2</sup>

Xi, Ki ∈{0,1}<sup>128</sup>

Puzzle = E( 0<sup>14</sup> || Pi , "Puzzle Xi || Ki" )

1) Alice sends 2<sup>16</sup> puzzles to Bob
2) Bob chooses one random puzzle and tries all possible keys knowing
   that the first 14 bytes are zero
3) If Bob sees the word "Puzzle" in the message after decrypting with the given key, he knows that he successfully solved
   one of the puzzles.
4) In the decrypted message, Bob sees the Xi and Ki value embedded, therefore he sends back to Alice Xi
5) Alice then uses the Xi value to look up in her table the matching Ki value.
6) Ki becomes the shared secret key between Bob and Alice

[This](https://www.youtube.com/watch?v=wRBkzEX-4Qo) video was used as reference and does a good job explaining the puzzle.

# Program Rundown

The program starts by generating 2<sup>16</sup> different puzzles. It generates a secret key where the first 14 bytes are zero, and the last two are random hex values. It also generates an Xi and Ki value. It then gets saved in a struct which only Alice has. (You can change the MAX_KEYS definition to reduce this number if you like)

Puzzle generation will depend on your computer. On mine, which is an i5-4690k @4.4GHz and 16Gb of RAM it takes around 2m30s to generate 65536 puzzles.

Alice has a struct which has an Index, the puzzle, Xi, and Ki. (ONLY Alice has this).
Bob has a struct with all the encrypted puzzles.

Next, Bob tries to solve any one random puzzle by trying all possible keys. eg. 0000000000000000 to 00000000000000FF and using that key to decrypt the encrypted message. If the decryption returns a message which contains "Puzzle", he knows that he has found the right key. With the decrypted message containing both the Xi and Ki value, he sends Alice the Xi value.

Next, Alice takes the Xi value from Bob and looks up in her table the corresponding Ki value.

Now Alice and Bob have a shared Secret Key.

# Complexity Analysis (Computational Cost)

Bob will see the encrypted messages and choose a random one. He then will spend O(n) to solve
the puzzle.
Bob will send Xi back to Alice.

Eve however dosent know which Xi value corresponds to the proper Ki value nor which puzzle Bob has solved.

Therefore, Eve will have to solve all the puzzles to find which value Xi was being sent back to Alice.

In conclusion, if Bob needed to spend O(n) to solve one puzzle, and Eve has to do it for each puzzle (n) ... it will take her O(n)*(n)
= O(n)<sup>2</sup> time.




