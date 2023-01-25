# pcp
 Repository containing (at least) homework assignments and the final project for course Programming for Contemporary Processors in academic year 2022/2023.
----------------------------------------------------------------------------------------------------------------------------
## HW1 Bitcoin_Merkle.py script output:

hashes of interest: 
9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab
c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800

number of leaves: 16

flags: [1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0]

hashes:

6382df3f3a0b1323ff73f4da50dc5e318468734d6054111481921d845c020b93
3b67006ccf7fe54b6cb3b2d7b9b03fb0b94185e12d086a42eb2f32d29d535918
9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab
b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638
b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263
c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800
8636b7a3935a68e49dd19fc224a8318f4ee3c14791b3388f47f9dc3dee2247d1

verify_inclusion: True

sorted hashes:

457743861de496c429912558a106b810b0507975a49773228aa788df40730d41
507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308
5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b
7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a
82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05
9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb
9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab
a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330
b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9
b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638
b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263
bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add
c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2
c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800
ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836
f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e

verify_non_inclusion() for all leaves:
False
False
False
False
False
False
False
False
False
False
False
False
False
False
False
False

verify_non_inclusion() for hashes_check:
True
True
False
False
False
False
True

verify_non_inclusion() that should return True:
True

----------------------------------------------------------------------------------------------------------------------------
## HW2 hw2.py script output (with newlines added for readability):

Uncompressed SEC format:  04852e3a8f4e64ee65624872095c466dccd460dcc85d4bab56ec2625b920677014d4895949efe57596ee4ed9bad45fb24b2a9df7686bb700e672f62a56860c1380

Compressed sec format:  02852e3a8f4e64ee65624872095c466dccd460dcc85d4bab56ec2625b920677014

Raw signature:  Signature(1b8702e527b5410464649721cffdead50944c251fb09727f55e2c54e1e56def,2a44f56715d0d9d4fa086539d261219f415fb474a2b74136c43ca462a862eda9)

DER signature:  3044022001b8702e527b5410464649721cffdead50944c251fb09727f55e2c54e1e56def02202a44f56715d0d9d4fa086539d261219f415fb474a2b74136c43ca462a862eda9

Testnet address:  mnWaVwJYCFKK3nCriPFfHD9wLKhz9RVbcy

Mainnet address:  17zdCtDZPDt4GfjEzpHHTHwcUL7HBW6k2a

(material used for solution: https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/ch04.html)

----------------------------------------------------------------------------------------------------------------------------
## HW3:

### Part 1
secret1 = 'Dels1'

address1 = 'n1kJtzTUR3SCXXJaLwuJ17NYYFryqBXhfE'

seret2 = 'Dels2'

address2 = 'mtoadNYwKHRASQQgVtALfDhApXsiqSXYBx'

Tx hash: 'b8e47b6abe7e7ec69a5bda03d4833599d9c04dafb5b61804af1f0cedc9481217'

Tx hash: '87fb227afe62f3846830bbb7e6f14aa5a21342dafe2a255dfefdc7d56b34dc5e'

### Part 2
Tx: '0100000002171248c9ed0c1faf0418b6b5af4dc0d9993583d403da5b9ac67e7ebe6a7be4b8000000006a47304402205af8b1e42f6e434bd88ea5b53a83b9ebe2731ad3a6e0a554cad81e4d642858360220540129871c7cfe734f22f65d856aab8021dee56af0009a27d72459db602ad0cc0121034ac57dc4d3d16fdaef19a7fc4478f61fa030df945d2537a243845e3b7ca32d53ffffffff5edc346bd5c7fdfe5d252afeda4213a2a54af1e6b7bb306884f362fe7a22fb87000000006b483045022100fcefa5b3c9e3c3bc09a45d2af06b686bed245ba893e23881c57b024b4f0e5a380220192cae88e1c7ad3d201863ff3022a9b35d7b69f5547204322e248feeddea05bc0121034ac57dc4d3d16fdaef19a7fc4478f61fa030df945d2537a243845e3b7ca32d53ffffffff01e8030000000000001976a91491be9eb1dd37e02eaf4e5e4bcf68ee9dd14ae21988ac00000000'

Tx hash: 'a00766ec92e998dc3ec6799c8fb1969262ec6446b10acb88af4fcfca5bf6303a'

### Part 3
address3: '2N9KSwqsWgzRHV7gUYkXjjjTn2kaaBSJ4ao'

Tx: '01000000013a30f65bcacf4faf88cb0ab14664ec629296b18f9c79c63edc98e992ec6607a0000000006a47304402205f029d96a10f2bd1dd8c99b16c7e13c9c1edda90649f8136bb6169dab62654a702203390af0a2a54e493045f37538431d59bd9646a16e580054ce7b40ab1501155f1012103596317f02a778ead013895b35de20434cb22eb0f6885a8c887acb80fa25de258ffffffff02c8000000000000001976a91459cada50314c829e19f5a7786f8ee0d4987f429d88acc80000000000000017a914b04e7e3cd9e0b9e33ecf96b9b6aff2e3cc6829158700000000'

Tx hash: '2c3b06cde523bba65d296c27f69142e14a62c934cf791ec99adf79a0e48f67de'

### Part 4
Tx: '0100000001de678fe4a079df9ac91e79cf34c9624ae14291f6276c295da6bb23e5cd063b2c0100000084473044022069a3696e92dd2e865a884553d8a875b8aeb0f5af4c6afdfb667da45752f6ba11022022ba385f624e2572ad3285a585ea797181b5cf7f3f104c496f6ce858854129e80121034ac57dc4d3d16fdaef19a7fc4478f61fa030df945d2537a243845e3b7ca32d531976a914dde91f050aafdaad45c5ef8cdc5c66f2d58d52a888acffffffff0196000000000000001976a91459cada50314c829e19f5a7786f8ee0d4987f429d88ac00000000'

Tx hash: '04d95dbeaaaa425adca123428e0a520978b859646195a5f35c0daddc34c6e484'

----------------------------------------------------------------------------------------------------------------------------
## HW4:

### Regular part

#### Part 1

All the relevant information for first 20 blocks of Bitcoin testnet is in file out.txt.

#### Part 2
Printed error is in file out_error.txt. Explanation: if we add the command print(prev_tx.hex()) in parse method of class TxIn, we see that for all first transactions in block, value of previous transaction hash is all zeros, i.e. not a valid transaction hash and thus the transaction cannot be verified.
