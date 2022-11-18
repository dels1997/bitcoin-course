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
## HW2 hw2.py script output:

Uncompressed SEC format:  04852e3a8f4e64ee65624872095c466dccd460dcc85d4bab56ec2625b920677014d4895949efe57596ee4ed9bad45fb24b2a9df7686bb700e672f62a56860c1380
Compressed sec format:  02852e3a8f4e64ee65624872095c466dccd460dcc85d4bab56ec2625b920677014
Raw signature:  Signature(1b8702e527b5410464649721cffdead50944c251fb09727f55e2c54e1e56def,2a44f56715d0d9d4fa086539d261219f415fb474a2b74136c43ca462a862eda9)
DER signature:  3044022001b8702e527b5410464649721cffdead50944c251fb09727f55e2c54e1e56def02202a44f56715d0d9d4fa086539d261219f415fb474a2b74136c43ca462a862eda9
Testnet address:  mnWaVwJYCFKK3nCriPFfHD9wLKhz9RVbcy
Mainnet address:  17zdCtDZPDt4GfjEzpHHTHwcUL7HBW6k2a

(material used for solution: https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/ch04.html)
----------------------------------------------------------------------------------------------------------------------------
