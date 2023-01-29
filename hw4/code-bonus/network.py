import socket
import time

from io import BytesIO
from random import randint

from block import Block, GENESIS_BLOCK
from helper import (
    hash256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)

from block import *

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4
ADDRESS_DATA_TYPE = 5

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'


class NetworkEnvelope:

    def __init__(self, command, payload, testnet=False):
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self):
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )

    @classmethod
    def parse(cls, s, testnet=False):
        '''Takes a stream and creates a NetworkEnvelope'''
        # check the network magic
        magic = s.read(4)
        if magic == b'':
            raise RuntimeError('Connection reset!')
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if magic != expected_magic:
            raise RuntimeError('magic is not right {} vs {}'.format(magic.hex(), expected_magic.hex()))
        # command 12 bytes
        command = s.read(12)
        # strip the trailing 0's
        command = command.strip(b'\x00')
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(s.read(4))
        # checksum 4 bytes, first four of hash256 of payload
        checksum = s.read(4)
        # payload is of length payload_length
        payload = s.read(payload_length)
        # verify checksum
        calculated_checksum = hash256(payload)[:4]
        if calculated_checksum != checksum:
            raise RuntimeError('checksum does not match')
        # return an instance of the class
        return cls(command, payload, testnet=testnet)

    def serialize(self):
        '''Returns the byte serialization of the entire network message'''
        # add the network magic
        result = self.magic
        # command 12 bytes
        # fill with 0's
        result += self.command + b'\x00' * (12 - len(self.command))
        # payload length 4 bytes, little endian
        result += int_to_little_endian(len(self.payload), 4)
        # checksum 4 bytes, first four of hash256 of payload
        result += hash256(self.payload)[:4]
        # payload
        result += self.payload
        return result

    def stream(self):
        '''Returns a stream for parsing the payload'''
        return BytesIO(self.payload)



class VersionMessage:
    command = b'version'

    def __init__(self, version=70015, services=0, timestamp=None,
                 receiver_services=0,
                 receiver_ip=b'\x00\x00\x00\x00', receiver_port=8333,
                 sender_services=0,
                 sender_ip=b'\x00\x00\x00\x00', sender_port=8333,
                 nonce=None, user_agent=b'/programmingbitcoin:0.1/',
                 latest_block=0, relay=False):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2**64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self):
        '''Serialize this message to send over the network'''
        # version is 4 bytes little endian
        result = int_to_little_endian(self.version, 4)
        # services is 8 bytes little endian
        result += int_to_little_endian(self.services, 8)
        # timestamp is 8 bytes little endian
        result += int_to_little_endian(self.timestamp, 8)
        # receiver services is 8 bytes little endian
        result += int_to_little_endian(self.receiver_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        result += b'\x00' * 10 + b'\xff\xff' + self.receiver_ip
        # receiver port is 2 bytes, big endian
        result += self.receiver_port.to_bytes(2, 'big')
        # sender services is 8 bytes little endian
        result += int_to_little_endian(self.sender_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        result += b'\x00' * 10 + b'\xff\xff' + self.sender_ip
        # sender port is 2 bytes, big endian
        result += self.sender_port.to_bytes(2, 'big')
        # nonce should be 8 bytes
        result += self.nonce
        # useragent is a variable string, so varint first
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        # latest block is 4 bytes little endian
        result += int_to_little_endian(self.latest_block, 4)
        # relay is 00 if false, 01 if true
        if self.relay:
            result += b'\x01'
        else:
            result += b'\x00'
        return result



class VerAckMessage:
    command = b'verack'

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b''


class PingMessage:
    command = b'ping'

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PongMessage:
    command = b'pong'

    def __init__(self, nonce):
        self.nonce = nonce

    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class GetHeadersMessage:
    command = b'getheaders'

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError('a start block is required')
        self.start_block = start_block
        if end_block is None:
            self.end_block = b'\x00' * 32
        else:
            self.end_block = end_block

    def serialize(self):
        '''Serialize this message to send over the network'''
        # protocol version is 4 bytes little-endian
        result = int_to_little_endian(self.version, 4)
        # number of hashes is a varint
        result += encode_varint(self.num_hashes)
        # start block is in little-endian
        result += self.start_block[::-1]
        # end block is also in little-endian
        result += self.end_block[::-1]
        return result


class HeadersMessage:
    command = b'headers'

    def __init__(self, blocks):
        self.blocks = blocks

    @classmethod
    def parse(cls, stream):
        # number of headers is in a varint
        num_headers = read_varint(stream)
        # initialize the blocks array
        blocks = []
        # loop through number of headers times
        for _ in range(num_headers):
            # add a block to the blocks array by parsing the stream
            blocks.append(Block.parse(stream))
            # read the next varint (num_txs)
            num_txs = read_varint(stream)
            # num_txs should be 0 or raise a RuntimeError
            if num_txs != 0:
                raise RuntimeError('number of txs not 0')
        # return a class instance
        return cls(blocks)


class GetAddrMessage:
    command = b'getaddr'

    def __init__(self, time, services, ipv64, port):
        self.time = time
        self.services = services
        self.ipv64 = ipv64
        self.port = port
        # if start_block is None:
        #     raise RuntimeError('a start block is required')
        # self.start_block = start_block
        # if end_block is None:
        #     self.end_block = b'\x00' * 32
        # else:
        #     self.end_block = end_block

    def serialize(self):
        '''Serialize this message to send over the network'''
        result = int_to_little_endian(self.time, 4)
        result += int_to_little_endian(self.services, 8)
        result += self.ipv64[::-1]
        result += int_to_little_endian(self.port, 2)
        return result


class AddrMessage:
    command = b'addr'

    def __init__(self, addresses):
        self.addresses = addresses

    @classmethod
    def parse(cls, stream):
        num_addrs = read_varint(stream)
        addresses = []
        for _ in range(num_addrs):
            addresses.append(Block.parse(stream))
            num_txs = read_varint(stream)
            if num_addrs != 0:
                raise RuntimeError('number of addrs not 0')
        # return a class instance
        return cls(addresses)


###############################
###IMPLEMENT IN THE HOMEWORK###
###############################
class BlockMessage:
    command = b'block'

    def __init__(self, block):
        self.block = block

    # This just keeps a single full block which we parse
    @classmethod
    def parse(cls, stream):
        # version is 4 bytes little endian
        version = little_endian_to_int(stream.read(4))
        # prev_block is 32 bytes little endian
        prev_block = stream.read(32)[::-1]
        # merkle_root is 32 bytes little endian
        merkle_root = stream.read(32)[::-1]
        # timestamp is 8 bytes little endian
        timestamp = little_endian_to_int(stream.read(4))
        # bits is 4 bytes
        bits = stream.read(4)
        # nonce is 4 bytes
        nonce = stream.read(4)
        # number of headers is in a varint
        txn_count = read_varint(stream)
        # initialize the transactions array
        txns = []
        # loop through number of headers times
        for _ in range(txn_count):
            # add a txns to the transactions array by parsing the stream
            txns.append(Tx.parse(stream))
            # read the next varint (num_txs)
            # num_txs = read_varint(stream)
            # # num_txs should be 0 or raise a RuntimeError
            # if num_txs != 0:
            #     raise RuntimeError('number of txs not 0')
        block = FullBlock(version, prev_block, merkle_root, timestamp, bits, nonce, txn_count, txns)
        # return a class instance
        return cls(block)



###############################
###IMPLEMENT IN THE HOMEWORK###
###############################
class GetDataMessage:
    command = b'getdata'

    def __init__(self):
        self.data = []  # <1>

    def add_data(self, data_type, identifier):
        self.data.append((data_type, identifier))  # <2>
    # end::source1[]
    def serialize(self):
        result = encode_varint(len(self.data))
        for data_type, identifier in self.data:
            result += int_to_little_endian(data_type, 4)
            result += identifier[::-1]
        return result

# ###############################
# ###IMPLEMENT IN THE HOMEWORK###
# ###############################



class GenericMessage:
    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    def serialize(self):
        return self.payload


class SimpleNode:

    def __init__(self, host, port=None, testnet=False, logging=False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.testnet = testnet
        self.logging = logging
        # connect to socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        # create a stream that we can use with the rest of the library
        self.stream = self.socket.makefile('rb', None)

    def handshake(self):
        '''Do a handshake with the other node.
        Handshake is sending a version message and getting a verack back.'''
        # create a version message
        version = VersionMessage()
        # send the command
        self.send(version)
        # wait for a verack message
        self.wait_for(VerAckMessage)

    def send(self, message):
        '''Send a message to the connected node'''
        # create a network envelope
        envelope = NetworkEnvelope(
            message.command, message.serialize(), testnet=self.testnet)
        if self.logging:
            print('sending: {}'.format(envelope))
        # send the serialized envelope over the socket using sendall
        self.socket.sendall(envelope.serialize())

    def read(self):
        '''Read a message from the socket'''
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)
        if self.logging:
            print('receiving: {}'.format(envelope))
        return envelope

    def wait_for(self, *message_classes):
        '''Wait for one of the messages in the list'''
        # initialize the command we have, which should be None
        command = None
        command_to_class = {m.command: m for m in message_classes}
        # loop until the command is in the commands we want
        while command not in command_to_class.keys():
            # get the next network message
            envelope = self.read()
            # set the command to be evaluated
            command = envelope.command
            # we know how to respond to version and ping, handle that here
            if command == VersionMessage.command:
                # send verack
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                # send pong
                self.send(PongMessage(envelope.payload))
        # return the envelope parsed as a member of the right message class
        return command_to_class[command].parse(envelope.stream())




first_20_blocks_mainnet = [
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    '00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048',
    '000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd',
    '0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449',
    '000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485',
    '000000009b7262315dbf071787ad3656097b892abffd1f95a1a022f896f533fc',
    '000000003031a0e73735690c5a1ff2a4be82553b2a12b776fbd3a215dc8f778d',
    '0000000071966c2b1d065fd446b1e485b2c9d9594acd2007ccbd5441cfc89444',
    '00000000408c48f847aa786c2268fc3e6ec2af68e8468a34a28c61b7f1de0dc6',
    '000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805',
    '000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9',
    '0000000097be56d606cdd9c54b04d4747e957d3608abe69198c661f2add73073',
    '0000000027c2488e2510d1acf4369787784fa20ee084c258b58d9fbd43802b5e',
    '000000005c51de2031a895adc145ee2242e919a01c6d61fb222a54a54b4d3089',
    '0000000080f17a0c5a67f663a9bc9969eb37e81666d9321125f0e293656f8a37',
    '00000000b3322c8c3ef7d2cf6da009a776e6a99ee65ec5a32f3f345712238473',
    '00000000174a25bb399b009cc8deff1c4b3ea84df7e93affaaf60dc3416cc4f5',
    '000000003ff1d0d70147acfbef5d6a87460ff5bcfce807c2d5b6f0a66bfdf809',
    '000000008693e98cf893e4c85a446b410bb4dfa129bd1be582c09ed3f0261116',
    '00000000841cb802ca97cf20fb9470480cae9e5daa5d06b4a18ae2d5dd7f186f'
]


# Establish a connection to a mainnet node
# node = SimpleNode('mainnet.programmingbitcoin.com', testnet=False)
# node.handshake()

# genesis = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'

# getheaders = GetHeadersMessage(start_block = bytes.fromhex(genesis))
# node.send(getheaders)
# headers = node.wait_for(HeadersMessage)

# for x in headers.blocks:
#     print(x.hash().hex(),x.prev_block.hex())


from contextlib import redirect_stdout

def write_data(node_number):
    path = r"C:\Users\dels\Desktop\Računarstvo i matematika\2. godina\pcp\hw4\code-bonus\out"
    path += str(node_number)
    path += ".txt"

    node = SimpleNode('mainnet.programmingbitcoin.com', testnet=False)
    node.handshake()
    with open(path, 'w') as f:
        with redirect_stdout(f):
            for block in first_20_blocks_mainnet:
                getBlock = GetDataMessage()
                getBlock.add_data(BLOCK_DATA_TYPE,bytes.fromhex(block))

                node.send(getBlock)
                received = node.wait_for(BlockMessage)

                block = received.block

                print(block.hash().hex())

                for tx in block.txs:
                    # We don't know how to verify coinbase transactions!!!!!!!!!!
                    # print(tx.verify())
                    print(tx)
                
                print()
                print()
                print('-' * 100)
                print()
                print()

write_data(1)
write_data(2)
write_data(3)

'''
# Establish a connection to a testnet node
node = SimpleNode("testnet.programmingbitcoin.com", testnet=True)
node.handshake()
'''

'''
# Get the first 2000 blocks of Bitcoin:
previous = Block.parse(BytesIO(GENESIS_BLOCK))
getheaders = GetHeadersMessage(start_block = previous.hash())
node.send(getheaders)
headers = node.wait_for(HeadersMessage)

for x in headers.blocks:
    print(x.hash().hex(),x.prev_block.hex())
'''


# # First 15 blocks:
# previous = Block.parse(BytesIO(GENESIS_BLOCK))
# block15 = '000000009425e151b8bab13f801282ef0f3dcefc55ec4b2e0355e513db4cd328'
# getheaders = GetHeadersMessage(start_block = previous.hash(), end_block=bytes.fromhex(block15))

# node.send(getheaders)
# headers = node.wait_for(HeadersMessage)

# from contextlib import redirect_stdout

# with open(r"C:\Users\dels\Desktop\Računarstvo i matematika\2. godina\pcp\hw4\code\out3.txt", 'w') as f:
#     with redirect_stdout(f):
#         for x in headers.blocks:
#             print(x.hash().hex(),x.prev_block.hex())




'''
getBlock = GetDataMessage()
getBlock.add_data(BLOCK_DATA_TYPE,bytes.fromhex('000000009425e151b8bab13f801282ef0f3dcefc55ec4b2e0355e513db4cd328'))

node.send(getBlock)
received = node.wait_for(BlockMessage)

block = received.block

print(block.hash().hex())

print(block)

for tx in block.txs:
    # We don't know how to verify coinbase transactions!!!!!!!!!!
    #print(tx.verify())
    print(tx)
'''

# Added Code

# First 20 full blocks:
# previous = Block.parse(BytesIO(GENESIS_BLOCK))
# block15 = '000000009425e151b8bab13f801282ef0f3dcefc55ec4b2e0355e513db4cd328'
# getheaders = GetHeadersMessage(start_block = previous.hash(), end_block=bytes.fromhex(block15))

# node.send(getheaders)
# headers = node.wait_for(HeadersMessage)

# for x in headers.blocks:
#     print(x.hash().hex(),x.prev_block.hex())


# first_20_blocks = [
#     '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943',
#     '00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206',
#     '000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820',
#     '000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10',
#     '000000008b5d0af9ffb1741e38b17b193bd12d7683401cecd2fd94f548b6e5dd',
#     '00000000bc45ac875fbd34f43f7732789b6ec4e8b5974b4406664a75d43b21a1',
#     '000000006633685edce4fa4d8f12d001781c6849837d1632c4e2dd6ff2090a7b',
#     '00000000e29e3aa65f3d12440eac9081844c464aeba7c6e6121dfc8ac0c02ba6',
#     '000000009cbaa1b39a336d3afa300a6d73fab6d81413b2f7965418932a14e2f9',
#     '0000000050ff3053ada24e6ad581fa0295297f20a2747d034997ffc899aa931e',
#     '00000000700e92a916b46b8b91a14d1303d5d91ef0b09eecc3151fb958fd9a2e',
#     '00000000adde5256150e514644c5ec4f81bda990faec90230a2c80a929cae027',
#     '000000004705938332863b772ff732d2d5ac8fe60ee824e37813569bda3a1f00',
#     '0000000092c69507e1628a6a91e4e69ea28fe378a1a6a636b9c3157e84c71b78',
#     '000000006408fcd00d8bb0428b9d2ad872333c317f346f8fee05b538a9913913',
#     '000000009425e151b8bab13f801282ef0f3dcefc55ec4b2e0355e513db4cd328',
#     '00000000c4cbd75af741f3a2b2ff72d9ed4d83a048462c1efe331be31ccf006b',
#     '00000000fe198cce4c8abf9dca0fee1182cb130df966cc428ad2a230df8da743',
#     '000000008d55c3e978639f70af1d2bf1fe6f09cb3143e104405a599215c89a48',
#     '000000009b3bca4909f38313f2746120129cce4a699a1f552390955da470c5a9',
#     ]

# from contextlib import redirect_stdout

# with open(r"C:\Users\dels\Desktop\Računarstvo i matematika\2. godina\pcp\hw4\code-regular\out.txt", 'w') as f:
#     with redirect_stdout(f):
#         for block in first_20_blocks:
#             getBlock = GetDataMessage()
#             getBlock.add_data(BLOCK_DATA_TYPE,bytes.fromhex(block))

#             node.send(getBlock)
#             received = node.wait_for(BlockMessage)

#             block = received.block

#             print(block.hash().hex())

#             print(block)

#             for tx in block.txs:
#                 # We don't know how to verify coinbase transactions!!!!!!!!!!
#                 # print(tx.verify())
#                 print(tx)
#             print()
#             print()
#             print('-' * 100)
#             print()
#             print()
