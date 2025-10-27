import hashlib
import time

class Block:
    def __init__(self, data, prev_hash=''):
        self.data = data
        self.prev_hash = prev_hash
        self.nonce = 0
        self.hash = None

def hash_block(data, prev_hash, nonce):
    text = str(data) + str(prev_hash) + str(nonce)
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def mine_block(block, difficulty):
    prefix = '0' * difficulty
    while True:
        block_hash = hash_block(block.data, block.prev_hash, block.nonce)
        if block_hash.startswith(prefix):
            block.hash = block_hash
            return block
        block.nonce += 1

def add_block(blockchain, data, difficulty):
    prev_hash = blockchain[-1].hash if blockchain else ''
    block = Block(data, prev_hash)
    print(f"Mining a block with data: {data} ...")
    start_time = time.time()
    mined_block = mine_block(block, difficulty)
    end_time = time.time()
    print(f"Block found: {mined_block.hash}")
    print(f"Mining time: {end_time - start_time:.2f} sec\n")
    blockchain.append(mined_block)

if __name__ == "__main__":
    values = [91911, 90954, 95590, 97390, 96578, 97211, 95090]
    difficulty = 5  

    blockchain = []

    print("Creation of Genesis Block...")
    genesis_block = Block("Genesis Block")
    mine_block(genesis_block, difficulty)
    blockchain.append(genesis_block)
    print(f"Genesis Block hash: {genesis_block.hash}\n")

    for value in values:
        add_block(blockchain, value, difficulty)

    print("\n Blockchain:")
    for i, block in enumerate(blockchain):
        print(f"\n=== Block {i} ===")
        print(f"Data: {block.data}")
        print(f"Prev Hash: {block.prev_hash}")
        print(f"Nonce: {block.nonce}")
        print(f"Hash: {block.hash}")
