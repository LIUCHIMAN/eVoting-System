import hashlib

class Block:
    def __init__(self, previous_block_hash, transaction_list):
        self.previous_block_hash = previous_block_hash
        self.transaction_list = transaction_list
        self.block_data = "-".join(str(transaction_list))+"-"+previous_block_hash
        self.block_hash = hashlib.sha256(self.block_data.encode()).hexdigest()

def append_new_block(current_hash,check_hash,ballot_database,ballot,block_database):
    if current_hash == check_hash:
        ballot_database.append(ballot)
        new_block = Block(current_hash, ballot_database)
        block_database.append((new_block.block_hash,new_block.block_data))       
    else:
        print("Alert!!!!! The eVoting System has been hacked!!!!!")

#ballot_database = []
#block_database = []
#current_hash = "Initial Block"
#ballot = "a"

#Check the Block..................
#for x in range(5):
#    len_of_block = len(block_database)
#    print("len_of_block:",len_of_block,"+",ballot_database)
#    if len_of_block == 0:
#        ballot_database.append(ballot)
#        new_block = Block(current_hash, ballot_database)
#        block_database.append((new_block.block_hash,new_block.block_data))
#        current_hash = new_block.block_hash

#    elif len_of_block == 1:
        #Using current database + previous hash--> hash and compare with current hash --> if same --> ballot_database will + new data -->create new block and append to block_database 
#        check_block = Block("Initial Block",ballot_database)
#        append_new_block(current_hash,check_block.block_hash,ballot_database,ballot,block_database)
#        current_hash = block_database[len_of_block][0]

#    else:
        #hack test 1 - change the database
        #if len_of_block==2:
        #    ballot_database=['a', 'b']
        #hack test 2 - add ballot to the database
        #if len_of_block==2:
        #    ballot_database.append('b')
#        check_block = Block(block_database[len_of_block-2][0],ballot_database)
#        append_new_block(current_hash,check_block.block_hash,ballot_database,ballot,block_database)
#        current_hash = block_database[len_of_block][0]

#print("Final Ballot Database:",ballot_database)
#print("Final Block Database:",block_database)



