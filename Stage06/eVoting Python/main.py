from ballot_encryption import *
from asymmetricEncryption import *
from blockchain import *

#Generate Admin Keys
keys = generateKey()

#Database Setting
ballot_database = []
ballot_tracker_database = []
block_database = []
current_hash = "Initial Block"

start_to_decrypte = False
end = "N"
print("<<<The election start!!>>>")

#System main part
while end == "N":
    ballot = input("Please input your selection: ")

    #Generate the ballot tracker
    ballot_tracker = ballot_tracker_generation()
    print("Your ballot tracker is :",ballot_tracker.decode())

    #Encoding the ballot
    first_encrypted_ballot = ballot_encoding(ballot,ballot_tracker)

    #Encrypt the ballot
    final_encrypted_ballot = encrypt_message(first_encrypted_ballot.decode(),keys[1])

    #Storing the ballot tracker
    ballot_tracker_database.append(ballot_tracker)

    #Storing the ballot
    len_of_block = len(block_database)
    if len_of_block == 0:
        ballot_database.append(final_encrypted_ballot)
        new_block = Block(current_hash, ballot_database)
        block_database.append((new_block.block_hash,new_block.block_data))
        current_hash = new_block.block_hash
        print("Your ballot has been submitted successfully!")
        end = input("Should the voting be ended? (Y/N)")
        if end == "Y":
            start_to_decrypte = True

    elif len_of_block == 1:
        #Using current database + previous hash--> hash and compare with current hash --> if same --> ballot_database will + new data -->create new block and append to block_database 
        check_block = Block("Initial Block",ballot_database)
        append_new_block(current_hash,check_block.block_hash,ballot_database,final_encrypted_ballot,block_database)
        if len_of_block != len(block_database):
            current_hash = block_database[len_of_block][0]
            print("Your ballot has been submitted successfully!")
            end = input("Should the voting be ended? (Y/N)")
            if end == "Y":
                start_to_decrypte = True
        else:
            end = "Y"
            print("Your ballot has not submitted!")
            print("The election need to pause now!")

    else:
        #hack test 1 - change the database
        if len_of_block==2:
            ballot_database=['A', 'B']
        #hack test 2 - add ballot to the database
        #if len_of_block==2:
        #    ballot_database.append('b')
        check_block = Block(block_database[len_of_block-2][0],ballot_database)
        append_new_block(current_hash,check_block.block_hash,ballot_database,final_encrypted_ballot,block_database)
        if len_of_block != len(block_database):
            current_hash = block_database[len_of_block][0]
            print("Your ballot has been submitted successfully!")
            end = input("Should the voting be ended? (Y/N)")
        else:
            end = "Y"
            print("Your ballot has not submitted!")
            print("The election need to pause now!")


#Decrypted ballot
def decrypted_ballot():
    for x in ballot_database:
        original_message = decrypt_message(x,keys[0])
        for y in ballot_tracker_database:
            try:
                message = ballot_decoding(original_message,y)
            except:
                i=0
        print(message)

if start_to_decrypte == True:
    decrypted_ballot()

