# slides start on 49
# EBC on 60
# CBC on 61

# used this as reference for DES https://www.geeksforgeeks.org/computer-networks/data-encryption-standard-des-set-1/
# just used conceptual ideas in beginning half

from bitarray import bitarray
import sys
from long_functions import initial_perm
from long_functions import generate_round_keys
from long_functions import expand_block
from long_functions import lookup_s_table_1
from long_functions import lookup_s_table_2
from long_functions import lookup_s_table_3
from long_functions import lookup_s_table_4
from long_functions import lookup_s_table_5
from long_functions import lookup_s_table_6
from long_functions import lookup_s_table_7
from long_functions import lookup_s_table_8
from long_functions import p_box_perm
from long_functions import final_perm

round_keys = []
def blockify(input_txt, flag):
    if flag:
        blocks = []
        org_blocks = []
        # for encrypting
        for index in range(0, len(input_txt), 8):
            # separates into 8 byte chunks
            if (len(input_txt) - index) < 7:
                text = bitarray((input_txt[index:] + '\0' * (8 - len(input_txt[index:]))).encode('utf-8'))
                blocks.append(text)
                org_blocks.append(text)
            else:
                # if chunk is not quite 8 bytes, then pad to make 8 bytes
                text = bitarray(input_txt[index: index + 8].encode('utf-8'))
                blocks.append(text)
                org_blocks.append(text)
        return blocks, org_blocks
    else:
        cblocks = []
        org_cblocks = []
        # for decrypting - in bytes
        # don't have to check block len because it is padded when encrypting
        for index in range(0, len(input_txt), 8):
            text = bitarray(input_txt[index: index + 8])
            cblocks.append(text)
            org_cblocks.append(text)
        return cblocks, org_cblocks

def generate_keys(inital_key):
    # convert to 56 bit key - removes every 8th bit
    init_key = inital_key[:7] + inital_key[8:15] + inital_key[16:23] + inital_key[24:31]
    init_key += inital_key[32:39] + inital_key[40:47] + inital_key[48:55] + inital_key[56:63]
    rounds = []
    rounds.append(init_key)


    for i in range(16):
        # generate keys with prev rhs and lhs
        next_round_key, round_key = generate_round_keys(rounds[i][:28].copy(), rounds[i][28:].copy(), i + 1)
        # adds round key to round_keys list
        # adds next lhs to rounds
        round_keys.append(round_key)
        rounds.append(next_round_key)

def keyed_substitution(expanded):
    # convert each s box into 4 bits using pre-defined lookup tables
    s_boxes = []
    i = 1
    # divide expanded into 8 6 bit chunks
    for index in range(0, len(expanded), 6):
        text = expanded[index: index + 6]

        y = bitarray(2)
        x = bitarray(4)

        # y is first and last bit of text
        y[0] = text[0]
        y[1] = text[5]

        # x is middle values
        x[:] = text[1:5]

        # send to table
        # each segment gets sent to different table
        if i == 1:
            text = lookup_s_table_1(x, y)
        elif i == 2:
            text = lookup_s_table_2(x, y)
        elif i == 3:
            text = lookup_s_table_3(x, y)
        elif i == 4:
            text = lookup_s_table_4(x, y)
        elif i == 5:
            text = lookup_s_table_5(x, y)
        elif i == 6:
            text = lookup_s_table_6(x, y)
        elif i == 7:
            text = lookup_s_table_7(x, y)
        elif i == 8:
            text = lookup_s_table_8(x, y)

        # gets back value to substitute in binary as a bit array
        s_boxes.append(text)
        i += 1

    # rejoin all the 6-bit segments
    for j in range(1, 8):
        s_boxes[0] += s_boxes[j]

    return s_boxes[0]

def feistel_rounds(block, round, round_keys):
    # splits the block into left plain text and right plain text
    lpt = block[:32].copy()
    rpt = block[32:].copy()

    # first, rpt will go through expansion permutation
    expanded = expand_block(rpt)
    # second, rpt will be xor-ed with round key
    expanded = expanded ^ round_keys[round]
    # third, create s boxes for keyed substitution
    subbed = keyed_substitution(expanded)

    # finally, gets permutated again
    # permutating in place, so no need for re-assignment
    p_box_perm(subbed)

    # next right hand is subbed xor-ed with left hand side
    nrpt = subbed ^ lpt
    # the next left hand is initial right hand side
    # the next right hand side is left side xor-ed with modified right hand side
    return rpt + nrpt

def encryption(input, init_key):
    # turn everything into 64 bit blocks
    blocks, org_blocks = blockify(input, True)

    # do init perm for all blocks and save it
    for i in range(len(blocks)):
        blocks[i] = initial_perm(blocks[i])


    # create round keys
    generate_keys(init_key)

    # for every fiestel round, go through every block
    for i in range(len(blocks)):
        # for every block, go through 16 rounds
        for round in range(0, 16):
            npt = feistel_rounds(blocks[i], round, round_keys)
            # npt is next rounds ciphertext
            # after each round, reassign that block to the next round's ciphertext
            blocks[i] = npt

    # for each block, 32 bit swap - swap sides
    for i in range(len(blocks)):
        # saving left
        temp = blocks[i][:32].copy()
        #assigning left to right
        blocks[i][:32] = blocks[i][32:]
        # assigning right to org left
        blocks[i][32:] = temp[:]

        # final permutation
        blocks[i] = final_perm(blocks[i])

    # after encryption, should return blocks
    return blocks

def decryption(ciphertext):
    # decryption is same as encryption except has reverse key order

    # turn everything into 64 bit blocks
    cblocks, org_cblocks = blockify(ciphertext, False)

    # do init perm for all blocks and save it
    for i in range(len(cblocks)):
        cblocks[i] = initial_perm(cblocks[i])

    # for every fiestel round, go through every block
    for i in range(len(cblocks)):
        for round in range(0, 16):
            npt = feistel_rounds(cblocks[i], round, round_keys[::-1])
            # npt is next rounds ciphertext
            cblocks[i] = npt

    # 32 bit swap - swap sides
    for i in range(len(cblocks)):
        temp = cblocks[i][:32].copy()
        cblocks[i][:32] = cblocks[i][32:]
        cblocks[i][32:] = temp[:]

        # final permutation
        cblocks[i] = final_perm(cblocks[i])

    # after decryption, should return cblocks
    return cblocks


def main():
    # open file
    try:
        ifile_name = sys.argv[1]
    except:
        print("No file input given. Please rerun program like this:")
        print("python3 des.py [input_file.txt]")
        return
    try:
        ifile = open(ifile_name, "r")
    except Exception as err:
        # if input file creates err, just return
        print(f"Error: {err} ")
        print("Exiting program...")
        return

    # if input file name exists, read
    input = ifile.read()

    # turning predefined key into bitarray from hex string
    key = "AABB09182736CCDD"
    key = int(key, 16)
    key = format(key, "64b")
    init_key = bitarray(key)

    # encrypt
    blocks = encryption(input, init_key)

    ofile_name = ifile_name + ".enc"
    # write to output file
    ofile = open(ofile_name, "wb")

    # to write, have to turn them all into strings again
    for block in blocks:
        block = block.tobytes()
        ofile.write(block)
    # close file
    ofile.close()

    # read in encyrpted file
    cfile = open(ofile_name, "rb")
    ciphertext = cfile.read()

    # decrypt the text
    cblocks = decryption(ciphertext)

    output_txt = ""

    # turn output back into one string
    for i in range(len(cblocks)):
        text = cblocks[i].tobytes()
        output_txt += text.decode('utf-8')

    final_name = ofile_name + ".dec"

    # change output to get rid of padding
    output_txt = output_txt.rstrip('\0')

    # write to file
    output_file = open(final_name, "w")
    output_file.write(output_txt)

    # close files
    ifile.close()
    output_file.close()

main()