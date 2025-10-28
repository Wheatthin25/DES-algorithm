# slides start on 49
# EBC on 60
# CBC on 61

# used this as reference for DES https://www.geeksforgeeks.org/computer-networks/data-encryption-standard-des-set-1/
import os
from bitarray import bitarray

def blockify(input_txt):
    blocks = []

    for index in range(0, len(input_txt), 8):
        if (len(input_txt) - index) < 7:
            text = bitarray((input_txt[index:] + '\0' * (8 - len(input_txt[index:]))).encode('utf-8'))
            blocks.append(text)
        else:
            text = bitarray(input_txt[index: index + 8].encode('utf-8'))
            blocks.append(text)
    return blocks

def initial_perm(block, iv):
    # using fixed permutation table
    block2 = block.copy() ^ iv
    block2[0] = block[57]
    block2[1] = block[49]
    block2[2] = block[41]
    block2[3] = block[33]
    block2[4] = block[25]
    block2[5] = block[17]
    block2[6] = block[9]
    block2[7] = block[1]

    block2[8] = block[59]
    block2[9] = block[51]
    block2[10] = block[43]
    block2[11] = block[35]
    block2[12] = block[27]
    block2[13] = block[19]
    block2[14] = block[11]
    block2[15] = block[3]

    block2[16] = block[61]
    block2[17] = block[53]
    block2[18] = block[45]
    block2[19] = block[37]
    block2[20] = block[29]
    block2[21] = block[21]
    block2[22] = block[13]
    block2[23] = block[5]

    block2[24] = block[63]
    block2[25] = block[55]
    block2[26] = block[47]
    block2[27] = block[39]
    block2[28] = block[31]
    block2[29] = block[23]
    block2[30] = block[15]
    block2[31] = block[7]

    block2[32] = block[56]
    block2[33] = block[48]
    block2[34] = block[40]
    block2[35] = block[32]
    block2[36] = block[24]
    block2[37] = block[16]
    block2[38] = block[8]
    block2[39] = block[0]

    block2[40] = block[58]
    block2[41] = block[50]
    block2[42] = block[42]
    block2[43] = block[34]
    block2[44] = block[26]
    block2[45] = block[18]
    block2[46] = block[10]
    block2[47] = block[2]

    block2[48] = block[60]
    block2[49] = block[52]
    block2[50] = block[44]
    block2[51] = block[36]
    block2[52] = block[28]
    block2[53] = block[20]
    block2[54] = block[12]
    block2[55] = block[4]

    block2[56] = block[62]
    block2[57] = block[54]
    block2[58] = block[46]
    block2[59] = block[38]
    block2[60] = block[30]
    block2[61] = block[22]
    block2[62] = block[14]
    block2[63] = block[6]

    return block2

def key_left_shift(shift, key):
    shifted_key = key << shift
    j = -1
    for i in range(shift - 1, -1, -1):
        shifted_key[j] = key[i]
        j -= 1

    return shifted_key



def generate_round_keys(inital_key):
    round_keys = []
    # convert to 56 bit key
    for i in range(0, len(inital_key), 8):
        inital_key.pop(i)

    # split into right hand side and left side
    lhs = inital_key[:28].copy()
    rhs = inital_key[28:].copy()

    # round 1 gets shifted left once
    lhs = key_left_shift(1, lhs)
    rhs = key_left_shift(1, rhs)

    # recombining halves + saving left hand side for next round
    next_lhs = lhs.copy()
    lhs.extend(rhs)

    # permutation 2
    permutation_key = lhs.copy()
    permutation_key[0] = lhs[13]
    permutation_key[1] = lhs[16]
    permutation_key[2] = lhs[10]
    permutation_key[3] = lhs[23]
    permutation_key[4] = lhs[0]
    permutation_key[5] = lhs[4]
    permutation_key[6] = lhs[2]
    permutation_key[7] = lhs[27]

    permutation_key[8] = lhs[14]
    permutation_key[9] = lhs[5]
    permutation_key[10] = lhs[20]
    permutation_key[11] = lhs[9]
    permutation_key[12] = lhs[22]
    permutation_key[13] = lhs[18]
    permutation_key[14] = lhs[11]
    permutation_key[15] = lhs[3]

    permutation_key[16] = lhs[25]
    permutation_key[17] = lhs[7]
    permutation_key[18] = lhs[15]
    permutation_key[19] = lhs[6]
    permutation_key[20] = lhs[26]
    permutation_key[21] = lhs[19]
    permutation_key[22] = lhs[12]
    permutation_key[23] = lhs[1]

    permutation_key[24] = lhs[40]
    permutation_key[25] = lhs[51]
    permutation_key[26] = lhs[30]
    permutation_key[27] = lhs[36]
    permutation_key[28] = lhs[46]
    permutation_key[29] = lhs[54]
    permutation_key[30] = lhs[29]
    permutation_key[31] = lhs[39]

    permutation_key[32] = lhs[50]
    permutation_key[33] = lhs[44]
    permutation_key[34] = lhs[32]
    permutation_key[35] = lhs[47]
    permutation_key[36] = lhs[43]
    permutation_key[37] = lhs[48]
    permutation_key[38] = lhs[38]
    permutation_key[39] = lhs[55]

    permutation_key[40] = lhs[33]
    permutation_key[41] = lhs[52]
    permutation_key[42] = lhs[45]
    permutation_key[43] = lhs[41]
    permutation_key[44] = lhs[49]
    permutation_key[45] = lhs[35]
    permutation_key[46] = lhs[28]
    permutation_key[47] = lhs[31]

    round_keys.append(permutation_key)








def encryption():
    pass


def decryption():
    pass
def main():
    # read file
    ifile = open("input.txt", "r")
    input = ifile.read()
    # turn everything into 64 bit blocks
    blocks = blockify(input)

    # create initilization vector 64 bit
    iv = bitarray(os.urandom(8))

    # do init perm for all blocks
    for i in range(len(blocks)):
        blocks[i] = initial_perm(blocks[i], iv)

    # randomly generate key
    init_key = bitarray(os.urandom(8))

    round_keys = []
    generate_round_keys(init_key)

    # print(blocks)

main()