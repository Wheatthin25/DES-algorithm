# slides start on 49
# EBC on 60
# CBC on 61

# used this as reference for DES https://www.geeksforgeeks.org/computer-networks/data-encryption-standard-des-set-1/
# just used conceptual ideas in beginning half

from bitarray import bitarray
import sys

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

def initial_perm(block):
    # using fixed permutation table
    block2 = block.copy()
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
    # performs a bit shift
    shifted_key = key << shift
    j = -1
    # appends the shifted off bits onto end
    # DES requires circular left shift
    for i in range(shift - 1, -1, -1):
        shifted_key[j] = key[i]
        j -= 1
    return shifted_key

def generate_round_keys(lhs, rhs, i):
    # shift left
    # rounds 1, 2, 9, 16, left shift of 1
    # rounds 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15 left shift of 2
    # recombining halves + saving left hand side for next round

    if i in [1, 2, 9, 16]:
        lhs = key_left_shift(1, lhs)
        rhs = key_left_shift(1, rhs)
    else:
        lhs = key_left_shift(2, lhs)
        rhs = key_left_shift(2, rhs)

    lhs += rhs
    # after shifting
    next_key = lhs.copy()

    # permutation 2 using predefined table
    permutation_key = bitarray(48)
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

    # return the next round's lhs and rhs
    return next_key, permutation_key

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



def expand_block(rpt):
    # using predefined permutation table
    expanded = bitarray(48)

    expanded[0] = rpt[31]
    expanded[1] = rpt[0]
    expanded[2] = rpt[1]
    expanded[3] = rpt[2]
    expanded[4] = rpt[3]
    expanded[5] = rpt[4]

    expanded[6] = rpt[3]
    expanded[7] = rpt[4]
    expanded[8] = rpt[5]
    expanded[9] = rpt[6]
    expanded[10] = rpt[7]
    expanded[11] = rpt[8]

    expanded[12] = rpt[7]
    expanded[13] = rpt[8]
    expanded[14] = rpt[9]
    expanded[15] = rpt[10]
    expanded[16] = rpt[11]
    expanded[17] = rpt[12]

    expanded[18] = rpt[11]
    expanded[19] = rpt[12]
    expanded[20] = rpt[13]
    expanded[21] = rpt[14]
    expanded[22] = rpt[15]
    expanded[23] = rpt[16]

    expanded[24] = rpt[15]
    expanded[25] = rpt[16]
    expanded[26] = rpt[17]
    expanded[27] = rpt[18]
    expanded[28] = rpt[19]
    expanded[29] = rpt[20]

    expanded[30] = rpt[19]
    expanded[31] = rpt[20]
    expanded[32] = rpt[21]
    expanded[33] = rpt[22]
    expanded[34] = rpt[23]
    expanded[35] = rpt[24]

    expanded[36] = rpt[23]
    expanded[37] = rpt[24]
    expanded[38] = rpt[25]
    expanded[39] = rpt[26]
    expanded[40] = rpt[27]
    expanded[41] = rpt[28]

    expanded[42] = rpt[27]
    expanded[43] = rpt[28]
    expanded[44] = rpt[29]
    expanded[45] = rpt[30]
    expanded[46] = rpt[31]
    expanded[47] = rpt[0]

    return expanded

def lookup_s_table_1(x, y):
    # change from bit arrays to tuples, then create the tuple of them together
    bit_x = tuple(map(int, x))
    bit_y = tuple(map(int, y))
    key = (bit_y, bit_x)

    # uses the key to find the value to substitute with
    table = {
        ((0, 0), (0, 0, 0, 0)): 14, ((0, 0), (0, 0, 0, 1)): 4, ((0, 0), (0, 0, 1, 0)): 13, ((0, 0), (0, 0, 1, 1)): 1,
        ((0, 0), (0, 1, 0, 0)): 2, ((0, 0), (0, 1, 0, 1)): 15, ((0, 0), (0, 1, 1, 0)): 11, ((0, 0), (0, 1, 1, 1)): 8,
        ((0, 0), (1, 0, 0, 0)): 3, ((0, 0), (1, 0, 0, 1)): 10, ((0, 0), (1, 0, 1, 0)): 6, ((0, 0), (1, 0, 1, 1)): 12,
        ((0, 0), (1, 1, 0, 0)): 5, ((0, 0), (1, 1, 0, 1)): 9, ((0, 0), (1, 1, 1, 0)): 0, ((0, 0), (1, 1, 1, 1)): 7,

        ((0, 1), (0, 0, 0, 0)): 0, ((0, 1), (0, 0, 0, 1)): 15, ((0, 1), (0, 0, 1, 0)): 7, ((0, 1), (0, 0, 1, 1)): 4,
        ((0, 1), (0, 1, 0, 0)): 14, ((0, 1), (0, 1, 0, 1)): 2, ((0, 1), (0, 1, 1, 0)): 13, ((0, 1), (0, 1, 1, 1)): 1,
        ((0, 1), (1, 0, 0, 0)): 10, ((0, 1), (1, 0, 0, 1)): 6, ((0, 1), (1, 0, 1, 0)): 12, ((0, 1), (1, 0, 1, 1)): 11,
        ((0, 1), (1, 1, 0, 0)): 9, ((0, 1), (1, 1, 0, 1)): 5, ((0, 1), (1, 1, 1, 0)): 3, ((0, 1), (1, 1, 1, 1)): 8,

        ((1, 0), (0, 0, 0, 0)): 4, ((1, 0), (0, 0, 0, 1)): 1, ((1, 0), (0, 0, 1, 0)): 14, ((1, 0), (0, 0, 1, 1)): 8,
        ((1, 0), (0, 1, 0, 0)): 13, ((1, 0), (0, 1, 0, 1)): 6, ((1, 0), (0, 1, 1, 0)): 2, ((1, 0), (0, 1, 1, 1)): 11,
        ((1, 0), (1, 0, 0, 0)): 15, ((1, 0), (1, 0, 0, 1)): 12, ((1, 0), (1, 0, 1, 0)): 9, ((1, 0), (1, 0, 1, 1)): 7,
        ((1, 0), (1, 1, 0, 0)): 3, ((1, 0), (1, 1, 0, 1)): 10, ((1, 0), (1, 1, 1, 0)): 5, ((1, 0), (1, 1, 1, 1)): 0,

        ((1, 1), (0, 0, 0, 0)): 15, ((1, 1), (0, 0, 0, 1)): 12, ((1, 1), (0, 0, 1, 0)): 8, ((1, 1), (0, 0, 1, 1)): 2,
        ((1, 1), (0, 1, 0, 0)): 4, ((1, 1), (0, 1, 0, 1)): 9, ((1, 1), (0, 1, 1, 0)): 1, ((1, 1), (0, 1, 1, 1)): 7,
        ((1, 1), (1, 0, 0, 0)): 5, ((1, 1), (1, 0, 0, 1)): 11, ((1, 1), (1, 0, 1, 0)): 3, ((1, 1), (1, 0, 1, 1)): 14,
        ((1, 1), (1, 1, 0, 0)): 10, ((1, 1), (1, 1, 0, 1)): 0, ((1, 1), (1, 1, 1, 0)): 6, ((1, 1), (1, 1, 1, 1)): 13
    }

    # returns the value in binary as a bitarray
    bits = format(table[key], "04b")
    return bitarray(bits)

def lookup_s_table_2(x, y):
    # change from bit arrays to tuples, then create the tuple of them together
    bit_x = tuple(map(int, x))
    bit_y = tuple(map(int, y))
    key = (bit_y, bit_x)

    # uses the key to find the value to substitute with
    table = {
        ((0, 0), (0, 0, 0, 0)): 15, ((0, 0), (0, 0, 0, 1)): 1, ((0, 0), (0, 0, 1, 0)): 8, ((0, 0), (0, 0, 1, 1)): 14,
        ((0, 0), (0, 1, 0, 0)): 6, ((0, 0), (0, 1, 0, 1)): 11, ((0, 0), (0, 1, 1, 0)): 3, ((0, 0), (0, 1, 1, 1)): 4,
        ((0, 0), (1, 0, 0, 0)): 9, ((0, 0), (1, 0, 0, 1)): 7, ((0, 0), (1, 0, 1, 0)): 2, ((0, 0), (1, 0, 1, 1)): 13,
        ((0, 0), (1, 1, 0, 0)): 12, ((0, 0), (1, 1, 0, 1)): 0, ((0, 0), (1, 1, 1, 0)): 5, ((0, 0), (1, 1, 1, 1)): 10,

        ((0, 1), (0, 0, 0, 0)): 3, ((0, 1), (0, 0, 0, 1)): 13, ((0, 1), (0, 0, 1, 0)): 4, ((0, 1), (0, 0, 1, 1)): 7,
        ((0, 1), (0, 1, 0, 0)): 15, ((0, 1), (0, 1, 0, 1)): 2, ((0, 1), (0, 1, 1, 0)): 8, ((0, 1), (0, 1, 1, 1)): 14,
        ((0, 1), (1, 0, 0, 0)): 12, ((0, 1), (1, 0, 0, 1)): 0, ((0, 1), (1, 0, 1, 0)): 1, ((0, 1), (1, 0, 1, 1)): 10,
        ((0, 1), (1, 1, 0, 0)): 6, ((0, 1), (1, 1, 0, 1)): 9, ((0, 1), (1, 1, 1, 0)): 11, ((0, 1), (1, 1, 1, 1)): 5,

        ((1, 0), (0, 0, 0, 0)): 0, ((1, 0), (0, 0, 0, 1)): 14, ((1, 0), (0, 0, 1, 0)): 7, ((1, 0), (0, 0, 1, 1)): 11,
        ((1, 0), (0, 1, 0, 0)): 10, ((1, 0), (0, 1, 0, 1)): 4, ((1, 0), (0, 1, 1, 0)): 13, ((1, 0), (0, 1, 1, 1)): 1,
        ((1, 0), (1, 0, 0, 0)): 5, ((1, 0), (1, 0, 0, 1)): 8, ((1, 0), (1, 0, 1, 0)): 12, ((1, 0), (1, 0, 1, 1)): 6,
        ((1, 0), (1, 1, 0, 0)): 9, ((1, 0), (1, 1, 0, 1)): 3, ((1, 0), (1, 1, 1, 0)): 2, ((1, 0), (1, 1, 1, 1)): 15,

        ((1, 1), (0, 0, 0, 0)): 13, ((1, 1), (0, 0, 0, 1)): 8, ((1, 1), (0, 0, 1, 0)): 10, ((1, 1), (0, 0, 1, 1)): 1,
        ((1, 1), (0, 1, 0, 0)): 3, ((1, 1), (0, 1, 0, 1)): 15, ((1, 1), (0, 1, 1, 0)): 4, ((1, 1), (0, 1, 1, 1)): 2,
        ((1, 1), (1, 0, 0, 0)): 11, ((1, 1), (1, 0, 0, 1)): 6, ((1, 1), (1, 0, 1, 0)): 7, ((1, 1), (1, 0, 1, 1)): 12,
        ((1, 1), (1, 1, 0, 0)): 2, ((1, 1), (1, 1, 0, 1)): 5, ((1, 1), (1, 1, 1, 0)): 14, ((1, 1), (1, 1, 1, 1)): 9
    }
    # returns the value in binary as a bitarray
    bits = format(table[key], "04b")
    return bitarray(bits)

def lookup_s_table_3(x, y):
    # change from bit arrays to tuples, then create the tuple of them together
    bit_x = tuple(map(int, x))
    bit_y = tuple(map(int, y))
    key = (bit_y, bit_x)
    # uses the key to find the value to substitute with
    table = {
        ((0, 0), (0, 0, 0, 0)): 10, ((0, 0), (0, 0, 0, 1)): 0, ((0, 0), (0, 0, 1, 0)): 9, ((0, 0), (0, 0, 1, 1)): 14,
        ((0, 0), (0, 1, 0, 0)): 6, ((0, 0), (0, 1, 0, 1)): 3, ((0, 0), (0, 1, 1, 0)): 15, ((0, 0), (0, 1, 1, 1)): 5,
        ((0, 0), (1, 0, 0, 0)): 1, ((0, 0), (1, 0, 0, 1)): 13, ((0, 0), (1, 0, 1, 0)): 12, ((0, 0), (1, 0, 1, 1)): 7,
        ((0, 0), (1, 1, 0, 0)): 11, ((0, 0), (1, 1, 0, 1)): 4, ((0, 0), (1, 1, 1, 0)): 2, ((0, 0), (1, 1, 1, 1)): 8,

        ((0, 1), (0, 0, 0, 0)): 13, ((0, 1), (0, 0, 0, 1)): 7, ((0, 1), (0, 0, 1, 0)): 0, ((0, 1), (0, 0, 1, 1)): 9,
        ((0, 1), (0, 1, 0, 0)): 3, ((0, 1), (0, 1, 0, 1)): 4, ((0, 1), (0, 1, 1, 0)): 6, ((0, 1), (0, 1, 1, 1)): 10,
        ((0, 1), (1, 0, 0, 0)): 2, ((0, 1), (1, 0, 0, 1)): 8, ((0, 1), (1, 0, 1, 0)): 5, ((0, 1), (1, 0, 1, 1)): 14,
        ((0, 1), (1, 1, 0, 0)): 12, ((0, 1), (1, 1, 0, 1)): 11, ((0, 1), (1, 1, 1, 0)): 15, ((0, 1), (1, 1, 1, 1)): 1,

        ((1, 0), (0, 0, 0, 0)): 13, ((1, 0), (0, 0, 0, 1)): 6, ((1, 0), (0, 0, 1, 0)): 4, ((1, 0), (0, 0, 1, 1)): 9,
        ((1, 0), (0, 1, 0, 0)): 8, ((1, 0), (0, 1, 0, 1)): 15, ((1, 0), (0, 1, 1, 0)): 3, ((1, 0), (0, 1, 1, 1)): 0,
        ((1, 0), (1, 0, 0, 0)): 11, ((1, 0), (1, 0, 0, 1)): 1, ((1, 0), (1, 0, 1, 0)): 2, ((1, 0), (1, 0, 1, 1)): 12,
        ((1, 0), (1, 1, 0, 0)): 5, ((1, 0), (1, 1, 0, 1)): 10, ((1, 0), (1, 1, 1, 0)): 14, ((1, 0), (1, 1, 1, 1)): 7,

        ((1, 1), (0, 0, 0, 0)): 1, ((1, 1), (0, 0, 0, 1)): 10, ((1, 1), (0, 0, 1, 0)): 13, ((1, 1), (0, 0, 1, 1)): 0,
        ((1, 1), (0, 1, 0, 0)): 6, ((1, 1), (0, 1, 0, 1)): 9, ((1, 1), (0, 1, 1, 0)): 8, ((1, 1), (0, 1, 1, 1)): 7,
        ((1, 1), (1, 0, 0, 0)): 4, ((1, 1), (1, 0, 0, 1)): 15, ((1, 1), (1, 0, 1, 0)): 14, ((1, 1), (1, 0, 1, 1)): 3,
        ((1, 1), (1, 1, 0, 0)): 11, ((1, 1), (1, 1, 0, 1)): 5, ((1, 1), (1, 1, 1, 0)): 2, ((1, 1), (1, 1, 1, 1)): 12
    }
    # returns the value in binary as a bitarray
    bits = format(table[key], "04b")
    return bitarray(bits)

def lookup_s_table_4(x, y):
    # change from bit arrays to tuples, then create the tuple of them together
    bit_x = tuple(map(int, x))
    bit_y = tuple(map(int, y))
    key = (bit_y, bit_x)
    # uses the key to find the value to substitute with
    table = {
        ((0, 0), (0, 0, 0, 0)): 7, ((0, 0), (0, 0, 0, 1)): 13, ((0, 0), (0, 0, 1, 0)): 14, ((0, 0), (0, 0, 1, 1)): 3,
        ((0, 0), (0, 1, 0, 0)): 0, ((0, 0), (0, 1, 0, 1)): 6, ((0, 0), (0, 1, 1, 0)): 9, ((0, 0), (0, 1, 1, 1)): 10,
        ((0, 0), (1, 0, 0, 0)): 1, ((0, 0), (1, 0, 0, 1)): 2, ((0, 0), (1, 0, 1, 0)): 8, ((0, 0), (1, 0, 1, 1)): 5,
        ((0, 0), (1, 1, 0, 0)): 11, ((0, 0), (1, 1, 0, 1)): 12, ((0, 0), (1, 1, 1, 0)): 4, ((0, 0), (1, 1, 1, 1)): 15,

        ((0, 1), (0, 0, 0, 0)): 13, ((0, 1), (0, 0, 0, 1)): 8, ((0, 1), (0, 0, 1, 0)): 11, ((0, 1), (0, 0, 1, 1)): 5,
        ((0, 1), (0, 1, 0, 0)): 6, ((0, 1), (0, 1, 0, 1)): 15, ((0, 1), (0, 1, 1, 0)): 0, ((0, 1), (0, 1, 1, 1)): 3,
        ((0, 1), (1, 0, 0, 0)): 4, ((0, 1), (1, 0, 0, 1)): 7, ((0, 1), (1, 0, 1, 0)): 2, ((0, 1), (1, 0, 1, 1)): 12,
        ((0, 1), (1, 1, 0, 0)): 1, ((0, 1), (1, 1, 0, 1)): 10, ((0, 1), (1, 1, 1, 0)): 14, ((0, 1), (1, 1, 1, 1)): 9,

        ((1, 0), (0, 0, 0, 0)): 10, ((1, 0), (0, 0, 0, 1)): 6, ((1, 0), (0, 0, 1, 0)): 9, ((1, 0), (0, 0, 1, 1)): 0,
        ((1, 0), (0, 1, 0, 0)): 12, ((1, 0), (0, 1, 0, 1)): 11, ((1, 0), (0, 1, 1, 0)): 7, ((1, 0), (0, 1, 1, 1)): 13,
        ((1, 0), (1, 0, 0, 0)): 15, ((1, 0), (1, 0, 0, 1)): 1, ((1, 0), (1, 0, 1, 0)): 3, ((1, 0), (1, 0, 1, 1)): 14,
        ((1, 0), (1, 1, 0, 0)): 5, ((1, 0), (1, 1, 0, 1)): 2, ((1, 0), (1, 1, 1, 0)): 8, ((1, 0), (1, 1, 1, 1)): 4,

        ((1, 1), (0, 0, 0, 0)): 3, ((1, 1), (0, 0, 0, 1)): 15, ((1, 1), (0, 0, 1, 0)): 0, ((1, 1), (0, 0, 1, 1)): 6,
        ((1, 1), (0, 1, 0, 0)): 10, ((1, 1), (0, 1, 0, 1)): 1, ((1, 1), (0, 1, 1, 0)): 13, ((1, 1), (0, 1, 1, 1)): 8,
        ((1, 1), (1, 0, 0, 0)): 9, ((1, 1), (1, 0, 0, 1)): 4, ((1, 1), (1, 0, 1, 0)): 5, ((1, 1), (1, 0, 1, 1)): 11,
        ((1, 1), (1, 1, 0, 0)): 12, ((1, 1), (1, 1, 0, 1)): 7, ((1, 1), (1, 1, 1, 0)): 2, ((1, 1), (1, 1, 1, 1)): 14
    }
    # returns the value in binary as a bitarray
    bits = format(table[key], "04b")
    return bitarray(bits)
def lookup_s_table_5(x, y):
    # change from bit arrays to tuples, then create the tuple of them together
    bit_x = tuple(map(int, x))
    bit_y = tuple(map(int, y))
    key = (bit_y, bit_x)
    # uses the key to find the value to substitute with
    table = {
        ((0, 0), (0, 0, 0, 0)): 2, ((0, 0), (0, 0, 0, 1)): 12, ((0, 0), (0, 0, 1, 0)): 4, ((0, 0), (0, 0, 1, 1)): 1,
        ((0, 0), (0, 1, 0, 0)): 7, ((0, 0), (0, 1, 0, 1)): 10, ((0, 0), (0, 1, 1, 0)): 11, ((0, 0), (0, 1, 1, 1)): 6,
        ((0, 0), (1, 0, 0, 0)): 8, ((0, 0), (1, 0, 0, 1)): 5, ((0, 0), (1, 0, 1, 0)): 3, ((0, 0), (1, 0, 1, 1)): 15,
        ((0, 0), (1, 1, 0, 0)): 13, ((0, 0), (1, 1, 0, 1)): 0, ((0, 0), (1, 1, 1, 0)): 14, ((0, 0), (1, 1, 1, 1)): 9,

        ((0, 1), (0, 0, 0, 0)): 14, ((0, 1), (0, 0, 0, 1)): 11, ((0, 1), (0, 0, 1, 0)): 2, ((0, 1), (0, 0, 1, 1)): 12,
        ((0, 1), (0, 1, 0, 0)): 4, ((0, 1), (0, 1, 0, 1)): 7, ((0, 1), (0, 1, 1, 0)): 13, ((0, 1), (0, 1, 1, 1)): 1,
        ((0, 1), (1, 0, 0, 0)): 5, ((0, 1), (1, 0, 0, 1)): 0, ((0, 1), (1, 0, 1, 0)): 15, ((0, 1), (1, 0, 1, 1)): 10,
        ((0, 1), (1, 1, 0, 0)): 3, ((0, 1), (1, 1, 0, 1)): 9, ((0, 1), (1, 1, 1, 0)): 8, ((0, 1), (1, 1, 1, 1)): 6,

        ((1, 0), (0, 0, 0, 0)): 4, ((1, 0), (0, 0, 0, 1)): 2, ((1, 0), (0, 0, 1, 0)): 1, ((1, 0), (0, 0, 1, 1)): 11,
        ((1, 0), (0, 1, 0, 0)): 10, ((1, 0), (0, 1, 0, 1)): 13, ((1, 0), (0, 1, 1, 0)): 7, ((1, 0), (0, 1, 1, 1)): 8,
        ((1, 0), (1, 0, 0, 0)): 15, ((1, 0), (1, 0, 0, 1)): 9, ((1, 0), (1, 0, 1, 0)): 12, ((1, 0), (1, 0, 1, 1)): 5,
        ((1, 0), (1, 1, 0, 0)): 6, ((1, 0), (1, 1, 0, 1)): 3, ((1, 0), (1, 1, 1, 0)): 0, ((1, 0), (1, 1, 1, 1)): 14,

        ((1, 1), (0, 0, 0, 0)): 11, ((1, 1), (0, 0, 0, 1)): 8, ((1, 1), (0, 0, 1, 0)): 12, ((1, 1), (0, 0, 1, 1)): 7,
        ((1, 1), (0, 1, 0, 0)): 1, ((1, 1), (0, 1, 0, 1)): 14, ((1, 1), (0, 1, 1, 0)): 2, ((1, 1), (0, 1, 1, 1)): 13,
        ((1, 1), (1, 0, 0, 0)): 6, ((1, 1), (1, 0, 0, 1)): 15, ((1, 1), (1, 0, 1, 0)): 0, ((1, 1), (1, 0, 1, 1)): 9,
        ((1, 1), (1, 1, 0, 0)): 10, ((1, 1), (1, 1, 0, 1)): 4, ((1, 1), (1, 1, 1, 0)): 5, ((1, 1), (1, 1, 1, 1)): 3
    }
    # returns the value in binary as a bitarray
    bits = format(table[key], "04b")
    return bitarray(bits)

def lookup_s_table_6(x, y):
    # change from bit arrays to tuples, then create the tuple of them together
    bit_x = tuple(map(int, x))
    bit_y = tuple(map(int, y))
    key = (bit_y, bit_x)
    # uses the key to find the value to substitute with
    table = {
        ((0, 0), (0, 0, 0, 0)): 12, ((0, 0), (0, 0, 0, 1)): 1, ((0, 0), (0, 0, 1, 0)): 10, ((0, 0), (0, 0, 1, 1)): 15,
        ((0, 0), (0, 1, 0, 0)): 9, ((0, 0), (0, 1, 0, 1)): 2, ((0, 0), (0, 1, 1, 0)): 6, ((0, 0), (0, 1, 1, 1)): 8,
        ((0, 0), (1, 0, 0, 0)): 0, ((0, 0), (1, 0, 0, 1)): 13, ((0, 0), (1, 0, 1, 0)): 3, ((0, 0), (1, 0, 1, 1)): 4,
        ((0, 0), (1, 1, 0, 0)): 14, ((0, 0), (1, 1, 0, 1)): 7, ((0, 0), (1, 1, 1, 0)): 5, ((0, 0), (1, 1, 1, 1)): 11,

        ((0, 1), (0, 0, 0, 0)): 10, ((0, 1), (0, 0, 0, 1)): 15, ((0, 1), (0, 0, 1, 0)): 4, ((0, 1), (0, 0, 1, 1)): 2,
        ((0, 1), (0, 1, 0, 0)): 7, ((0, 1), (0, 1, 0, 1)): 12, ((0, 1), (0, 1, 1, 0)): 9, ((0, 1), (0, 1, 1, 1)): 5,
        ((0, 1), (1, 0, 0, 0)): 6, ((0, 1), (1, 0, 0, 1)): 1, ((0, 1), (1, 0, 1, 0)): 13, ((0, 1), (1, 0, 1, 1)): 14,
        ((0, 1), (1, 1, 0, 0)): 0, ((0, 1), (1, 1, 0, 1)): 11, ((0, 1), (1, 1, 1, 0)): 3, ((0, 1), (1, 1, 1, 1)): 8,

        ((1, 0), (0, 0, 0, 0)): 9, ((1, 0), (0, 0, 0, 1)): 14, ((1, 0), (0, 0, 1, 0)): 15, ((1, 0), (0, 0, 1, 1)): 5,
        ((1, 0), (0, 1, 0, 0)): 2, ((1, 0), (0, 1, 0, 1)): 8, ((1, 0), (0, 1, 1, 0)): 12, ((1, 0), (0, 1, 1, 1)): 3,
        ((1, 0), (1, 0, 0, 0)): 7, ((1, 0), (1, 0, 0, 1)): 0, ((1, 0), (1, 0, 1, 0)): 4, ((1, 0), (1, 0, 1, 1)): 10,
        ((1, 0), (1, 1, 0, 0)): 1, ((1, 0), (1, 1, 0, 1)): 13, ((1, 0), (1, 1, 1, 0)): 11, ((1, 0), (1, 1, 1, 1)): 6,

        ((1, 1), (0, 0, 0, 0)): 4, ((1, 1), (0, 0, 0, 1)): 3, ((1, 1), (0, 0, 1, 0)): 2, ((1, 1), (0, 0, 1, 1)): 12,
        ((1, 1), (0, 1, 0, 0)): 9, ((1, 1), (0, 1, 0, 1)): 5, ((1, 1), (0, 1, 1, 0)): 15, ((1, 1), (0, 1, 1, 1)): 10,
        ((1, 1), (1, 0, 0, 0)): 11, ((1, 1), (1, 0, 0, 1)): 14, ((1, 1), (1, 0, 1, 0)): 1, ((1, 1), (1, 0, 1, 1)): 7,
        ((1, 1), (1, 1, 0, 0)): 6, ((1, 1), (1, 1, 0, 1)): 0, ((1, 1), (1, 1, 1, 0)): 8, ((1, 1), (1, 1, 1, 1)): 13
    }
    # returns the value in binary as a bitarray
    bits = format(table[key], "04b")
    return bitarray(bits)

def lookup_s_table_7(x, y):
    # change from bit arrays to tuples, then create the tuple of them together
    bit_x = tuple(map(int, x))
    bit_y = tuple(map(int, y))
    key = (bit_y, bit_x)
    # uses the key to find the value to substitute with
    table = {
        ((0, 0), (0, 0, 0, 0)): 4, ((0, 0), (0, 0, 0, 1)): 11, ((0, 0), (0, 0, 1, 0)): 2, ((0, 0), (0, 0, 1, 1)): 14,
        ((0, 0), (0, 1, 0, 0)): 15, ((0, 0), (0, 1, 0, 1)): 0, ((0, 0), (0, 1, 1, 0)): 8, ((0, 0), (0, 1, 1, 1)): 13,
        ((0, 0), (1, 0, 0, 0)): 3, ((0, 0), (1, 0, 0, 1)): 12, ((0, 0), (1, 0, 1, 0)): 9, ((0, 0), (1, 0, 1, 1)): 7,
        ((0, 0), (1, 1, 0, 0)): 5, ((0, 0), (1, 1, 0, 1)): 10, ((0, 0), (1, 1, 1, 0)): 6, ((0, 0), (1, 1, 1, 1)): 1,

        ((0, 1), (0, 0, 0, 0)): 13, ((0, 1), (0, 0, 0, 1)): 0, ((0, 1), (0, 0, 1, 0)): 11, ((0, 1), (0, 0, 1, 1)): 7,
        ((0, 1), (0, 1, 0, 0)): 4, ((0, 1), (0, 1, 0, 1)): 9, ((0, 1), (0, 1, 1, 0)): 1, ((0, 1), (0, 1, 1, 1)): 10,
        ((0, 1), (1, 0, 0, 0)): 14, ((0, 1), (1, 0, 0, 1)): 3, ((0, 1), (1, 0, 1, 0)): 5, ((0, 1), (1, 0, 1, 1)): 12,
        ((0, 1), (1, 1, 0, 0)): 2, ((0, 1), (1, 1, 0, 1)): 15, ((0, 1), (1, 1, 1, 0)): 8, ((0, 1), (1, 1, 1, 1)): 6,

        ((1, 0), (0, 0, 0, 0)): 1, ((1, 0), (0, 0, 0, 1)): 4, ((1, 0), (0, 0, 1, 0)): 11, ((1, 0), (0, 0, 1, 1)): 13,
        ((1, 0), (0, 1, 0, 0)): 12, ((1, 0), (0, 1, 0, 1)): 3, ((1, 0), (0, 1, 1, 0)): 7, ((1, 0), (0, 1, 1, 1)): 14,
        ((1, 0), (1, 0, 0, 0)): 10, ((1, 0), (1, 0, 0, 1)): 15, ((1, 0), (1, 0, 1, 0)): 6, ((1, 0), (1, 0, 1, 1)): 8,
        ((1, 0), (1, 1, 0, 0)): 0, ((1, 0), (1, 1, 0, 1)): 5, ((1, 0), (1, 1, 1, 0)): 9, ((1, 0), (1, 1, 1, 1)): 2,

        ((1, 1), (0, 0, 0, 0)): 6, ((1, 1), (0, 0, 0, 1)): 11, ((1, 1), (0, 0, 1, 0)): 13, ((1, 1), (0, 0, 1, 1)): 8,
        ((1, 1), (0, 1, 0, 0)): 1, ((1, 1), (0, 1, 0, 1)): 4, ((1, 1), (0, 1, 1, 0)): 10, ((1, 1), (0, 1, 1, 1)): 7,
        ((1, 1), (1, 0, 0, 0)): 9, ((1, 1), (1, 0, 0, 1)): 5, ((1, 1), (1, 0, 1, 0)): 0, ((1, 1), (1, 0, 1, 1)): 15,
        ((1, 1), (1, 1, 0, 0)): 14, ((1, 1), (1, 1, 0, 1)): 2, ((1, 1), (1, 1, 1, 0)): 3, ((1, 1), (1, 1, 1, 1)): 12
    }
    # returns the value in binary as a bitarray
    bits = format(table[key], "04b")
    return bitarray(bits)
def lookup_s_table_8(x, y):
    # change from bit arrays to tuples, then create the tuple of them together
    bit_x = tuple(map(int, x))
    bit_y = tuple(map(int, y))
    key = (bit_y, bit_x)
    # uses the key to find the value to substitute with
    table = {
        ((0, 0), (0, 0, 0, 0)): 13, ((0, 0), (0, 0, 0, 1)): 2, ((0, 0), (0, 0, 1, 0)): 8, ((0, 0), (0, 0, 1, 1)): 4,
        ((0, 0), (0, 1, 0, 0)): 6, ((0, 0), (0, 1, 0, 1)): 15, ((0, 0), (0, 1, 1, 0)): 11, ((0, 0), (0, 1, 1, 1)): 1,
        ((0, 0), (1, 0, 0, 0)): 10, ((0, 0), (1, 0, 0, 1)): 9, ((0, 0), (1, 0, 1, 0)): 3, ((0, 0), (1, 0, 1, 1)): 14,
        ((0, 0), (1, 1, 0, 0)): 5, ((0, 0), (1, 1, 0, 1)): 0, ((0, 0), (1, 1, 1, 0)): 12, ((0, 0), (1, 1, 1, 1)): 7,

        ((0, 1), (0, 0, 0, 0)): 1, ((0, 1), (0, 0, 0, 1)): 15, ((0, 1), (0, 0, 1, 0)): 13, ((0, 1), (0, 0, 1, 1)): 8,
        ((0, 1), (0, 1, 0, 0)): 10, ((0, 1), (0, 1, 0, 1)): 3, ((0, 1), (0, 1, 1, 0)): 7, ((0, 1), (0, 1, 1, 1)): 4,
        ((0, 1), (1, 0, 0, 0)): 12, ((0, 1), (1, 0, 0, 1)): 5, ((0, 1), (1, 0, 1, 0)): 6, ((0, 1), (1, 0, 1, 1)): 11,
        ((0, 1), (1, 1, 0, 0)): 0, ((0, 1), (1, 1, 0, 1)): 14, ((0, 1), (1, 1, 1, 0)): 9, ((0, 1), (1, 1, 1, 1)): 2,

        ((1, 0), (0, 0, 0, 0)): 7, ((1, 0), (0, 0, 0, 1)): 11, ((1, 0), (0, 0, 1, 0)): 4, ((1, 0), (0, 0, 1, 1)): 1,
        ((1, 0), (0, 1, 0, 0)): 9, ((1, 0), (0, 1, 0, 1)): 12, ((1, 0), (0, 1, 1, 0)): 14, ((1, 0), (0, 1, 1, 1)): 2,
        ((1, 0), (1, 0, 0, 0)): 0, ((1, 0), (1, 0, 0, 1)): 6, ((1, 0), (1, 0, 1, 0)): 10, ((1, 0), (1, 0, 1, 1)): 13,
        ((1, 0), (1, 1, 0, 0)): 15, ((1, 0), (1, 1, 0, 1)): 3, ((1, 0), (1, 1, 1, 0)): 5, ((1, 0), (1, 1, 1, 1)): 8,

        ((1, 1), (0, 0, 0, 0)): 2, ((1, 1), (0, 0, 0, 1)): 1, ((1, 1), (0, 0, 1, 0)): 14, ((1, 1), (0, 0, 1, 1)): 7,
        ((1, 1), (0, 1, 0, 0)): 4, ((1, 1), (0, 1, 0, 1)): 10, ((1, 1), (0, 1, 1, 0)): 8, ((1, 1), (0, 1, 1, 1)): 13,
        ((1, 1), (1, 0, 0, 0)): 15, ((1, 1), (1, 0, 0, 1)): 12, ((1, 1), (1, 0, 1, 0)): 9, ((1, 1), (1, 0, 1, 1)): 0,
        ((1, 1), (1, 1, 0, 0)): 3, ((1, 1), (1, 1, 0, 1)): 5, ((1, 1), (1, 1, 1, 0)): 6, ((1, 1), (1, 1, 1, 1)): 11
    }
    # returns the value in binary as a bitarray
    bits = format(table[key], "04b")
    return bitarray(bits)

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

def p_box_perm(subbed):
    # permutation according to pre-defined tables
    subbed2 = subbed.copy()
    subbed[0] = subbed2[15]
    subbed[1] = subbed2[6]
    subbed[2] = subbed2[19]
    subbed[3] = subbed2[20]
    subbed[4] = subbed2[28]
    subbed[5] = subbed2[11]
    subbed[6] = subbed2[27]
    subbed[7] = subbed2[16]
    subbed[8] = subbed2[0]
    subbed[9] = subbed2[14]
    subbed[10] = subbed2[22]
    subbed[11] = subbed2[25]
    subbed[12] = subbed2[4]
    subbed[13] = subbed2[17]
    subbed[14] = subbed2[30]
    subbed[15] = subbed2[9]
    subbed[16] = subbed2[1]
    subbed[17] = subbed2[7]
    subbed[18] = subbed2[23]
    subbed[19] = subbed2[13]
    subbed[20] = subbed2[31]
    subbed[21] = subbed2[26]
    subbed[22] = subbed2[2]
    subbed[23] = subbed2[8]
    subbed[24] = subbed2[18]
    subbed[25] = subbed2[12]
    subbed[26] = subbed2[29]
    subbed[27] = subbed2[5]
    subbed[28] = subbed2[21]
    subbed[29] = subbed2[10]
    subbed[30] = subbed2[3]
    subbed[31] = subbed2[24]

    # permutates in place, so no need to return/reassign


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

def final_perm(block):
    # permutation following pre-defined permutation table
    block2 = block.copy()
    block2[57] = block[0]
    block2[49] = block[1]
    block2[41] = block[2]
    block2[33] = block[3]
    block2[25] = block[4]
    block2[17] = block[5]
    block2[9] = block[6]
    block2[1] = block[7]

    block2[59] = block[8]
    block2[51] = block[9]
    block2[43] = block[10]
    block2[35] = block[11]
    block2[27] = block[12]
    block2[19] = block[13]
    block2[11] = block[14]
    block2[3] = block[15]

    block2[61] = block[16]
    block2[53] = block[17]
    block2[45] = block[18]
    block2[37] = block[19]
    block2[29] = block[20]
    block2[21] = block[21]
    block2[13] = block[22]
    block2[5] = block[23]

    block2[63] = block[24]
    block2[55] = block[25]
    block2[47] = block[26]
    block2[39] = block[27]
    block2[31] = block[28]
    block2[23] = block[29]
    block2[15] = block[30]
    block2[7] = block[31]

    block2[56] = block[32]
    block2[48] = block[33]
    block2[40] = block[34]
    block2[32] = block[35]
    block2[24] = block[36]
    block2[16] = block[37]
    block2[8] = block[38]
    block2[0] = block[39]

    block2[58] = block[40]
    block2[50] = block[41]
    block2[42] = block[42]
    block2[34] = block[43]
    block2[26] = block[44]
    block2[18] = block[45]
    block2[10] = block[46]
    block2[2] = block[47]

    block2[60] = block[48]
    block2[52] = block[49]
    block2[44] = block[50]
    block2[36] = block[51]
    block2[28] = block[52]
    block2[20] = block[53]
    block2[12] = block[54]
    block2[4] = block[55]

    block2[62] = block[56]
    block2[54] = block[57]
    block2[46] = block[58]
    block2[38] = block[59]
    block2[30] = block[60]
    block2[22] = block[61]
    block2[14] = block[62]
    block2[6] = block[63]

    return block2

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
    ifile_name = sys.argv[1]
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