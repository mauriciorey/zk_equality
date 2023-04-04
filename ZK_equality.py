from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    r_o = Secret(utils.get_random_num(bits = 128))
    r_t = Secret(utils.get_random_num(bits = 128))
    mS = Secret(utils.get_random_num(bits = 128))
    C1 = r_o.value * G
    C2 = mS.value * G + r_o.value * H
    D1 = r_t.value * G
    D2 = mS.value * G + r_t.value * H

    #Generate a NIZK proving equality of the plaintexts
    stmt = DLRep(C1, r_o * G) & DLRep(C2, r_o * H + mS * G) & DLRep(D1, r_t * G) & DLRep(D2, r_t * H + mS * G)
    zk_proof = stmt.prove()
    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof

