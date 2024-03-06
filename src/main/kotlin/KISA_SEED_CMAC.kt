import lib.KISA_SEED_LIB

/**
 * @file KISA_SEED_CMAC.kt
 * @brief SEED CMAC 암호 알고리즘
 * @author Copyright (c) 2009 by KISA
 * @author Copyright (c) 2024 by Ayaan_ <minsu.kim@hanarin.uk>
 * @remarks http://seed.kisa.or.kr/
 */

class KISA_SEED_CMAC {
    private fun SEED_CMAC_SubkeySched(sKey: ByteArray) {
        var i = 0
        val carry = (sKey[0].toInt() and 0xff) shr 7

        i = 0
        while (i < 15) {
            sKey[i] = (((sKey[i].toInt() and 0xff) shl 1) or ((sKey[i + 1].toInt() and 0xff) shr 7)).toByte()
            i++
        }

        sKey[i] = ((sKey[i].toInt() and 0xff) shl 1).toByte()

        if (carry != 0) sKey[i] = (sKey[i].toInt() xor 0x87).toByte()
    }

    fun SEED_Generate_CMAC(pMAC: ByteArray, macLen: Int, pIn: ByteArray, inLen: Int, mKey: ByteArray): Int {
        val L = ByteArray(BLOCK_SIZE_SEED)
        val temp = ByteArray(BLOCK_SIZE_SEED)
        val subKey = IntArray(BLOCK_SIZE_SEED / 4)
        val temp1 = IntArray(BLOCK_SIZE_SEED / 4)
        val rKey = IntArray(32)
        var blockLen = 0
        var i = 0
        var j = 0

        val seed = KISA_SEED_LIB()

        if (macLen > BLOCK_SIZE_SEED) return 1

        seed.SEED_KeySched(mKey, rKey)
        seed.SEED_Encrypt(subKey, subKey, rKey)

        Word2Byte(L, subKey, BLOCK_SIZE_SEED)

        // make K1
        SEED_CMAC_SubkeySched(L)

        if (inLen == 0) {
            // make K2
            SEED_CMAC_SubkeySched(L)

            L[0] = (L[0].toInt() xor 0x80).toByte()

            Byte2Word(subKey, L, BLOCK_SIZE_SEED)
            seed.SEED_Encrypt(temp1, subKey, rKey)
        } else {
            // make K2
            SEED_CMAC_SubkeySched(L)

            blockLen = (inLen + BLOCK_SIZE_SEED) / BLOCK_SIZE_SEED

            i = 0
            while (i < blockLen - 1) {
                Word2Byte(temp, temp1, BLOCK_SIZE_SEED)
                j = 0
                while (j < BLOCK_SIZE_SEED) {
                    temp[j] = (temp[j].toInt() xor pIn[BLOCK_SIZE_SEED * i + j].toInt()).toByte()
                    j++
                }

                Byte2Word(temp1, temp, BLOCK_SIZE_SEED)

                seed.SEED_Encrypt(temp1, temp1, rKey)
                i++
            }

            Word2Byte(temp, temp1, BLOCK_SIZE_SEED)

            j = 0
            while ((BLOCK_SIZE_SEED * i + j) < inLen) {
                temp[j] = (temp[j].toInt() xor (pIn[BLOCK_SIZE_SEED * i + j].toInt() xor L[j].toInt())).toByte()
                j++
            }
            temp[j] = (temp[j].toInt() xor (0x80 xor L[j].toInt())).toByte()
            j += 1
            while (j < BLOCK_SIZE_SEED) {
                temp[j] = (temp[j].toInt() xor L[j].toInt()).toByte()
                j++
            }

            Byte2Word(temp1, temp, BLOCK_SIZE_SEED)

            seed.SEED_Encrypt(temp1, temp1, rKey)
        }

        Word2Byte(temp, temp1, BLOCK_SIZE_SEED)

        i = 0
        while (i < macLen) {
            pMAC[i] = temp[i]
            i++
        }

        return 0
    }

    fun SEED_Verify_CMAC(pMAC: ByteArray, macLen: Int, pIn: ByteArray, inLen: Int, mKey: ByteArray): Int {
        val L = ByteArray(BLOCK_SIZE_SEED)
        val temp = ByteArray(BLOCK_SIZE_SEED)
        val subKey = IntArray(BLOCK_SIZE_SEED / 4)
        val temp1 = IntArray(BLOCK_SIZE_SEED / 4)
        val rKey = IntArray(32)
        var blockLen = 0
        var i = 0
        var j = 0

        val seed = KISA_SEED_LIB()

        if (macLen > BLOCK_SIZE_SEED) return 1

        seed.SEED_KeySched(mKey, rKey)
        seed.SEED_Encrypt(subKey, subKey, rKey)

        Word2Byte(L, subKey, BLOCK_SIZE_SEED)

        // make K1
        SEED_CMAC_SubkeySched(L)

        if (inLen == 0) {
            // make K2
            SEED_CMAC_SubkeySched(L)

            L[0] = (L[0].toInt() xor 0x80).toByte()

            Byte2Word(subKey, L, BLOCK_SIZE_SEED)
            seed.SEED_Encrypt(temp1, subKey, rKey)
        } else {
            // make K2
            SEED_CMAC_SubkeySched(L)

            blockLen = (inLen + BLOCK_SIZE_SEED) / BLOCK_SIZE_SEED

            i = 0
            while (i < blockLen - 1) {
                Word2Byte(temp, temp1, BLOCK_SIZE_SEED)
                j = 0
                while (j < BLOCK_SIZE_SEED) {
                    temp[j] = (temp[j].toInt() xor pIn[BLOCK_SIZE_SEED * i + j].toInt()).toByte()
                    j++
                }

                Byte2Word(temp1, temp, BLOCK_SIZE_SEED)

                seed.SEED_Encrypt(temp1, temp1, rKey)
                i++
            }

            Word2Byte(temp, temp1, BLOCK_SIZE_SEED)

            j = 0
            while ((BLOCK_SIZE_SEED * i + j) < inLen) {
                temp[j] = (temp[j].toInt() xor (pIn[BLOCK_SIZE_SEED * i + j].toInt() xor L[j].toInt())).toByte()
                j++
            }
            temp[j] = (temp[j].toInt() xor (0x80 xor L[j].toInt())).toByte()
            j += 1
            while (j < BLOCK_SIZE_SEED) {
                temp[j] = (temp[j].toInt() xor L[j].toInt()).toByte()
                j++
            }

            Byte2Word(temp1, temp, BLOCK_SIZE_SEED)

            seed.SEED_Encrypt(temp1, temp1, rKey)
        }

        Word2Byte(temp, temp1, BLOCK_SIZE_SEED)

        i = 0
        while (i < macLen) {
            if (pMAC[i] != temp[i]) return 1
            i++
        }

        return 0
    }

    companion object {
        private const val BLOCK_SIZE_SEED = 16

        private fun Byte2Word(dst: IntArray, src: ByteArray, srcLen: Int) {
            var i = 0
            var remain = 0

            i = 0
            while (i < srcLen) {
                remain = i and 3

                if (remain == 0) dst[i shr 2] = ((src[i].toInt() and 0x0FF) shl 24)
                else if (remain == 1) dst[i shr 2] = dst[i shr 2] xor ((src[i].toInt() and 0x0FF) shl 16)
                else if (remain == 2) dst[i shr 2] = dst[i shr 2] xor ((src[i].toInt() and 0x0FF) shl 8)
                else dst[i shr 2] = dst[i shr 2] xor (src[i].toInt() and 0x0FF)
                i++
            }
        }

        private fun Word2Byte(dst: ByteArray, src: IntArray, srcLen: Int) {
            var i = 0
            var remain = 0

            i = 0
            while (i < srcLen) {
                remain = i and 3

                if (remain == 0) dst[i] = (src[i shr 2] shr 24).toByte()
                else if (remain == 1) dst[i] = (src[i shr 2] shr 16).toByte()
                else if (remain == 2) dst[i] = (src[i shr 2] shr 8).toByte()
                else dst[i] = src[i shr 2].toByte()
                i++
            }
        }
    }
}