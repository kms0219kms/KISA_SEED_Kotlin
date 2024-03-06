import lib.KISA_SEED_LIB

/**
 * @file KISA_SEED_CCM.kt
 * @brief SEED CCM 암호 알고리즘
 * @author Copyright (c) 2009 by KISA
 * @author Copyright (c) 2024 by Ayaan_ <minsu.kim@hanarin.uk>
 * @remarks http://seed.kisa.or.kr/
 */

class KISA_SEED_CCM {
    fun SEED_CCM_Encryption(
        ct: ByteArray,
        pt: ByteArray, ptLen: Int,
        macLen: Int,
        nonce: ByteArray, nonceLen: Int,
        aad: ByteArray, aadLen: Int,
        mKey: ByteArray
    ): Int {
        val CTR_in = IntArray(4)
        val CTR_out = IntArray(4)
        val CBC_in = IntArray(4)
        val CBC_out = IntArray(4)
        val MAC = IntArray(4)
        val tmp = IntArray(8)
        val rKey = IntArray(100)
        var i: Int
        var tmpLen = 0
        val seed = KISA_SEED_LIB()

        if (macLen > BLOCK_SIZE_SEED) return 1

        seed.SEED_KeySched(mKey, rKey)

        Byte2Word(CTR_in, nonce, 0, nonceLen)
        SHIFTR8(CTR_in)

        var flag = 14 - nonceLen

        CTR_in[0] = CTR_in[0] xor (flag shl 24)

        seed.SEED_Encrypt(MAC, CTR_in, rKey)

        i = 0
        while (i < ptLen) {
            INCREASE(CTR_in)

            ZERO128(tmp)

            if ((ptLen - i) < BLOCK_SIZE_SEED) Byte2Word(tmp, pt, i, ptLen - i)
            else Byte2Word(tmp, pt, i, BLOCK_SIZE_SEED)

            seed.SEED_Encrypt(CTR_out, CTR_in, rKey)

            XOR128(tmp, CTR_out, tmp)

            if ((ptLen - i) < BLOCK_SIZE_SEED) Word2Byte(ct, i, tmp, ptLen - i)
            else Word2Byte(ct, i, tmp, BLOCK_SIZE_SEED)
            i += BLOCK_SIZE_SEED
        }

        Byte2Word(CBC_in, nonce, 0, nonceLen)
        SHIFTR8(CBC_in)

        flag = if (aadLen > 0) 0x00000040
        else 0x00000000
        flag = flag xor (((macLen - 2) shr 1) shl 3)
        flag = flag xor 14 - nonceLen

        CBC_in[0] = CBC_in[0] xor (flag shl 24)
        CBC_in[3] = CBC_in[3] xor ptLen

        seed.SEED_Encrypt(CBC_out, CBC_in, rKey)

        if (aadLen > 0) {
            tmpLen = if (aadLen > 14) 14
            else aadLen

            ZERO128(CBC_in)

            Byte2Word(CBC_in, aad, 0, tmpLen)
            SHIFTR16(CBC_in)

            CBC_in[0] = CBC_in[0] xor ((aadLen shl 16) and -0x10000)

            XOR128(CBC_in, CBC_in, CBC_out)

            seed.SEED_Encrypt(CBC_out, CBC_in, rKey)

            i = tmpLen
            while (i < aadLen) {
                ZERO128(CBC_in)

                if ((aadLen - i) < BLOCK_SIZE_SEED) Byte2Word(CBC_in, aad, i, aadLen - i)
                else Byte2Word(CBC_in, aad, i, BLOCK_SIZE_SEED)

                XOR128(CBC_in, CBC_in, CBC_out)

                seed.SEED_Encrypt(CBC_out, CBC_in, rKey)
                i += BLOCK_SIZE_SEED
            }
        }

        i = 0
        while (i < ptLen) {
            ZERO128(tmp)

            if ((ptLen - i) < BLOCK_SIZE_SEED) Byte2Word(tmp, pt, i, ptLen - i)
            else Byte2Word(tmp, pt, i, BLOCK_SIZE_SEED)

            XOR128(CBC_in, tmp, CBC_out)

            seed.SEED_Encrypt(CBC_out, CBC_in, rKey)
            i += BLOCK_SIZE_SEED
        }

        XOR128(MAC, MAC, CBC_out)

        Word2Byte(ct, ptLen, MAC, macLen)

        return ptLen + macLen
    }

    fun SEED_CCM_Decryption(
        pt: ByteArray,
        ct: ByteArray, ctLen: Int,
        macLen: Int,
        nonce: ByteArray, nonceLen: Int,
        aad: ByteArray, aadLen: Int,
        mKey: ByteArray
    ): Int {
        val CTR_in = IntArray(4)
        val CTR_out = IntArray(4)
        val CBC_in = IntArray(4)
        val CBC_out = IntArray(4)
        val MAC = IntArray(4)
        val tMAC = ByteArray(16)
        val tmp = IntArray(8)
        val rKey = IntArray(32)
        var i: Int
        var j: Int
        var tmpLen = 0
        val seed = KISA_SEED_LIB()

        if (macLen > BLOCK_SIZE_SEED) return 1

        seed.SEED_KeySched(mKey, rKey)

        Byte2Word(CTR_in, nonce, 0, nonceLen)
        SHIFTR8(CTR_in)

        var flag = 14 - nonceLen

        CTR_in[0] = CTR_in[0] xor (flag shl 24)

        seed.SEED_Encrypt(MAC, CTR_in, rKey)

        i = 0
        while (i < ctLen - macLen) {
            INCREASE(CTR_in)

            ZERO128(tmp)

            if ((ctLen - macLen - i) < BLOCK_SIZE_SEED) Byte2Word(tmp, ct, i, ctLen - macLen - i)
            else Byte2Word(tmp, ct, i, BLOCK_SIZE_SEED)

            seed.SEED_Encrypt(CTR_out, CTR_in, rKey)

            XOR128(tmp, CTR_out, tmp)

            if ((ctLen - macLen - i) < BLOCK_SIZE_SEED) Word2Byte(pt, i, tmp, ctLen - macLen - i)
            else Word2Byte(pt, i, tmp, BLOCK_SIZE_SEED)
            i += BLOCK_SIZE_SEED
        }

        Byte2Word(CBC_in, nonce, 0, nonceLen)
        SHIFTR8(CBC_in)

        flag = if (aadLen > 0) 0x00000040
        else 0x00000000

        flag = flag xor (((macLen - 2) shr 1) shl 3)
        flag = flag xor 14 - nonceLen

        CBC_in[0] = CBC_in[0] xor (flag shl 24)
        CBC_in[3] = CBC_in[3] xor ctLen - macLen

        seed.SEED_Encrypt(CBC_out, CBC_in, rKey)

        if (aadLen > 0) {
            tmpLen = if (aadLen > 14) 14
            else aadLen

            ZERO128(CBC_in)

            Byte2Word(CBC_in, aad, 0, tmpLen)
            SHIFTR16(CBC_in)

            CBC_in[0] = CBC_in[0] xor (aadLen shl 16)

            XOR128(CBC_in, CBC_in, CBC_out)

            seed.SEED_Encrypt(CBC_out, CBC_in, rKey)

            i = tmpLen
            while (i < aadLen) {
                ZERO128(CBC_in)

                if ((aadLen - i) < BLOCK_SIZE_SEED) Byte2Word(CBC_in, aad, i, aadLen - i)
                else Byte2Word(CBC_in, aad, i, BLOCK_SIZE_SEED)

                XOR128(CBC_in, CBC_in, CBC_out)

                seed.SEED_Encrypt(CBC_out, CBC_in, rKey)
                i += BLOCK_SIZE_SEED
            }
        }

        i = 0
        while (i < ctLen - macLen) {
            ZERO128(tmp)

            if ((ctLen - macLen - i) < BLOCK_SIZE_SEED) Byte2Word(tmp, pt, i, ctLen - macLen - i)
            else Byte2Word(tmp, pt, i, BLOCK_SIZE_SEED)

            XOR128(CBC_in, tmp, CBC_out)

            seed.SEED_Encrypt(CBC_out, CBC_in, rKey)
            i += BLOCK_SIZE_SEED
        }

        XOR128(MAC, MAC, CBC_out)

        Word2Byte(tMAC, 0, MAC, macLen)

        i = 0
        while (i < macLen) {
            if (tMAC[i] != ct[ctLen - macLen + i]) {
                j = 0
                while (j < ctLen - macLen) {
                    pt[j] = 0
                    j++
                }

                return 1
            }
            i++
        }

        return ctLen - macLen
    }

    companion object {
        private const val BLOCK_SIZE_SEED = 16

        private fun SHIFTR8(x: IntArray) {
            x[3] = ((x[3] shr 8) and 0x00FFFFFF) xor ((x[2] shl 24) and -0x1000000)
            x[2] = ((x[2] shr 8) and 0x00FFFFFF) xor ((x[1] shl 24) and -0x1000000)
            x[1] = ((x[1] shr 8) and 0x00FFFFFF) xor ((x[0] shl 24) and -0x1000000)
            x[0] = ((x[0] shr 8) and 0x00FFFFFF)
        }

        private fun SHIFTR16(x: IntArray) {
            x[3] = ((x[3] shr 16) and 0x0000FFFF) xor ((x[2] shl 16) and -0x10000)
            x[2] = ((x[2] shr 16) and 0x0000FFFF) xor ((x[1] shl 16) and -0x10000)
            x[1] = ((x[1] shr 16) and 0x0000FFFF) xor ((x[0] shl 16) and -0x10000)
            x[0] = ((x[0] shr 16) and 0x0000FFFF)
        }

        private fun XOR128(R: IntArray, A: IntArray, B: IntArray) {
            R[0] = A[0] xor B[0]
            R[1] = A[1] xor B[1]
            R[2] = A[2] xor B[2]
            R[3] = A[3] xor B[3]
        }

        private fun INCREASE(ctr: IntArray) {
            if (ctr[3] == -0x1) {
                ctr[2]++
                ctr[3] = 0
            } else {
                ctr[3]++
            }
        }

        private fun ZERO128(a: IntArray) {
            a[0] = 0x00000000
            a[1] = 0x00000000
            a[2] = 0x00000000
            a[3] = 0x00000000
        }

        private fun Byte2Word(dst: IntArray, src: ByteArray, src_offset: Int, srcLen: Int) {
            var i = 0
            var remain = 0

            i = 0
            while (i < srcLen) {
                remain = i and 3

                if (remain == 0) dst[i shr 2] = ((src[src_offset + i].toInt() and 0x0FF) shl 24)
                else if (remain == 1) dst[i shr 2] = dst[i shr 2] xor ((src[src_offset + i].toInt() and 0x0FF) shl 16)
                else if (remain == 2) dst[i shr 2] = dst[i shr 2] xor ((src[src_offset + i].toInt() and 0x0FF) shl 8)
                else dst[i shr 2] = dst[i shr 2] xor (src[src_offset + i].toInt() and 0x0FF)
                i++
            }
        }

        private fun Word2Byte(dst: ByteArray, dst_offset: Int, src: IntArray, srcLen: Int) {
            var i = 0
            var remain = 0

            i = 0
            while (i < srcLen) {
                remain = i and 3

                if (remain == 0) dst[dst_offset + i] = (src[i shr 2] shr 24).toByte()
                else if (remain == 1) dst[dst_offset + i] = (src[i shr 2] shr 16).toByte()
                else if (remain == 2) dst[dst_offset + i] = (src[i shr 2] shr 8).toByte()
                else dst[dst_offset + i] = src[i shr 2].toByte()
                i++
            }
        }
    }
}