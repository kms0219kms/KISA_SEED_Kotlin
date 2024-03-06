import lib.KISA_SEED_LIB

/**
 * @file KISA_SEED_GCM.kt
 * @brief SEED GCM 암호 알고리즘
 * @author Copyright (c) 2009 by KISA
 * @author Copyright (c) 2024 by Ayaan_ <minsu.kim@hanarin.uk>
 * @remarks http://seed.kisa.or.kr/
 */

class KISA_SEED_GCM {
    fun SEED_GCM_Encryption(
        ct: ByteArray,
        pt: ByteArray, ptLen: Int,
        macLen: Int,
        nonce: ByteArray, nonceLen: Int,
        aad: ByteArray, aadLen: Int,
        mKey: ByteArray
    ): Int {
        val rKey = IntArray(100)
        val H = IntArray(4)
        val Z = IntArray(4)
        val tmp = IntArray(8)
        val GCTR_in = IntArray(4)
        val GCTR_out = IntArray(4)
        val GHASH_in = IntArray(4)
        val GHASH_out = IntArray(4)
        val M8 = Array(256) { IntArray(4) }
        var i = 0
        val seed = KISA_SEED_LIB()

        if (macLen > 16) return 1

        seed.SEED_KeySched(mKey, rKey)

        seed.SEED_Encrypt(H, H, rKey)

        makeM8(M8, H)

        if (nonceLen == 12) {
            Byte2Word(GCTR_in, nonce, 0, nonceLen)

            GCTR_in[3] = 1

            seed.SEED_Encrypt(Z, GCTR_in, rKey)
        } else {
            i = 0
            while (i < nonceLen) {
                ZERO128(tmp)

                if ((nonceLen - i) < 16) Byte2Word(tmp, nonce, i, nonceLen - i)
                else Byte2Word(tmp, nonce, i, BLOCK_SIZE_SEED)

                GHASH_8BIT(GCTR_in, tmp, M8, R8)
                i += BLOCK_SIZE_SEED
            }

            ZERO128(tmp)
            tmp[3] = (nonceLen shl 3)

            GHASH_8BIT(GCTR_in, tmp, M8, R8)

            seed.SEED_Encrypt(Z, GCTR_in, rKey)
        }

        i = 0
        while (i < ptLen) {
            ZERO128(tmp)

            INCREASE(GCTR_in)

            seed.SEED_Encrypt(GCTR_out, GCTR_in, rKey)

            if ((ptLen - i) < 16) {
                Byte2Word(tmp, pt, i, ptLen - i)
                XOR128(GCTR_out, GCTR_out, tmp)
                Word2Byte(ct, i, GCTR_out, ptLen - i)
            } else {
                Byte2Word(tmp, pt, i, BLOCK_SIZE_SEED)
                XOR128(GCTR_out, GCTR_out, tmp)
                Word2Byte(ct, i, GCTR_out, BLOCK_SIZE_SEED)
            }
            i += BLOCK_SIZE_SEED
        }

        i = 0
        while (i < aadLen) {
            ZERO128(GHASH_in)

            if ((aadLen - i) < 16) Byte2Word(GHASH_in, aad, i, aadLen - i)
            else Byte2Word(GHASH_in, aad, i, BLOCK_SIZE_SEED)

            GHASH_8BIT(GHASH_out, GHASH_in, M8, R8)
            i += BLOCK_SIZE_SEED
        }

        i = 0
        while (i < ptLen) {
            ZERO128(GHASH_in)

            if ((ptLen - i) < 16) Byte2Word(GHASH_in, ct, i, ptLen - i)
            else Byte2Word(GHASH_in, ct, i, BLOCK_SIZE_SEED)

            GHASH_8BIT(GHASH_out, GHASH_in, M8, R8)
            i += BLOCK_SIZE_SEED
        }

        ZERO128(GHASH_in)

        GHASH_in[1] = GHASH_in[1] xor (aadLen shl 3)
        GHASH_in[3] = GHASH_in[3] xor (ptLen shl 3)

        GHASH_8BIT(GHASH_out, GHASH_in, M8, R8)

        XOR128(GHASH_out, GHASH_out, Z)

        Word2Byte(ct, ptLen, GHASH_out, macLen)

        return ptLen + macLen
    }

    fun SEED_GCM_Decryption(
        pt: ByteArray,
        ct: ByteArray, ctLen: Int,
        macLen: Int,
        nonce: ByteArray, nonceLen: Int,
        aad: ByteArray, aadLen: Int,
        mKey: ByteArray
    ): Int {
        val rKey = IntArray(100)
        val H = IntArray(4)
        val Z = IntArray(4)
        val tmp = IntArray(8)
        val GCTR_in = IntArray(4)
        val GCTR_out = IntArray(4)
        val GHASH_in = IntArray(4)
        val GHASH_out = IntArray(4)
        val MAC = ByteArray(16)
        val M8 = Array(256) { IntArray(4) }
        var i = 0
        var j = 0
        val seed = KISA_SEED_LIB()

        if (macLen > 16) return 1

        seed.SEED_KeySched(mKey, rKey)

        seed.SEED_Encrypt(H, H, rKey)

        makeM8(M8, H)

        if (nonceLen == 12) {
            Byte2Word(GCTR_in, nonce, 0, nonceLen)

            GCTR_in[3] = 1

            seed.SEED_Encrypt(Z, GCTR_in, rKey)
        } else {
            i = 0
            while (i < nonceLen) {
                ZERO128(tmp)

                if ((nonceLen - i) < 16) Byte2Word(tmp, nonce, i, nonceLen - i)
                else Byte2Word(tmp, nonce, i, BLOCK_SIZE_SEED)

                GHASH_8BIT(GCTR_in, tmp, M8, R8)
                i += BLOCK_SIZE_SEED
            }

            ZERO128(tmp)
            tmp[3] = (nonceLen shl 3)

            GHASH_8BIT(GCTR_in, tmp, M8, R8)

            seed.SEED_Encrypt(Z, GCTR_in, rKey)
        }

        i = 0
        while (i < ctLen - macLen) {
            ZERO128(tmp)

            INCREASE(GCTR_in)

            seed.SEED_Encrypt(GCTR_out, GCTR_in, rKey)

            if ((ctLen - macLen - i) < 16) {
                Byte2Word(tmp, ct, i, ctLen - macLen - i)
                XOR128(GCTR_out, GCTR_out, tmp)
                Word2Byte(pt, i, GCTR_out, ctLen - macLen - i)
            } else {
                Byte2Word(tmp, ct, i, BLOCK_SIZE_SEED)
                XOR128(GCTR_out, GCTR_out, tmp)
                Word2Byte(pt, i, GCTR_out, BLOCK_SIZE_SEED)
            }
            i += BLOCK_SIZE_SEED
        }

        i = 0
        while (i < aadLen) {
            ZERO128(GHASH_in)

            if ((aadLen - i) < 16) Byte2Word(GHASH_in, aad, i, aadLen - i)
            else Byte2Word(GHASH_in, aad, i, BLOCK_SIZE_SEED)

            GHASH_8BIT(GHASH_out, GHASH_in, M8, R8)
            i += BLOCK_SIZE_SEED
        }

        i = 0
        while (i < ctLen - macLen) {
            ZERO128(GHASH_in)

            if ((ctLen - macLen - i) < 16) Byte2Word(GHASH_in, ct, i, ctLen - macLen - i)
            else Byte2Word(GHASH_in, ct, i, BLOCK_SIZE_SEED)

            GHASH_8BIT(GHASH_out, GHASH_in, M8, R8)
            i += BLOCK_SIZE_SEED
        }

        ZERO128(GHASH_in)

        GHASH_in[1] = aadLen shl 3
        GHASH_in[3] = (ctLen - macLen) shl 3

        GHASH_8BIT(GHASH_out, GHASH_in, M8, R8)

        XOR128(GHASH_out, GHASH_out, Z)

        Word2Byte(MAC, 0, GHASH_out, macLen)

        i = 0
        while (i < macLen) {
            if (ct[ctLen - macLen + i] != MAC[i]) {
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

        private fun SHIFTR1(R: IntArray) {
            R[3] = ((R[3] shr 1) and 0x7FFFFFFF) xor ((R[2] shl 31) and -0x80000000)
            R[2] = ((R[2] shr 1) and 0x7FFFFFFF) xor ((R[1] shl 31) and -0x80000000)
            R[1] = ((R[1] shr 1) and 0x7FFFFFFF) xor ((R[0] shl 31) and -0x80000000)
            R[0] = ((R[0] shr 1) and 0x7FFFFFFF)
        }

        private fun SHIFTR8(R: IntArray) {
            R[3] = ((R[3] shr 8) and 0x00FFFFFF) xor ((R[2] shl 24) and -0x1000000)
            R[2] = ((R[2] shr 8) and 0x00FFFFFF) xor ((R[1] shl 24) and -0x1000000)
            R[1] = ((R[1] shr 8) and 0x00FFFFFF) xor ((R[0] shl 24) and -0x1000000)
            R[0] = ((R[0] shr 8) and 0x00FFFFFF)
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

        private val R8 = intArrayOf(
            0x00000000, 0x01c20000, 0x03840000, 0x02460000, 0x07080000, 0x06ca0000, 0x048c0000, 0x054e0000,
            0x0e100000, 0x0fd20000, 0x0d940000, 0x0c560000, 0x09180000, 0x08da0000, 0x0a9c0000, 0x0b5e0000,
            0x1c200000, 0x1de20000, 0x1fa40000, 0x1e660000, 0x1b280000, 0x1aea0000, 0x18ac0000, 0x196e0000,
            0x12300000, 0x13f20000, 0x11b40000, 0x10760000, 0x15380000, 0x14fa0000, 0x16bc0000, 0x177e0000,
            0x38400000, 0x39820000, 0x3bc40000, 0x3a060000, 0x3f480000, 0x3e8a0000, 0x3ccc0000, 0x3d0e0000,
            0x36500000, 0x37920000, 0x35d40000, 0x34160000, 0x31580000, 0x309a0000, 0x32dc0000, 0x331e0000,
            0x24600000, 0x25a20000, 0x27e40000, 0x26260000, 0x23680000, 0x22aa0000, 0x20ec0000, 0x212e0000,
            0x2a700000, 0x2bb20000, 0x29f40000, 0x28360000, 0x2d780000, 0x2cba0000, 0x2efc0000, 0x2f3e0000,
            0x70800000, 0x71420000, 0x73040000, 0x72c60000, 0x77880000, 0x764a0000, 0x740c0000, 0x75ce0000,
            0x7e900000, 0x7f520000, 0x7d140000, 0x7cd60000, 0x79980000, 0x785a0000, 0x7a1c0000, 0x7bde0000,
            0x6ca00000, 0x6d620000, 0x6f240000, 0x6ee60000, 0x6ba80000, 0x6a6a0000, 0x682c0000, 0x69ee0000,
            0x62b00000, 0x63720000, 0x61340000, 0x60f60000, 0x65b80000, 0x647a0000, 0x663c0000, 0x67fe0000,
            0x48c00000, 0x49020000, 0x4b440000, 0x4a860000, 0x4fc80000, 0x4e0a0000, 0x4c4c0000, 0x4d8e0000,
            0x46d00000, 0x47120000, 0x45540000, 0x44960000, 0x41d80000, 0x401a0000, 0x425c0000, 0x439e0000,
            0x54e00000, 0x55220000, 0x57640000, 0x56a60000, 0x53e80000, 0x522a0000, 0x506c0000, 0x51ae0000,
            0x5af00000, 0x5b320000, 0x59740000, 0x58b60000, 0x5df80000, 0x5c3a0000, 0x5e7c0000, 0x5fbe0000,
            -0x1f000000, -0x1f3e0000, -0x1d7c0000, -0x1cba0000, -0x19f80000, -0x18360000, -0x1a740000, -0x1bb20000,
            -0x10f00000, -0x112e0000, -0x136c0000, -0x12aa0000, -0x17e80000, -0x16260000, -0x14640000, -0x15a20000,
            -0x2e00000, -0x31e0000, -0x15c0000, -0x9a0000, -0x5d80000, -0x4160000, -0x6540000, -0x7920000,
            -0xcd00000, -0xd0e0000, -0xf4c0000, -0xe8a0000, -0xbc80000, -0xa060000, -0x8440000, -0x9820000,
            -0x26c00000, -0x277e0000, -0x253c0000, -0x24fa0000, -0x21b80000, -0x20760000, -0x22340000, -0x23f20000,
            -0x28b00000, -0x296e0000, -0x2b2c0000, -0x2aea0000, -0x2fa80000, -0x2e660000, -0x2c240000, -0x2de20000,
            -0x3aa00000, -0x3b5e0000, -0x391c0000, -0x38da0000, -0x3d980000, -0x3c560000, -0x3e140000, -0x3fd20000,
            -0x34900000, -0x354e0000, -0x370c0000, -0x36ca0000, -0x33880000, -0x32460000, -0x30040000, -0x31c20000,
            -0x6e800000, -0x6fbe0000, -0x6dfc0000, -0x6c3a0000, -0x69780000, -0x68b60000, -0x6af40000, -0x6b320000,
            -0x60700000, -0x61ae0000, -0x63ec0000, -0x622a0000, -0x67680000, -0x66a60000, -0x64e40000, -0x65220000,
            -0x72600000, -0x739e0000, -0x71dc0000, -0x701a0000, -0x75580000, -0x74960000, -0x76d40000, -0x77120000,
            -0x7c500000, -0x7d8e0000, -0x7fcc0000, -0x7e0a0000, -0x7b480000, -0x7a860000, -0x78c40000, -0x79020000,
            -0x56400000, -0x57fe0000, -0x55bc0000, -0x547a0000, -0x51380000, -0x50f60000, -0x52b40000, -0x53720000,
            -0x58300000, -0x59ee0000, -0x5bac0000, -0x5a6a0000, -0x5f280000, -0x5ee60000, -0x5ca40000, -0x5d620000,
            -0x4a200000, -0x4bde0000, -0x499c0000, -0x485a0000, -0x4d180000, -0x4cd60000, -0x4e940000, -0x4f520000,
            -0x44100000, -0x45ce0000, -0x478c0000, -0x464a0000, -0x43080000, -0x42c60000, -0x40840000, -0x41420000
        )

        private fun makeM8(M: Array<IntArray>, H: IntArray) {
            var i = 64
            var j = 0
            val temp = IntArray(4)

            M[128][0] = H[0]
            M[128][1] = H[1]
            M[128][2] = H[2]
            M[128][3] = H[3]

            while (i > 0) {
                temp[0] = M[i shl 1][0]
                temp[1] = M[i shl 1][1]
                temp[2] = M[i shl 1][2]
                temp[3] = M[i shl 1][3]

                if ((temp[3] and 0x01) == 1) {
                    SHIFTR1(temp)
                    temp[0] = temp[0] xor -0x1f000000
                } else {
                    SHIFTR1(temp)
                }

                M[i][0] = temp[0]
                M[i][1] = temp[1]
                M[i][2] = temp[2]
                M[i][3] = temp[3]

                i = i shr 1
            }

            i = 2

            while (i < 256) {
                j = 1
                while (j < i) {
                    M[i + j][0] = M[i][0] xor M[j][0]
                    M[i + j][1] = M[i][1] xor M[j][1]
                    M[i + j][2] = M[i][2] xor M[j][2]
                    M[i + j][3] = M[i][3] xor M[j][3]
                    j++
                }

                i = i shl 1
            }

            M[0][0] = 0
            M[0][1] = 0
            M[0][2] = 0
            M[0][3] = 0
        }

        private fun GHASH_8BIT(out: IntArray, `in`: IntArray, M: Array<IntArray>, R: IntArray) {
            val W = IntArray(4)
            val Z = IntArray(4)
            var temp = 0
            var i = 0

            XOR128(Z, out, `in`)

            i = 0
            while (i < 15) {
                temp = ((Z[3 - (i shr 2)] shr ((i and 3) shl 3)) and 0x0FF)

                W[0] = W[0] xor M[temp][0]
                W[1] = W[1] xor M[temp][1]
                W[2] = W[2] xor M[temp][2]
                W[3] = W[3] xor M[temp][3]

                temp = W[3] and 0x0FF

                SHIFTR8(W)
                W[0] = W[0] xor R[temp]
                i++
            }

            temp = (Z[0] shr 24) and 0xFF

            out[0] = W[0] xor M[temp][0]
            out[1] = W[1] xor M[temp][1]
            out[2] = W[2] xor M[temp][2]
            out[3] = W[3] xor M[temp][3]
        }
    }
}