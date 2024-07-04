package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.CRYPTO_BYTES;
import static com.sak.smaugpake.SmaugKEM.DIMENSION;
import static com.sak.smaugpake.SmaugKEM.HS;
import static com.sak.smaugpake.SmaugKEM.LWE_N;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;
import static com.sak.smaugpake.SmaugKEM.NOISE_D1;
import static com.sak.smaugpake.SmaugKEM.NOISE_D2;
import static com.sak.smaugpake.SmaugKEM.NOISE_D3;
import static com.sak.smaugpake.SmaugKEM.NOISE_D4;
import static com.sak.smaugpake.SmaugKEM.PKPOLYMAT_BYTES;
import static com.sak.smaugpake.SmaugKEM.RAND_BITS;
import static com.sak.smaugpake.SmaugKEM.SEED_LEN;
import static com.sak.smaugpake.SmaugKEM._16_LOG_Q;

import android.util.Log;

import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.Shake128;

import java.util.Arrays;

import com.sak.smaugpake.Model.PublicKey;
import com.sak.smaugpake.Model.SecretKey;

public class KeyOperation {


    public static void genSxVec(SecretKey sk, byte[] seed) {
        byte[] cnt_arr = new byte[MODULE_RANK];
        byte[] res = new byte[DIMENSION];

        for (int i = 0; i < MODULE_RANK; ++i) {
            cnt_arr[i] = 0;
        }
        sk.setCnt_arr(cnt_arr);

        res = Hwt.hwt(sk.getCnt_arr(), seed, CRYPTO_BYTES, HS);

        for (int i = 0; i < MODULE_RANK; ++i) {
            sk.getS()[i] = new byte[sk.getCnt_arr()[i]];
            sk.getNeg_start()[i] = Poly.convToIdx(sk.getS()[i], sk.getCnt_arr()[i], Arrays.copyOfRange(res, i * LWE_N, (i + 1) * LWE_N), LWE_N);
        }
    }
    public static void genPubKey(PublicKey pk, SecretKey sk, byte[] seed) {
        KeccakSponge xof = new Shake128();
        xof.getAbsorbStream().write(pk.getSeed());
        xof.getSqueezeStream().read(pk.getSeed());

        pk.setA(genAx(pk.getSeed()));

        pk.setB(genBx(pk.getA(), sk.getS(), sk.getNeg_start(), sk.getCnt_arr(),seed));


    }

    private static short[][] genBx(short[][][] a, byte[][] s, byte[] neg_start, byte[] cnt_arr, byte[] seed) {
        short[][] b;
        b = addGaussianErrorVec(seed);
        Poly.matrix_vec_mult_sub(b,  a , s , cnt_arr , neg_start ,  0);
        return b;
    }
    public static short[][] addGaussianErrorVec(byte[] seed) {
        byte[] seedTmp = new byte[CRYPTO_BYTES + 8];
        short[][] b = new short[MODULE_RANK][LWE_N];

        for(int i = 0 ; i < CRYPTO_BYTES ; i++)
            seedTmp[i] = seed[i];

        System.arraycopy(seed, 0, seedTmp, 0, CRYPTO_BYTES);

        for (int i = 0; i < MODULE_RANK; ++i) {
            int nonce = MODULE_RANK * i;
            int size = Utils.longToBytes(nonce).length;
            for(int j = 0 ; j < size; j++)
                seedTmp[j + CRYPTO_BYTES] = Utils.longToBytes(nonce)[size - j - 1];

            b[i] = addGaussianError(LWE_N, seedTmp);

        }

        return b;
    }
    private static short[] addGaussianError(int length, byte[] seed) {
        short[] op = new short[LWE_N];
        if (length > LWE_N) {
            Log.d("AFD-AFD", "lenght > LWE_N");
        }
        long[] seed_temp;
        byte[] seed_temp_byte = new byte[SEED_LEN * 8];

        KeccakSponge xof = new Shake128();
        xof.getAbsorbStream().write(seed);
        xof.getSqueezeStream().read(seed_temp_byte);

        seed_temp = Utils.convertToLongArray(seed_temp_byte);

        int j = 0;

        for (int i = 0; i < length; i += 64) {
            long[] x = Arrays.copyOfRange(seed_temp, j, j+RAND_BITS);

            if (NOISE_D1 == 1) {
                long[] s = new long[2];
                s[0] = (x[0] & x[1] & x[2] & x[3] & x[4] & x[5] & x[7] & ~x[8]) |
                        (x[0] & x[3] & x[4] & x[5] & x[6] & x[8]) |
                        (x[1] & x[3] & x[4] & x[5] & x[6] & x[8]) |
                        (x[2] & x[3] & x[4] & x[5] & x[6] & x[8]) |
                        (~x[2] & ~x[3] & ~x[6] & x[8]) | (~x[1] & ~x[3] & ~x[6] & x[8]) |
                        (x[6] & x[7] & ~x[8]) | (~x[5] & ~x[6] & x[8]) |
                        (~x[4] & ~x[6] & x[8]) | (~x[7] & x[8]);
                s[1] = (x[1] & x[2] & x[4] & x[5] & x[7] & x[8]) |
                        (x[3] & x[4] & x[5] & x[7] & x[8]) | (x[6] & x[7] & x[8]);
                for (int k = 0; k < 64; ++k) {
                    op[i + k] = (short) (((s[0] >> k) & 0x01) | (((s[1] >> k) & 0x01) << 1));
                    long sign = (x[9] >> k) & 0x01;
                    op[i + k] = (short) ((((-sign) ^ op[i + k]) + sign) << _16_LOG_Q);
                }
            }
            if (NOISE_D2 == 1) {
                long[] s = new long[3];
                s[0] = (x[0] & x[1] & x[2] & x[3] & x[5] & x[7] & x[8]) |
                        (x[1] & x[2] & x[3] & x[5] & ~x[6] & x[7] & x[9]) |
                        (~x[1] & ~x[2] & ~x[3] & x[6] & x[7] & x[8]) |
                        (~x[1] & ~x[2] & ~x[3] & ~x[5] & ~x[8] & x[9]) |
                        (~x[0] & ~x[2] & ~x[3] & ~x[5] & ~x[8] & x[9]) |
                        (x[4] & x[5] & ~x[6] & x[7] & x[9]) |
                        (x[3] & x[4] & x[8] & ~x[9]) | (~x[5] & x[6] & x[7] & x[8]) |
                        (~x[4] & x[6] & x[7] & x[8]) | (~x[4] & ~x[5] & ~x[8] & x[9]) |
                        (x[5] & x[8] & ~x[9]) | (x[6] & x[8] & ~x[9]) |
                        (x[7] & x[8] & ~x[9]) | (~x[7] & ~x[8] & x[9]) |
                        (~x[6] & ~x[8] & x[9]);
                s[1] = (x[0] & x[1] & x[4] & ~x[5] & x[6] & x[7] & x[9]) |
                        (x[2] & x[4] & ~x[5] & x[6] & x[7] & x[9]) |
                        (x[3] & x[4] & ~x[5] & x[6] & x[7] & x[9]) |
                        (x[5] & x[6] & x[7] & ~x[8] & x[9]) |
                        (~x[1] & ~x[2] & ~x[3] & x[8] & x[9]) | (~x[7] & x[8] & x[9]) |
                        (~x[6] & x[8] & x[9]) | (~x[5] & x[8] & x[9]) |
                        (~x[4] & x[8] & x[9]);
                s[2] = (x[1] & x[4] & x[5] & x[6] & x[7] & x[8] & x[9]) |
                        (x[2] & x[4] & x[5] & x[6] & x[7] & x[8] & x[9]) |
                        (x[3] & x[4] & x[5] & x[6] & x[7] & x[8] & x[9]);
                for (int k = 0; k < 64; ++k) {
                    op[i + k] = (short) (((s[0] >> k) & 0x01) | (((s[1] >> k) & 0x01) << 1) |
                                                (((s[2] >> k) & 0x01) << 2));
                    long sign = (x[10] >> k) & 0x01;
                    op[i + k] = (short) ((((-sign) ^ op[i + k]) + sign) << _16_LOG_Q);
                }
            }
            if (NOISE_D3 == 1) {
                long[] s = new long[3];
                s[0] = (x[0] & ~x[2] & ~x[3] & x[4] & x[6] & x[7] & x[9]) |
                        (x[1] & ~x[2] & ~x[3] & x[4] & x[6] & x[7] & x[9]) |
                        (~x[0] & ~x[1] & ~x[3] & x[5] & x[6] & x[7] & x[9]) |
                        (x[1] & x[2] & x[3] & x[5] & x[6] & x[7] & x[9]) |
                        (~x[1] & ~x[2] & ~x[3] & ~x[4] & ~x[7] & x[8] & x[9]) |
                        (x[2] & x[4] & ~x[5] & x[6] & x[8] & x[9]) |
                        (~x[3] & ~x[4] & ~x[7] & ~x[8] & ~x[9] & x[10]) |
                        (x[3] & x[4] & x[7] & x[8] & ~x[10]) |
                        (x[3] & x[4] & ~x[5] & x[6] & x[9]) |
                        (~x[4] & x[5] & x[6] & x[7] & x[9]) |
                        (~x[6] & ~x[7] & ~x[8] & ~x[9] & x[10]) |
                        (~x[5] & ~x[7] & ~x[8] & ~x[9] & x[10]) |
                        (x[5] & x[7] & x[8] & ~x[10]) | (x[6] & x[7] & x[8] & ~x[10]) |
                        (x[5] & x[6] & ~x[8] & x[9]) | (~x[6] & ~x[7] & x[8] & x[9]) |
                        (~x[5] & ~x[7] & x[8] & x[9]) | (x[7] & ~x[8] & x[9]) |
                        (x[9] & ~x[10]);
                s[1] = (x[0] & x[2] & x[4] & x[5] & x[6] & x[7] & x[10]) |
                        (x[1] & x[2] & x[4] & x[5] & x[6] & x[7] & x[10]) |
                        (~x[1] & ~x[2] & ~x[3] & ~x[4] & ~x[7] & x[9] & x[10]) |
                        (x[3] & x[4] & x[5] & x[6] & x[7] & x[10]) |
                        (x[3] & x[5] & x[6] & ~x[8] & x[10]) |
                        (x[4] & x[5] & x[6] & ~x[8] & x[10]) |
                        (~x[6] & ~x[7] & x[9] & x[10]) | (~x[5] & ~x[7] & x[9] & x[10]) |
                        (x[7] & ~x[8] & x[10]) | (x[8] & ~x[9] & x[10]) |
                        (~x[8] & x[9] & x[10]);
                s[2] = (x[1] & x[5] & x[6] & x[8] & x[9] & x[10]) |
                        (x[2] & x[5] & x[6] & x[8] & x[9] & x[10]) |
                        (x[3] & x[5] & x[6] & x[8] & x[9] & x[10]) |
                        (x[4] & x[5] & x[6] & x[8] & x[9] & x[10]) |
                        (x[7] & x[8] & x[9] & x[10]);
                for (int k = 0; k < 64; ++k) {
                    op[i + k] = (short) (((s[0] >> k) & 0x01) | (((s[1] >> k) & 0x01) << 1) |
                                                (((s[2] >> k) & 0x01) << 2));
                    long sign = (x[11] >> k) & 0x01;
                    op[i + k] = (short) ((((-sign) ^ op[i + k]) + sign) << _16_LOG_Q);
                }
            }

            if (NOISE_D4 == 1) {
                long[] s = new long[4];
                s[0] = (x[0] & x[1] & ~x[2] & x[3] & x[4] & ~x[6] & x[7] & ~x[9]) |
                        (x[2] & x[3] & x[4] & ~x[5] & ~x[6] & x[7] & ~x[9]) |
                        (~x[2] & ~x[3] & ~x[4] & ~x[5] & ~x[7] & x[8]) |
                        (~x[1] & ~x[3] & ~x[4] & ~x[5] & ~x[7] & x[8]) |
                        (~x[0] & ~x[3] & ~x[4] & ~x[5] & ~x[7] & x[8]) |
                        (x[0] & ~x[2] & x[3] & x[5] & ~x[6] & x[8]) |
                        (x[1] & ~x[2] & x[3] & x[5] & ~x[6] & x[8]) |
                        (x[2] & x[3] & ~x[4] & x[5] & ~x[6] & x[8]) |
                        (x[0] & x[1] & x[4] & x[5] & x[7] & x[9]) |
                        (x[2] & ~x[3] & x[4] & x[6] & x[7] & x[9]) |
                        (~x[2] & x[3] & x[4] & x[6] & x[7] & x[9]) |
                        (~x[3] & x[5] & ~x[6] & x[7] & ~x[9]) |
                        (x[0] & x[2] & x[5] & x[7] & ~x[8]) |
                        (x[1] & x[2] & x[5] & x[7] & ~x[8]) |
                        (x[4] & x[5] & ~x[6] & x[7] & x[9]) |
                        (~x[4] & ~x[5] & x[6] & x[7] & x[9]) |
                        (~x[2] & ~x[5] & x[6] & x[7] & x[9]) |
                        (x[3] & x[5] & x[7] & ~x[8]) | (~x[5] & ~x[6] & x[8] & ~x[9]) |
                        (~x[2] & ~x[6] & x[8] & ~x[9]) | (x[6] & x[7] & ~x[8]) |
                        (~x[7] & x[8] & ~x[9]) | (~x[6] & ~x[7] & x[8]);
                s[1] = (x[2] & x[3] & x[4] & x[5] & x[7] & x[8] & ~x[9]) |
                        (x[2] & x[3] & x[4] & ~x[5] & x[6] & x[7] & x[9]) |
                        (~x[2] & ~x[3] & ~x[4] & ~x[5] & ~x[7] & x[9]) |
                        (~x[1] & ~x[3] & ~x[4] & ~x[5] & ~x[7] & x[9]) |
                        (~x[0] & ~x[3] & ~x[4] & ~x[5] & ~x[7] & x[9]) |
                        (~x[4] & x[5] & x[6] & x[7] & x[9]) |
                        (~x[3] & x[5] & x[6] & x[7] & x[9]) |
                        (~x[2] & x[5] & x[6] & x[7] & x[9]) |
                        (x[6] & x[7] & x[8] & ~x[9]) | (~x[6] & ~x[7] & x[9]) |
                        (~x[8] & x[9]);
                s[2] = (x[0] & x[1] & x[2] & ~x[3] & x[6] & x[8] & x[9]) |
                        (x[3] & x[6] & ~x[7] & x[8] & x[9]) |
                        (x[4] & ~x[5] & x[6] & x[8] & x[9]) |
                        (~x[3] & x[5] & x[6] & x[8] & x[9]) |
                        (~x[6] & x[7] & x[8] & x[9]) | (~x[4] & x[7] & x[8] & x[9]) |
                        (~x[2] & x[7] & x[8] & x[9]);
                s[3] = (x[2] & x[3] & x[4] & x[5] & x[6] & x[7] & x[8] & x[9]);
                for (int k = 0; k < 64; ++k) {
                    op[i + k] = (short) (((s[0] >> k) & 0x01) | (((s[1] >> k) & 0x01) << 1) |
                                                (((s[2] >> k) & 0x01) << 2) |
                                                (((s[3] >> k) & 0x01) << 3));
                    long sign = (x[10] >> k) & 0x01;
                    op[i + k] = (short) ((((-sign) ^ op[i + k]) + sign) << _16_LOG_Q);
                }
            }
            j += RAND_BITS;
        }

        return op;
    }
    public static short[][][] genAx(byte[] seed) {
        byte[] buf = new byte[PKPOLYMAT_BYTES];
        short[][][] A = new short[MODULE_RANK][MODULE_RANK][LWE_N];

        KeccakSponge xof = new Shake128();
        xof.getAbsorbStream().write(seed);
        xof.getSqueezeStream().read(buf);

        A = Pack.bytesToRqMat(buf);

        for (int i = 0; i < MODULE_RANK; ++i) {
            for (int j = 0; j < MODULE_RANK; ++j) {
                for (int k = 0; k < LWE_N; ++k) {
                    A[i][j][k] <<= _16_LOG_Q;
                }
            }
        }

        return A;
    }

}
