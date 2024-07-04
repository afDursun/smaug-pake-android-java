package com.sak.smaugpake;

import com.sak.smaugpake.Model.Encapsulation;
import com.sak.smaugpake.Model.Key;
import com.sak.smaugpake.Model.SecurityLevel;

public class SmaugKEM {
        public static boolean IS_RANDOM;
        public static int LOG_LWE_N;
        public static int SMAUG_MODE;
        public static int SHAKE256_RATE;

        public static int LWE_N;

        public static int MODULE_RANK;
        public static int DIMENSION;
        public static int LOG_Q;
        public static int LOG_P2;
        public static int HS;
        public static int HR;
        public static int RAND_BITS;
        public static int SEED_LEN;
        public static int NOISE_D1;
        public static int NOISE_D2;
        public static int NOISE_D3;
        public static int NOISE_D4;

        public static short DEC_ADD;
        public static int LOG_P;
        public static int LOG_T;

        public static int RD_ADD;
        public static int RD_AND;

        public static int RD_ADD2;
        public static int RD_AND2;

        public static int DELTA_BYTES;
        public static int T_BYTES;

        public static int _16_LOG_Q;
        public static int _16_LOG_P;
        public static int _16_LOG_T;
        public static int _16_LOG_P2;

        public static int SHARED_SECRET_BYTES;
        public static int CRYPTO_BYTES;

        public static int ID_BYTES;
        public static int PW_BYTES;

        public static int CTPOLY1_BYTES;
        public static int CTPOLY2_BYTES;

        public static int SKPOLYVEC_BYTES;
        public static int CTPOLYVEC_BYTES;

        public static int PKE_SECRETKEY_BYTES;
        public static int KEM_SECRETKEY_BYTES;

        public static int CIPHERTEXT_BYTES;
        public static int PKSEED_BYTES;
        public static int PKPOLY_BYTES;
        public static int PKPOLYVEC_BYTES;
        public static int PKPOLYMAT_BYTES;

        public static int R11_DATA_OFFSET;
        public static int R11_BYTE_OFFSET;
        public static int R10_DATA_OFFSET;
        public static int R10_BYTE_OFFSET;

        public static int SHA3_256_HashSize;

        public static int PUBLICKEY_BYTES;
        public static int PAKE_A0_SEND;
        public static int  AUTH_SIZE ;


        public SmaugKEM(SecurityLevel s) {
                configureSecurityLevel(s);
        }

        private void configureSecurityLevel(SecurityLevel s) {
                MODULE_RANK = s.getModuleRank();
                IS_RANDOM = true;
                LOG_LWE_N = 8;
                SHAKE256_RATE = 136;
                LWE_N = 1 << LOG_LWE_N;
                DIMENSION = MODULE_RANK * LWE_N;
                DEC_ADD = 0x4000;

                switch (MODULE_RANK) {
                        case 2:
                                SMAUG_MODE = 1;
                                LOG_Q = 10;
                                LOG_P = 8;
                                LOG_P2 = 5;
                                LOG_T = 1;
                                NOISE_D1 = 1;
                                HS = 140;
                                HR = 132;
                                RAND_BITS = 10;
                                SEED_LEN = (RAND_BITS * LWE_N / 64);
                                RD_ADD = 0x80;
                                RD_AND = 0xff00;
                                RD_ADD2 = 0x80;
                                RD_AND2 = 0xff00;
                                DELTA_BYTES = LWE_N / 8;
                                T_BYTES = LWE_N / 8;
                                break;

                        case 3:
                                SMAUG_MODE = 3;
                                LOG_Q = 11;
                                LOG_P = 8;
                                LOG_P2 = 8;
                                LOG_T = 1;
                                NOISE_D1 = 0;
                                NOISE_D2 = 1;
                                NOISE_D3 = 0;
                                NOISE_D4 = 0;
                                HS = 198;
                                HR = 151;
                                RAND_BITS = 11;
                                SEED_LEN = (RAND_BITS * LWE_N / 64);
                                RD_ADD = 0x80;
                                RD_AND = 0xff00;
                                RD_ADD2 = 0x80;
                                RD_AND2 = 0xff00;
                                DELTA_BYTES = LWE_N / 8;
                                T_BYTES = LWE_N / 8;
                                break;

                        case 5:
                                SMAUG_MODE = 5;
                                LOG_Q = 11;
                                LOG_P = 8;
                                LOG_P2 = 6;
                                LOG_T = 1;
                                NOISE_D1 = 1;
                                NOISE_D2 = 0;
                                NOISE_D3 = 0;
                                NOISE_D4 = 0;
                                HS = 176;
                                HR = 160;
                                RAND_BITS = 10;
                                SEED_LEN = (RAND_BITS * LWE_N / 64);
                                RD_ADD = 0x80;
                                RD_AND = 0xff00;
                                RD_ADD2 = 0x80;
                                RD_AND2 = 0xff00;
                                DELTA_BYTES = LWE_N / 8;
                                T_BYTES = LWE_N / 8;
                                break;
                }

                _16_LOG_Q = (16 - LOG_Q);
                _16_LOG_P = (16 - LOG_P);
                _16_LOG_T = (16 - LOG_T);
                _16_LOG_P2 = (16 - LOG_P2);

                SHARED_SECRET_BYTES = 32;
                CRYPTO_BYTES = SHARED_SECRET_BYTES;
                ID_BYTES = 32;
                PW_BYTES = 32;
                CTPOLY1_BYTES = LWE_N;
                CTPOLY2_BYTES = LOG_P2 * LWE_N >> 3;
                SKPOLYVEC_BYTES = HS;
                CTPOLYVEC_BYTES = CTPOLY1_BYTES * MODULE_RANK;
                PKE_SECRETKEY_BYTES = SKPOLYVEC_BYTES + 2 * MODULE_RANK;
                KEM_SECRETKEY_BYTES = PKE_SECRETKEY_BYTES + T_BYTES;
                CIPHERTEXT_BYTES = CTPOLYVEC_BYTES + CTPOLY2_BYTES;
                PKSEED_BYTES = 32;
                PKPOLY_BYTES = LOG_Q * LWE_N / 8;
                PKPOLYVEC_BYTES = PKPOLY_BYTES * MODULE_RANK;
                PKPOLYMAT_BYTES = PKPOLYVEC_BYTES * MODULE_RANK;
                R11_DATA_OFFSET = LOG_Q;
                R11_BYTE_OFFSET = 8; // (bit size of uint8_t)
                R10_DATA_OFFSET = LOG_Q / 2;
                R10_BYTE_OFFSET = 8 / 2; // (bit size of uint8_t) / 2
                SHA3_256_HashSize = 32;
                PUBLICKEY_BYTES = PKSEED_BYTES + PKPOLYVEC_BYTES;
                PAKE_A0_SEND = PUBLICKEY_BYTES;
                AUTH_SIZE = ID_BYTES + ID_BYTES + ID_BYTES + PW_BYTES + PAKE_A0_SEND + CIPHERTEXT_BYTES + CRYPTO_BYTES;
        }
        public Key keygen() {
                return KEM.crypto_kem_keypair();
        }

        public Encapsulation encapsulation(byte[] pk) {
                return KEM.crypto_kem_encap(pk);
        }
        public byte[] decapsulation(byte[] sk, byte[] pk, byte[] ct){
                return KEM.crypto_kem_decap(sk,pk,ct);
        }
        public void random_generate(boolean isRandom){
                IS_RANDOM = isRandom;
        }
}