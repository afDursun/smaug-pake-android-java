package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.CIPHERTEXT_BYTES;
import static com.sak.smaugpake.SmaugKEM.CTPOLY1_BYTES;
import static com.sak.smaugpake.SmaugKEM.CTPOLYVEC_BYTES;
import static com.sak.smaugpake.SmaugKEM.LOG_P2;
import static com.sak.smaugpake.SmaugKEM.LOG_Q;
import static com.sak.smaugpake.SmaugKEM.LWE_N;
import static com.sak.smaugpake.SmaugKEM.MODULE_RANK;
import static com.sak.smaugpake.SmaugKEM.PKPOLYVEC_BYTES;
import static com.sak.smaugpake.SmaugKEM.PKPOLY_BYTES;
import static com.sak.smaugpake.SmaugKEM.PUBLICKEY_BYTES;
import static com.sak.smaugpake.SmaugKEM.R10_BYTE_OFFSET;
import static com.sak.smaugpake.SmaugKEM.R10_DATA_OFFSET;
import static com.sak.smaugpake.SmaugKEM.R11_BYTE_OFFSET;
import static com.sak.smaugpake.SmaugKEM.R11_DATA_OFFSET;

import java.util.ArrayList;
import java.util.Arrays;

public class Pack {
    public static short[][][] bytesToRqMat(byte[] bytes) {
        short[][][] data = new short[MODULE_RANK][MODULE_RANK][LWE_N];
        for (int i = 0 ; i < MODULE_RANK ; i++){
           data[i] = bytes_to_Rq_vec(Arrays.copyOfRange(bytes, i*PKPOLYVEC_BYTES , (i+1)*PKPOLYVEC_BYTES));

        }
        return data;
    }

    public static byte[] Sx_vec_to_bytes(byte[][] data, byte[] data_len_arr) {
        ArrayList<byte[]> byteList =  new ArrayList<>();
        int idx = 0;
        for (int i = 0; i < MODULE_RANK; ++i) {
            byteList.add(Sx_to_bytes(data[i], data_len_arr[i]));
            idx += data_len_arr[i];
        }
        return Utils.concatenateArrayList(byteList);
    }
    private static byte[] Sx_to_bytes(byte[] data, byte data_len) {
        return Verify.cmov(data, data_len, (byte) 1);
    }

    public static byte[]  Rq_vec_to_bytes(short[][] data) {
        byte[] output2 = new byte[PUBLICKEY_BYTES];
        ArrayList<byte[]> byteList =  new ArrayList<>();

        for (int i = 0; i < MODULE_RANK; ++i)
            byteList.add(Rq_to_bytes(data[i], LWE_N));

        return Utils.concatenateArrayList(byteList);
    }

    private static byte[] Rq_to_bytes(short[] data, int dlen) {
        byte[] bytes = new byte[PKPOLY_BYTES];

        int b_idx = 0, d_idx = 0;

        if (LOG_Q == 10) {
            for (int i = 0; i < dlen / 4; i++) {
                b_idx = R10_DATA_OFFSET * i;
                d_idx = R10_BYTE_OFFSET * i;
                bytes[b_idx] = (byte) (data[d_idx] & 0xff);
                bytes[b_idx + 1] = (byte) (data[d_idx + 1] & 0xff);
                bytes[b_idx + 2] = (byte) (data[d_idx + 2] & 0xff);
                bytes[b_idx + 3] = (byte) (data[d_idx + 3] & 0xff);
                bytes[b_idx + 4] = (byte) (((data[d_idx] >> 8) & 0x03) | ((data[d_idx + 1] >> 6) & 0x0c) |
                        ((data[d_idx + 2] >> 4) & 0x30) | ((data[d_idx + 3] >> 2) & 0xc0));
            }
        }

        if (LOG_Q == 11) {
            for (int i = 0; i < dlen / 8; ++i) {
                b_idx = R11_DATA_OFFSET * i;
                d_idx = R11_BYTE_OFFSET * i;
                bytes[b_idx] = (byte) (data[d_idx] & 0xff);
                bytes[b_idx + 1] = (byte) (((data[d_idx] >> 3) & 0xe0) | (data[d_idx + 1] & 0x1f));
                bytes[b_idx + 2] = (byte) (((data[d_idx + 1] >> 3) & 0xfc) | (data[d_idx + 2] & 0x03));
                bytes[b_idx + 3] = (byte) ((data[d_idx + 2] >> 2) & 0xff);
                bytes[b_idx + 4] = (byte) (((data[d_idx + 2] >> 3) & 0x80) | (data[d_idx + 3] & 0x7f));
                bytes[b_idx + 5] = (byte) (((data[d_idx + 3] >> 3) & 0xf0) | (data[d_idx + 4] & 0x0f));
                bytes[b_idx + 6] = (byte) (((data[d_idx + 4] >> 3) & 0xfe) | (data[d_idx + 5] & 0x01));
                bytes[b_idx + 7] = (byte) ((data[d_idx + 5] >> 1) & 0xff);
                bytes[b_idx + 8] = (byte) (((data[d_idx + 5] >> 3) & 0xc0) | (data[d_idx + 6] & 0x3f));
                bytes[b_idx + 9] = (byte) (((data[d_idx + 6] >> 3) & 0xf8) | (data[d_idx + 7] & 0x07));
                bytes[b_idx + 10] = (byte) ((data[d_idx + 7] >> 3) & 0xff);
            }
        }
        return bytes;
    }
    public static short[][] bytes_to_Rq_vec(byte[] bytes) {
        short[][] data = new short[MODULE_RANK][LWE_N];

        for (int i = 0 ; i < MODULE_RANK ; i++){
            data[i] = bytes_to_Rq(Arrays.copyOfRange(bytes, i*PKPOLY_BYTES , (i+1)*PKPOLY_BYTES), LWE_N);

        }
        return data;
    }

    private static short[] bytes_to_Rq(byte[] bytes, int dlen) {
        short[] data = new short[LWE_N];
        int b_idx = 0, d_idx = 0;

        // Assuming LOG_Q is 10
        if (LOG_Q == 10) {
            for (int i = 0; i < dlen / 4; i++) {
                b_idx = R10_DATA_OFFSET * i;
                d_idx = R10_BYTE_OFFSET * i;
                data[d_idx] = (short) ((((short)bytes[b_idx + 4] & 0x03) << 8) | (bytes[b_idx] & 0xff));
                data[d_idx + 1] = (short) ((((short)bytes[b_idx + 4] & 0x0c) << 6) | (bytes[b_idx + 1] & 0xff));
                data[d_idx + 2] = (short) ((((short)bytes[b_idx + 4] & 0x30) << 4) | (bytes[b_idx + 2] & 0xff));
                data[d_idx + 3] = (short) ((((short)bytes[b_idx + 4] & 0xc0) << 2) | (bytes[b_idx + 3] & 0xff));
            }
        }

        if (LOG_Q == 11) {
            for (int i = 0; i < dlen / 8; ++i) {
                b_idx = R11_DATA_OFFSET * i;
                d_idx = R11_BYTE_OFFSET * i;
                data[d_idx] = (short) ((((short)bytes[b_idx + 1] & 0xe0) << 3) | (bytes[b_idx] & 0xff));
                data[d_idx + 1] = (short) ((((short)bytes[b_idx + 2] & 0xfc) << 3) | (bytes[b_idx + 1] & 0x1f));
                data[d_idx + 2] = (short) ((((short)bytes[b_idx + 4] & 0x80) << 3) |
                        (((short)bytes[b_idx + 3] & 0xff) << 2) | (bytes[b_idx + 2] & 0x03));
                data[d_idx + 3] = (short) ((((short)bytes[b_idx + 5] & 0xf0) << 3) | (bytes[b_idx + 4] & 0x7f));
                data[d_idx + 4] = (short) ((((short)bytes[b_idx + 6] & 0xfe) << 3) | (bytes[b_idx + 5] & 0x0f));
                data[d_idx + 5] = (short) ((((short)bytes[b_idx + 8] & 0xc0) << 3) |
                        (((short)bytes[b_idx + 7] & 0xff) << 1) | (bytes[b_idx + 6] & 0x01));
                data[d_idx + 6] = (short) ((((short)bytes[b_idx + 9] & 0xf8) << 3) | (bytes[b_idx + 8] & 0x3f));
                data[d_idx + 7] = (short) ((((short)bytes[b_idx + 10] & 0xff) << 3) | (bytes[b_idx + 9] & 0x07));
            }
        }
        return data;
    }

    public static byte[] Rp_vec_to_bytes(short[][] data) {
        ArrayList<byte[]> byteList =  new ArrayList<>();
        for (int i = 0; i < MODULE_RANK; ++i)
            byteList.add(Rp_to_bytes(data[i]));
        return Utils.concatenateArrayList(byteList);
    }

    private static byte[] Rp_to_bytes(short[] data){
        byte[] bytes = new byte[CTPOLY1_BYTES];

        Arrays.fill(bytes, (byte) 0);

        for (int i = 0; i < data.length; ++i) {
            bytes[i] = (byte) data[i];
        }

        return bytes;
    }

    public static byte[] Rp2_to_bytes(short[] data) {
        byte[] bytes  = new byte[CIPHERTEXT_BYTES - CTPOLYVEC_BYTES];

        int bIdx = 0;
        int dIdx = 0;

        Arrays.fill(bytes, (byte) 0);

        switch (LOG_P2) {
            case 5:
                for (int i = 0; i < (data.length >> 3); ++i) {
                    bIdx = 5 * i;
                    dIdx = 8 * i;

                    bytes[bIdx] = (byte) ((data[dIdx] & 0x1f) | ((data[dIdx + 1] & 0x7) << 5));
                    bytes[bIdx + 1] = (byte) (((data[dIdx + 1] & 0x18) >> 3) |
                            ((data[dIdx + 2] & 0x1f) << 2) |
                            ((data[dIdx + 3] & 0x01) << 7));
                    bytes[bIdx + 2] = (byte) ((((data[dIdx + 3] & 0x1e) >> 1) |
                            ((data[dIdx + 4] & 0xf) << 4)));
                    bytes[bIdx + 3] = (byte) (((data[dIdx + 4] & 0x10) >> 4) |
                            ((data[dIdx + 5] & 0x1f) << 1) |
                            ((data[dIdx + 6] & 0x3) << 6));
                    bytes[bIdx + 4] = (byte) ((((data[dIdx + 6] & 0x1c) >> 2) |
                            ((data[dIdx + 7] & 0x1f) << 3)));
                }
                break;

            case 8:
                for (int i = 0; i < data.length; ++i) {
                    bytes[i] = (byte) data[i];
                }
                break;

            case 6:
                for (int i = 0; i < (data.length >> 2); ++i) {
                    bIdx = 3 * i;
                    dIdx = 4 * i;

                    bytes[bIdx] = (byte) ((data[dIdx] & 0x3f) | ((data[dIdx + 1] & 0x3) << 6));
                    bytes[bIdx + 1] = (byte) (((data[dIdx + 1] & 0x3c) >> 2) |
                            ((data[dIdx + 2] & 0xf) << 4));
                    bytes[bIdx + 2] = (byte) (((data[dIdx + 2] & 0x30) >> 4) |
                            ((data[dIdx + 3] & 0x3f) << 2));
                }
                break;

            default:
                // Handle other cases if needed
                break;
        }


        return bytes;
    }

    public static byte[][] bytes_to_Sx_vec(byte[] bytes, byte[] bytes_len_arr) {
        byte[][] data = new byte[MODULE_RANK][];
        int idx = 0;

        for (int i = 0; i < MODULE_RANK; ++i) {
            data[i] = bytes_to_Sx(Arrays.copyOfRange(bytes , idx , bytes.length), bytes_len_arr[i]);
            idx += bytes_len_arr[i];
        }
        return data;
    }

    private static byte[] bytes_to_Sx(byte[] bytes, byte bytes_len) {
        byte[] data;
        data = Verify.cmov(bytes, (int) bytes_len, (byte) 1);
        return data;
    }

    public static short[][] bytes_to_Rp_vec(byte[] bytes) {
        short[][] c1 = new short[MODULE_RANK][LWE_N];
        for (int i = 0; i < MODULE_RANK; ++i){
            c1[i] = bytes_to_Rp(Arrays.copyOfRange(bytes,  i * CTPOLY1_BYTES , (i+1) * CTPOLY1_BYTES));
        }
        return c1;
    }

    private static short[] bytes_to_Rp(byte[] bytes) {
        short[] data = new short[LWE_N];
        for (int i = 0; i < data.length; ++i) {
            data[i] = (short) (bytes[i] & 0xFF);
        }
        return data;
    }

    public static short[] bytes_to_Rp2(byte[] bytes) {
        short[] data = new short[LWE_N];

        int bIdx = 0;
        int dIdx = 0;
        Arrays.fill(data, (short) 0);

        int logP2 = LOG_P2; // Change this value based on your requirements

        switch (logP2) {
            case 5:
                for (int i = 0; i < (data.length >> 3); ++i) {
                    bIdx = 5 * i;
                    dIdx = 8 * i;

                    data[dIdx] = (short) (bytes[bIdx] & 0x1F);
                    data[dIdx + 1] = (short) (((bytes[bIdx] & 0xE0) >> 5) | ((bytes[bIdx + 1] & 0x3) << 3));
                    data[dIdx + 2] = (short) ((bytes[bIdx + 1] & 0x7C) >> 2);
                    data[dIdx + 3] = (short) (((bytes[bIdx + 1] & 0x80) >> 7) | ((bytes[bIdx + 2] & 0xF) << 1));
                    data[dIdx + 4] = (short) (((bytes[bIdx + 2] & 0xF0) >> 4) | ((bytes[bIdx + 3] & 0x1) << 4));
                    data[dIdx + 5] = (short) (((bytes[bIdx + 3] & 0x3E) >> 1));
                    data[dIdx + 6] = (short) (((bytes[bIdx + 3] & 0xC0) >> 6) | ((bytes[bIdx + 4] & 0x7) << 2));
                    data[dIdx + 7] = (short) ((bytes[bIdx + 4] & 0xF8) >> 3);
                }
                break;

            case 8:
                for (int i = 0; i < data.length; ++i) {
                    data[i] = (short) (bytes[i] & 0xFF);
                }
                break;

            case 6:
                for (int i = 0; i < (data.length >> 2); ++i) {
                    bIdx = 3 * i;
                    dIdx = 4 * i;

                    data[dIdx] = (short) (bytes[bIdx] & 0x3F);
                    data[dIdx + 1] = (short) (((bytes[bIdx] & 0xC0) >> 6) | ((bytes[bIdx + 1] & 0xF) << 2));
                    data[dIdx + 2] = (short) (((bytes[bIdx + 1] & 0xF0) >> 4) | ((bytes[bIdx + 2] & 0x3) << 4));
                    data[dIdx + 3] = (short) ((bytes[bIdx + 2] & 0xFC) >> 2);
                }
                break;

            default:
                // Handle other cases or throw an exception as needed
                break;
        }

        return data;

    }
}
