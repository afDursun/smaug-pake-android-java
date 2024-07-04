package com.sak.smaugpake;

import static com.sak.smaugpake.SmaugKEM.DIMENSION;
import static com.sak.smaugpake.SmaugKEM.SHAKE256_RATE;
import static com.sak.smaugpake.SmaugKEM.SMAUG_MODE;

import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.Shake256;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Hwt {
    public static byte[] hwt(byte[] cntArr, byte[] input, int inputSize, int hmwt) {
        byte[] res = new byte[DIMENSION];
        int i, pos = 0;
        int degMask = 0, deg = 0;
        byte[] bbuf = new byte[SHAKE256_RATE];
        short[] buf = new short[SHAKE256_RATE / 2];

        switch (SMAUG_MODE) {
            case 1:
                degMask = 0x3ff;
                break;
            case 3:
                degMask = 0x7ff;
                break;
            case 5:
                degMask = 0xfff;
                break;
            default:
                throw new IllegalArgumentException("Invalid SMAUG_MODE");
        }


        KeccakSponge xof = new Shake256();
        xof.getAbsorbStream().write(input);
        xof.getSqueezeStream().read(bbuf);
        ByteBuffer.wrap(bbuf).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(buf);


        for (i = 0; i < DIMENSION; ++i)
            res[i] = 0;

        for (i = DIMENSION - hmwt; i < DIMENSION; ++i) {
            do {

                if (pos >= SHAKE256_RATE / 2) {
                    xof.getSqueezeStream().read(bbuf);
                    ByteBuffer.wrap(bbuf).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(buf);
                    pos = 0;
                }
                deg = buf[pos++] & degMask;
            } while (deg > i);
            res[i] = res[deg];
            res[deg] = (byte) (((buf[pos - 1] >> 14) & 0x02) - 1);
        }


        int cntArrIdx = 0;
        for (i = 0; i < DIMENSION; ++i) {
            cntArrIdx = ((i & 0x700) >> 8) & (-(res[i] & 0x01));
            cntArr[cntArrIdx] += (res[i] & 0x01);
        }
        return res;
    }
}
