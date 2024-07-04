package sak.smaugpakewithascon;

import static com.sak.smaugpake.SmaugKEM.SHA3_256_HashSize;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.os.Trace;
import android.util.Log;

import com.sak.smaugpake.Model.PakeA0;
import com.sak.smaugpake.Model.PakeB0;
import com.sak.smaugpake.Model.Smaug_128;
import com.sak.smaugpake.Model.Smaug_192;
import com.sak.smaugpake.Model.Smaug_256;
import com.sak.smaugpake.SmaugKEM;
import com.sak.smaugpake.SmaugPake;

import java.util.Arrays;

public class MainActivity extends AppCompatActivity {

    PakeA0 a0;
    PakeB0 b0;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        byte[] pw = new byte[] {
                (byte)0x1F, (byte)0x2B, (byte)0x3C, (byte)0x4D, (byte)0x5E, (byte)0x6F, (byte)0x7A, (byte)0x8B,
                (byte)0x9C, (byte)0xAD, (byte)0xBE, (byte)0xCF, (byte)0xDA, (byte)0xEB, (byte)0xFC, (byte)0x10,
                (byte)0x21, (byte)0x32, (byte)0x43, (byte)0x54, (byte)0x65, (byte)0x76, (byte)0x87, (byte)0x98,
                (byte)0xA9, (byte)0xBA, (byte)0xCB, (byte)0xDC, (byte)0xED, (byte)0xFE, (byte)0x0F, (byte)0x1A
        };

        byte[] a_id = new byte[] {
                (byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, (byte)0x00, (byte)0x11,
                (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99,
                (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF,
                (byte)0x10, (byte)0x32, (byte)0x54, (byte)0x76, (byte)0x98, (byte)0xBA, (byte)0xDC, (byte)0xFE
        };

        byte[] b_id = new byte[] {
                (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88,
                (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, (byte)0x00,
                (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, (byte)0x9A, (byte)0xBC, (byte)0xDE, (byte)0xF0,
                (byte)0x21, (byte)0x43, (byte)0x65, (byte)0x87, (byte)0xA9, (byte)0xCB, (byte)0xED, (byte)0x0F
        };

        byte[] ssid = new byte[] {
                (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
                (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, (byte)0xBB, (byte)0xAA, (byte)0x99, (byte)0x88,
                (byte)0x77, (byte)0x66, (byte)0x55, (byte)0x44, (byte)0x33, (byte)0x22, (byte)0x11, (byte)0x00,
                (byte)0x0F, (byte)0x1E, (byte)0x2D, (byte)0x3C, (byte)0x4B, (byte)0x5A, (byte)0x69, (byte)0x78
        };




        byte[] key_a , key_b;




        byte[] send_a0 ;
        byte[] send_b0 = new byte[SHA3_256_HashSize];

        SmaugKEM kem = new SmaugKEM(new Smaug_256());
        SmaugPake smaugPake = new SmaugPake();




        (findViewById(R.id.b1)).setOnClickListener( v-> {
            Trace.beginSection("a0");
            a0 = smaugPake.a0(pw, ssid,kem);
            Trace.endSection();
        });
        (findViewById(R.id.b2)).setOnClickListener( v-> {
            Trace.beginSection("b0");
            b0 = smaugPake.b0(pw, ssid, a_id, b_id,  a0.getSend_a0(), send_b0, kem);
            Trace.endSection();
        });

        (findViewById(R.id.b3)).setOnClickListener( v-> {
            Trace.beginSection("a1");
            smaugPake.a1(pw, a0.getPk(), a0.getSk(), a0.getSend_a0(), b0.getSend_b0(), ssid, a_id, b_id, b0.getCt(),kem);
            Trace.endSection();
        });

        (findViewById(R.id.b4)).setOnClickListener( v-> {
            Trace.beginSection("b1");
            smaugPake.b1(ssid, a_id, b_id,  a0.getSend_a0(), b0.getCt(), b0.getAuth(), b0.getK());
            Trace.endSection();
        });

/*
        PakeA0 a0 = smaugPake.a0(pw, ssid,kem);
        PakeB0 b0 = smaugPake.b0(pw, ssid, a_id, b_id,  a0.getSend_a0(), send_b0, kem);
        key_a = smaugPake.a1(pw, a0.getPk(), a0.getSk(), a0.getSend_a0(), b0.getSend_b0(), ssid, a_id, b_id, b0.getCt(),kem);
        key_b = smaugPake.b1(ssid, a_id, b_id,  a0.getSend_a0(), b0.getCt(), b0.getAuth(), b0.getK());


        Log.d("AFD-AFD", Arrays.toString(key_a));
        Log.d("AFD-AFD", Arrays.toString(key_b));

        */
/*
        int ITERATIONS = 10000;
        long totalA0Time = 0;
        long totalB0Time = 0;
        long totalA1Time = 0;
        long totalB1Time = 0;

        for (int i = 0; i < ITERATIONS; i++) {
            long startTime = System.nanoTime();
            PakeA0 a0 = smaugPake.a0(pw, ssid, kem);
            long endTime = System.nanoTime();
            totalA0Time += (endTime - startTime);

            startTime = System.nanoTime();
            PakeB0 b0 = smaugPake.b0(pw, ssid, a_id, b_id, a0.getSend_a0(), send_b0, kem);
            endTime = System.nanoTime();
            totalB0Time += (endTime - startTime);

            startTime = System.nanoTime();
            smaugPake.a1(pw, a0.getPk(), a0.getSk(), a0.getSend_a0(), b0.getSend_b0(), ssid, a_id, b_id, b0.getCt(), kem);
            endTime = System.nanoTime();
            totalA1Time += (endTime - startTime);

            startTime = System.nanoTime();
            smaugPake.b1(ssid, a_id, b_id, a0.getSend_a0(), b0.getCt(), b0.getAuth(), b0.getK());
            endTime = System.nanoTime();
            totalB1Time += (endTime - startTime);
        }


        long averageA0Time = totalA0Time / ITERATIONS;
        long averageB0Time = totalB0Time / ITERATIONS;
        long averageA1Time = totalA1Time / ITERATIONS;
        long averageB1Time = totalB1Time / ITERATIONS;


        Log.d("AFD-AFD","Average a0 time: " + averageA0Time + " ns");
        Log.d("AFD-AFD","Average b0 time: " + averageB0Time + " ns");
        Log.d("AFD-AFD","Average a1 time: " + averageA1Time + " ns");
        Log.d("AFD-AFD","Average b1 time: " + averageB1Time + " ns");
*/


    }


}