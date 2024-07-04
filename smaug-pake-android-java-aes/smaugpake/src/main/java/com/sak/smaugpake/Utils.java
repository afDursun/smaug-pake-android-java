package com.sak.smaugpake;

import android.util.Log;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class Utils {
    public static byte[] random_bytes(int length) {
        byte[] array = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(array);
        return  array;
    }
    public static String hex(byte[] byteArray) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : byteArray) {
            hexString.append(String.format("%02x", b & 0xFF)).append("");
        }
        return hexString.toString().trim();
    }
    public static byte[] concatenateArrayList(ArrayList<byte[]> arrayList) {
        int totalLength = 0;

        for (byte[] arr : arrayList) {
            totalLength += arr.length;
        }

        byte[] result = new byte[totalLength];

        int currentIndex = 0;

        for (byte[] arr : arrayList) {
            System.arraycopy(arr, 0, result, currentIndex, arr.length);
            currentIndex += arr.length;
        }

        return result;
    }
    public static byte[] concatenateArrays(byte[] arr1, byte[] arr2) {
        int length1 = arr1.length;
        int length2 = arr2.length;

        byte[] result = new byte[length1 + length2];

        System.arraycopy(arr1, 0, result, 0, length1);

        System.arraycopy(arr2, 0, result, length1, length2);

        return result;
    }
    public static String printShortArrayInHex(short[] shortArray) {
    String hex= "";
        for (short value : shortArray) {
             hex = hex +  String.format("%02x", value);
        }
        return hex;
    }
    public static void printDebug(String s){
        Log.d("AFD-AFD" , s);
    }
    public static byte[] longToBytes(long value) {
        byte[] byteArray = new byte[8];
        for (int i = 0; i < 8; i++) {
            byteArray[7 - i] = (byte) (value >> (i * 8));
        }
        return byteArray;
    }
    public static long[] convertToLongArray(byte[] byteArray) {
        int longCount = byteArray.length / Long.BYTES;
        long[] longArray = new long[longCount];

        for (int i = 0; i < longCount; i++) {
            longArray[i] = bytesToLong(Arrays.copyOfRange(byteArray, i * Long.BYTES, (i + 1) * Long.BYTES));
        }

        return longArray;
    }
    public static byte[] short2byte(short[] shortArray) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(shortArray.length * 2); // short türü 2 byte olduğu için
        for (short value : shortArray) {
            byteBuffer.putShort(value);
        }
        return byteBuffer.array();
    }
    public static long bytesToLong(byte[] bytes) {
        long value = 0;
        for (int i = 0; i < bytes.length; i++) {
            value |= ((long) (bytes[i] & 0xFF)) << (8 * i);
        }
        return value;
    }
}
