package dke.lib.utils;

public class Logging {

    public static String formatByteArray(byte[] arr, boolean toHex){
        StringBuilder s = new StringBuilder();
        for (byte b : arr) {
            String p = b + "";
            if(toHex)
                p = Integer.toHexString(Byte.toUnsignedInt(b));
            s.append(p).append(",");

        }
        return s.toString();
    }

    public static String formatByteArray(byte[] arr){
        return formatByteArray(arr, true);
    }

}
