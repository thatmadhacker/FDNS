package org.thatmadhacker.utils.crypto;

import java.io.IOException;

public class BASE64 {
	
	public static byte[] decode(String s) throws IOException{
		return java.util.Base64.getDecoder().decode(s);
	}
	public static String encode(byte[] b){
		return java.util.Base64.getEncoder().encodeToString(b);
	}
}
