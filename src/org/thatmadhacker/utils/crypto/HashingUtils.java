package org.thatmadhacker.utils.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class HashingUtils {

	public static final String SHA256 = "SHA-256";
	public static final String SHA128 = "SHA-1";
	public static final String SHA512 = "SHA-512";
	public static final String SHA224 = "SHA-224";
	public static final String SHA384 = "SHA-384";
	public static final String MD5 = "MD5";
	public static final String MD2 = "MD2";

	/**
	 * Hash the input.
	 *
	 * @param string
	 *            the input string
	 * @param algo
	 *            the algorithm
	 * @return the string
	 */
	public static String hash(String string, String algo) throws Exception {
		MessageDigest digest = MessageDigest.getInstance(algo);
		String hash = BASE64.encode(digest.digest(string.getBytes(StandardCharsets.UTF_8)));
		return hash;
	}
	
	public static String saltAndHash(String string, String algo, byte[] salt) throws Exception{
		if(salt == null){
			SecureRandom random = new SecureRandom();
			salt = new byte[64];
			random.nextBytes(salt);
		}
		String saltString = BASE64.encode(salt);
		return hash(string+saltString, algo)+"#"+saltString;
	}
	public static boolean checkSaltedHash(String hash, String text, String algo) throws Exception{
		String salt = hash.split("#")[1];
		byte[] bytes = BASE64.decode(salt);
		String hashedText = saltAndHash(text, algo, bytes);
		if(hashedText.equals(hash)){
			return true;
		}
		return false;
	}
}
