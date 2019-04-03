package org.thatmadhacker.utils.crypto;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The Class AES.
 */
public class Symetric {

	public static boolean INIT = false;

	static {
		if (!Symetric.INIT) {
			Security.addProvider(new BouncyCastleProvider());
			Symetric.INIT = true;
		}
	}

	public static final String AES = "AES";
	public static final int AES128 = 128;
	public static final int AES192 = 192;
	public static final int AES256 = 256;

	/**
	 * Gen key.
	 *
	 * @param password the password
	 * @return the secret key
	 * @throws Exception the exception
	 */
	public static SecretKey genKey(String password, String salt, int length, String algo) throws Exception {
		byte[] salt1 = salt.getBytes();
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt1, 65536, 128);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), algo);
		return secret;
	}

	/**
	 * Gen key.
	 *
	 * @return the secret key
	 * @throws Exception the exception
	 */
	public static SecretKey genKey(String algo, int length) throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance(algo);
		SecureRandom random = new SecureRandom();
		keyGen.init(length, random);
		SecretKey secretKey = keyGen.generateKey();
		return secretKey;
	}

	/**
	 * Encrypt.
	 *
	 * @param data the data
	 * @param key  the key
	 * @return the string
	 * @throws Exception the exception
	 */
	public static String encrypt(String data, SecretKey key, String algo) throws Exception {
		Cipher c = Cipher.getInstance(algo);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encVal = c.doFinal(data.getBytes());
		String encryptedValue = BASE64.encode(encVal);
		return encryptedValue.replaceAll(System.lineSeparator(), "&l");
	}

	/**
	 * Decrypt.
	 *
	 * @param encryptedData the encrypted data
	 * @param key           the key
	 * @return the string
	 * @throws Exception the exception
	 */
	public static String decrypt(String encryptedData, SecretKey key, String algo) throws Exception {
		Cipher c = Cipher.getInstance(algo);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decodedValue = BASE64.decode(encryptedData.replaceAll("&l", System.lineSeparator()));
		byte[] decValue = c.doFinal(decodedValue);
		String decryptedValue = new String(decValue);
		return decryptedValue;
	}

	public static SecretKey genKeyFromByteArray(byte[] encodedKey, String algo) {
		return new SecretKeySpec(encodedKey, 0, encodedKey.length, algo);
	}

	public static void encryptDir(File dir, SecretKey key, String algo) throws Exception {
		for (File f : dir.listFiles()) {
			if (!f.isDirectory()) {
				Scanner in = new Scanner(f);
				List<String> lines = new ArrayList<String>();
				while (in.hasNextLine()) {
					lines.add(encrypt(in.nextLine(), key, algo));
				}
				in.close();
				f.delete();
				f.createNewFile();
				PrintWriter out = new PrintWriter(new FileWriter(f));
				for (String s : lines) {
					out.println(s);
				}
				out.close();
			} else {
				encryptDir(f, key, algo);
			}
		}
	}

	public static void decryptDir(File dir, SecretKey key, String algo) throws Exception {
		for (File f : dir.listFiles()) {
			if (!f.isDirectory()) {
				Scanner in = new Scanner(f);
				List<String> lines = new ArrayList<String>();
				while (in.hasNextLine()) {
					lines.add(decrypt(in.nextLine(), key, algo));
				}
				in.close();
				f.delete();
				f.createNewFile();
				PrintWriter out = new PrintWriter(new FileWriter(f));
				for (String s : lines) {
					out.println(s);
				}
				out.close();
			} else {
				decryptDir(f, key, algo);
			}
		}
	}
}
