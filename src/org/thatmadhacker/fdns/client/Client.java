package org.thatmadhacker.fdns.client;

import java.io.File;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.SecretKey;

import org.thatmadhacker.fdns.Constants;
import org.thatmadhacker.utils.crypto.ASymetric;
import org.thatmadhacker.utils.crypto.BASE64;
import org.thatmadhacker.utils.crypto.Symetric;

public class Client {
	
	public static void main(String[] args) {
		
		
		
	}
	
	public static String resolve(String domain, String fdnsIp) throws Exception{
		
		Socket s = new Socket(fdnsIp,Constants.PORT);
		
		PrintWriter out = new PrintWriter(s.getOutputStream(),true);
		Scanner in = new Scanner(s.getInputStream());
		
		PublicKey serverKey = ASymetric.getPublicKeyFromByteArray(BASE64.decode(in.nextLine().replaceAll("&l", "\n")), "RSA");
		
		SecretKey key = Symetric.genKey("AES", 256);
		
		out.println(ASymetric.encrypt(BASE64.encode(key.getEncoded()), serverKey, "RSA").replaceAll("\n", "&l"));
		
		out.println(Symetric.encrypt("{RESOLVE}", key, "AES").replaceAll("\n", "&l"));
		
		out.println(Symetric.encrypt(domain, key, "AES").replaceAll("\n", "&l"));
		
		String ip = Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES");
		
		in.close();
		s.close();
		
		return ip;
		
	}
	
	public static void addFDNSEntry(String fdnsIp, String domain, String ip, String keyPath, String password) throws Exception{
		
		Socket s = new Socket(fdnsIp,Constants.PORT);
		
		PrintWriter out = new PrintWriter(s.getOutputStream(),true);
		Scanner in = new Scanner(s.getInputStream());
		
		PublicKey serverKey = ASymetric.getPublicKeyFromByteArray(BASE64.decode(in.nextLine().replaceAll("&l", "\n")), "RSA");
		
		SecretKey key = Symetric.genKey("AES", 256);
		
		out.println(ASymetric.encrypt(BASE64.encode(key.getEncoded()), serverKey, "RSA").replaceAll("\n", "&l"));
		
		out.println(Symetric.encrypt("{CONTROL}", key, "AES").replaceAll("\n", "&l"));
		
		byte[] encKey = Files.readAllBytes(new File(keyPath).toPath());
		
		String encKeyS = BASE64.encode(encKey);
		
		byte[] controlKeyB = BASE64.decode(Symetric.decrypt(encKeyS, Symetric.genKey(password, "fdnssalt", 256, "AES"), "AES"));
		
		SecretKey controlKey = Symetric.genKeyFromByteArray(controlKeyB, "AES");
		
		String challenge = Symetric.decrypt(Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES"), controlKey, "AES");
		
		out.println(Symetric.encrypt(challenge, key, "AES").replaceAll("\n", "&l"));
		
		boolean response = Boolean.valueOf(Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES"));
		
		if(response) {
			
			out.println(Symetric.encrypt("A", key, "AES").replaceAll("\n", "&l"));
			
			out.println(Symetric.encrypt(domain, key, "AES").replaceAll("\n", "&l"));
			
			out.println(Symetric.encrypt(ip, key, "AES").replaceAll("\n", "&l"));
			
		}
		
		in.close();
		s.close();
		
	}
	
	public static void removeFDNSEntry(String fdnsIp, String domain, String keyPath, String password) throws Exception{
		
		Socket s = new Socket(fdnsIp,Constants.PORT);
		
		PrintWriter out = new PrintWriter(s.getOutputStream(),true);
		Scanner in = new Scanner(s.getInputStream());
		
		PublicKey serverKey = ASymetric.getPublicKeyFromByteArray(BASE64.decode(in.nextLine().replaceAll("&l", "\n")), "RSA");
		
		SecretKey key = Symetric.genKey("AES", 256);
		
		out.println(ASymetric.encrypt(BASE64.encode(key.getEncoded()), serverKey, "RSA").replaceAll("\n", "&l"));
		
		out.println(Symetric.encrypt("{CONTROL}", key, "AES").replaceAll("\n", "&l"));
		
		byte[] encKey = Files.readAllBytes(new File(keyPath).toPath());
		
		String encKeyS = BASE64.encode(encKey);
		
		byte[] controlKeyB = BASE64.decode(Symetric.decrypt(encKeyS, Symetric.genKey(password, "fdnssalt", 256, "AES"), "AES"));
		
		SecretKey controlKey = Symetric.genKeyFromByteArray(controlKeyB, "AES");
		
		String challenge = Symetric.decrypt(Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES"), controlKey, "AES");
		
		out.println(Symetric.encrypt(challenge, key, "AES").replaceAll("\n", "&l"));
		
		boolean response = Boolean.valueOf(Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES"));
		
		if(response) {
			
			out.println(Symetric.encrypt("R", key, "AES").replaceAll("\n", "&l"));
			
			out.println(Symetric.encrypt(domain, key, "AES").replaceAll("\n", "&l"));
			
		}
		
		in.close();
		s.close();
		
	}
	
}
