package org.thatmadhacker.fdns.server;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Scanner;

import javax.crypto.SecretKey;

import org.thatmadhacker.utils.crypto.BASE64;
import org.thatmadhacker.utils.crypto.Symetric;

public class Server {
	
	public static void main(String[] args) throws Exception{
		
		System.out.println("FDNS v0.1-dev written by thatmadhacker!\n");
		
		if(args.length != 0) {
			
		}else {
			
			Scanner in = new Scanner(System.in);
			
			System.out.print("> ");
			
			String command = in.nextLine();
			
			if(command.equalsIgnoreCase("setup")) {
				
				System.out.println("Entering setup mode!");
				
				System.out.print("Password: ");
				
				String pass = in.nextLine();
				
				System.out.print("Re-Enter Password: ");
				
				if(!pass.equals(in.nextLine())) {
					
					System.err.println("Passwords do not match!!!");
					
					System.exit(1);
					
				}
				
				System.out.println("Generating key...");
				
				SecretKey key = Symetric.genKey("AES", 256);
				
				System.out.println("Generated key!");
				
				System.out.println("Encrypting key with password...");
				
				byte[] encKey = BASE64.decode(Symetric.encrypt(BASE64.encode(key.getEncoded()), Symetric.genKey(pass, "fdnssalt", 256, "AES"), "AES"));
				
				System.out.println("Encrypted key with password!");
				
				System.out.print("Enter path to export key to: ");
				
				File path = new File(in.nextLine());
				
				Files.write(path.toPath(), encKey,StandardOpenOption.CREATE);
				
				System.out.println("Exported key to file");
				
				System.out.print("Enter path to save server's key to: ");
				
				File path2 = new File(in.nextLine());
				
				Files.write(path2.toPath(), key.getEncoded(), StandardOpenOption.CREATE);
				
				System.out.println("Saved key!");
				System.out.println("!!!WARNING!!! Do not save the plaintext key anywhere except on the server \n and it should only be accessable by the FDNS server!");
				
				System.out.println("Finished setup!");
				
				System.exit(0);
				
			}else if(command.equalsIgnoreCase("help")) {
				
				System.out.println("setup - Sets up the keys needed for the FDNS server");
				
				System.exit(0);
				
			}
			
		}
		
	}
	
}
