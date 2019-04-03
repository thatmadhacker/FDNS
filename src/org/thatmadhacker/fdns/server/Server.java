package org.thatmadhacker.fdns.server;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.SecretKey;

import org.thatmadhacker.fdns.Constants;
import org.thatmadhacker.utils.crypto.ASymetric;
import org.thatmadhacker.utils.crypto.BASE64;
import org.thatmadhacker.utils.crypto.Symetric;

public class Server extends Thread {

	public static Map<String, String> fdns = new HashMap<String, String>();

	public static void main(String[] args) throws Exception {

		System.out.println("FDNS v0.1-dev written by thatmadhacker!\n");

		if (args.length != 0) {

			if (args[0].equalsIgnoreCase("--start")) {
				startServer();
			}

		} else {

			Scanner in = new Scanner(System.in);

			System.out.print("> ");

			String command = in.nextLine();

			if (command.equalsIgnoreCase("setup")) {

				System.out.println("Entering setup mode!");

				System.out.print("Password: ");

				String pass = in.nextLine();

				System.out.print("Re-Enter Password: ");

				if (!pass.equals(in.nextLine())) {

					System.err.println("Passwords do not match!!!");

					System.exit(1);

				}

				System.out.println("Generating key...");

				SecretKey key = Symetric.genKey("AES", 256);

				System.out.println("Generated key!");

				System.out.println("Encrypting key with password...");

				byte[] encKey = BASE64.decode(Symetric.encrypt(BASE64.encode(key.getEncoded()),
						Symetric.genKey(pass, "fdnssalt", 256, "AES"), "AES"));

				System.out.println("Encrypted key with password!");

				System.out.print("Enter path to export key to: ");

				File path = new File(in.nextLine());

				Files.write(path.toPath(), encKey, StandardOpenOption.CREATE);

				System.out.println("Exported key to file");

				System.out.print("Enter path to save server's key to: ");

				File path2 = new File(in.nextLine());

				Files.write(path2.toPath(), key.getEncoded(), StandardOpenOption.CREATE);

				System.out.println("Saved key!");
				System.out.println(
						"!!!WARNING!!! Do not save the plaintext key anywhere except on the server \n and it should only be accessable by the FDNS server!");

				System.out.println("Finished setup!");

				System.exit(0);

			} else if (command.equalsIgnoreCase("help")) {

				System.out.println("setup - Sets up the keys needed for the FDNS server");
				System.out.println("start - Starts the FDNS server");

				System.exit(0);

			} else if (command.equalsIgnoreCase("start")) {
				startServer();
			}

			in.close();

		}

	}

	private static SecretKey controlKey;

	private static void startServer() {

		try {

			File f = new File("control.key");

			Scanner in = new Scanner(f);

			controlKey = Symetric.genKeyFromByteArray(BASE64.decode(in.nextLine().replaceAll("&l", "\n")), "AES");

			in.close();

			loadFDNS();

			ServerSocket ss = new ServerSocket(Constants.PORT);

			while (!ss.isClosed()) {

				Socket s = ss.accept();

				new Server(s).start();

			}

			ss.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static void loadFDNS() throws Exception {

		File f = new File("fdns.data");

		Scanner in = new Scanner(f);

		while (in.hasNextLine()) {

			String s = in.nextLine();

			fdns.put(s.split(":")[0], s.split(":")[1]);

		}

		in.close();

	}

	private static void appendFDNS(String domain, String ip) throws Exception {

		File f = new File("fdns.data");

		PrintWriter out = new PrintWriter(new FileWriter(f, true));

		out.println(domain + ":" + ip);

		out.close();

	}

	private static void saveFDNS() throws Exception {

		File f = new File("fdns.data");

		PrintWriter out = new PrintWriter(new FileWriter(f, true));
		
		for(String s : fdns.keySet()) {
			
			out.println(s+":"+fdns.get(s));
			
		}
		
		out.close();
		
	}

	private Socket s;

	public Server(Socket s) {
		this.s = s;
	}

	@Override
	public void start() {

		try {

			PrintWriter out = new PrintWriter(s.getOutputStream(), true);
			Scanner in = new Scanner(s.getInputStream());

			KeyPair pair = ASymetric.genKeys("RSA", 2048);

			out.println(BASE64.encode(pair.getPublic().getEncoded()).replaceAll("\n", "&l"));

			String keyS = ASymetric.decrypt(in.nextLine().replaceAll("&l", "\n"), pair.getPrivate(), "RSA");

			SecretKey key = Symetric.genKeyFromByteArray(BASE64.decode(keyS), "AES");

			while (!s.isClosed()) {

				String command = Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES");

				if (command.equals("{CONTROL}")) {

					byte[] test = new byte[8192];

					SecureRandom random = new SecureRandom();

					random.nextBytes(test);

					out.println(Symetric.encrypt(Symetric.encrypt(BASE64.encode(test), controlKey, "AES"), key, "AES")
							.replaceAll("\n", "&l"));

					byte[] response = BASE64.decode(Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES"));

					if (response.equals(test)) {
						out.println(Symetric.encrypt("true", key, "AES").replaceAll("\n", "&l"));
					} else {
						out.println(Symetric.encrypt("false", key, "AES").replaceAll("\n", "&l"));
						in.close();
						s.close();
						return;
					}
					// At this point the client has passed the test

					String command1 = Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES");

					if (command1.equals("R")) {
						
						String domain = Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES");
						
						fdns.remove(domain);
						
						saveFDNS();
						
					} else if (command1.equals("A")) {
						
						String domain = Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES");
						
						String ip = Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES");
						
						fdns.put(domain,ip);
						
						appendFDNS(domain, ip);
						
					}
					
					in.close();
					s.close();
					return;

				}else if(command.equals("{RESOLVE}")) {
					
					String domain = Symetric.decrypt(in.nextLine().replaceAll("&l", "\n"), key, "AES");
					
					out.println(Symetric.encrypt(fdns.get(domain), key, "AES").replaceAll("\n", "&l"));
					
					in.close();
					s.close();
					return;
					
				}

			}

			in.close();
			s.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
