package com.codernaut.letslicense;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
/**
 * 
 * This will be the class to generate the license
 * 
 * @author Codernaut
 *
 */
public class LicenseGenerator {
	public static void main(String []args) {
	
		String path=System.getProperty("user.home");
		if(args.length>1) {
			path=args[1];
			System.out.println("Second argument given which will be used as path to save key files");
		}
		if(args!=null||args.length==1) {
			try {
				String fileLines=Files.readAllLines(Paths.get(args[0])).toString();
				EncDec encdec=new EncDec();
				encdec.genrateKeyandEncode(fileLines);
				encdec.SaveKeyPair(path, encdec.getKeyPair());
			} catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				System.err.println("You need to atleast pass path to license file as first argument or you can pass second argument as path to save key files else they will be saves in user home");
				System.err.println("To use exsisting private key you can pass third argument");
			}
		}
		else {
			System.err.println("You need to atleast pass path to license file as first argument or you can pass second argument as path to save key files else they will be saves in user home");
			System.err.println("To use exsisting private key you can pass third argument");
		}
	}

}
