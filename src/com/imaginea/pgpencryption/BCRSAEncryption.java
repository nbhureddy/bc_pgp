package com.imaginea.pgpencryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Iterator;

import javax.crypto.Cipher;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class BCRSAEncryption
{
    protected static final String ALGORITHM = "RSA";
    private static final String ENC_PUBLIC_KEY_FILE = "henrypublickey.asc";
    private static final String ENC_PRIVATE_KEY_FILE = "henryprivatekey.asc";
    private static final String ENC_SECRET_PWD = "HenryWright";
    
    private static final String SIGN_PUBLIC_KEY_FILE = "marcopublickey.asc";
    private static final String SIGN_PRIVATE_KEY_FILE = "marcoprivatekey.asc";
    private static final String SIGN_SECRET_PWD = "MarcoPolo";
    
    public BCRSAEncryption() {
    	init();
    }
    
    public void init() {
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    
    public static void main(String [] args) {
    	BCRSAEncryption bcrsaEncryption = new BCRSAEncryption();
    	try {
    		PublicKey publicKey = bcrsaEncryption.getPublicKey(ENC_PUBLIC_KEY_FILE);

    		// The following code is for encryption & decryption
			Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] cipherBytes = cipher.doFinal("123456".getBytes());
			System.out.println("Encrypted : " +  new String(Base64.getEncoder().encode(cipherBytes)));
			
			PrivateKey decryptPrivateKey = bcrsaEncryption.getPrivateKey(ENC_PRIVATE_KEY_FILE, ENC_SECRET_PWD.toCharArray());;
			Cipher decrpyCipher = Cipher.getInstance("RSA", "BC");
			decrpyCipher.init(Cipher.DECRYPT_MODE, decryptPrivateKey);
	        byte[] decryptedBytes  = decrpyCipher.doFinal(cipherBytes);
	        System.out.println("Decrypted data: " + new String(decryptedBytes));
			
			
			
//			PrivateKey privateKey = bcrsaEncryption.getPrivateKey(SIGN_PRIVATE_KEY_FILE, SIGN_SECRET_PWD.toCharArray());
//			Signature rsaSign = Signature.getInstance("SHA256withRSA", "BC");
//			rsaSign.initSign(privateKey);
//			rsaSign.update("123456789".getBytes());
//
//			byte[] signedData = rsaSign.sign();
//			System.out.println("Signed : " + new String(Base64.getEncoder().encode(signedData)));
//			byte[] cipherBytes = cipher.doFinal(signedData);
//			System.out.println("123456789 : ");
//			System.out.println("Encrypted : " +  new String(Base64.getEncoder().encode(cipherBytes)));
//
//			cipherBytes = cipher.doFinal("987654321".getBytes());
//			rsaSign.update(cipherBytes);
//			signature = rsaSign.sign();
//			System.out.println("987654321 : ");
//			System.out.println("Encrypted : " +  new String(Base64.getEncoder().encode(cipherBytes)));
//			System.out.println("Signed : " + new String(Base64.getEncoder().encode(signature)));
//			
//			
//			cipherBytes = cipher.doFinal("123454321".getBytes());
//			rsaSign.update(cipherBytes);
//			signature = rsaSign.sign();
//			System.out.println("123454321 : ");
//			System.out.println("Encrypted : " +  new String(Base64.getEncoder().encode(cipherBytes)));
//			System.out.println("Signed : " + new String(Base64.getEncoder().encode(signature)));
//		
//			PublicKey csltPublicKey = bcrsaEncryption.getPublicKey(SIGN_PUBLIC_KEY_FILE);	
//			Signature rsaVerify = Signature.getInstance("SHA256withRSA", "BC");
//			rsaVerify.initVerify(csltPublicKey);
//			rsaVerify.update("123456789".getBytes());
//			System.out.println("Verification: " + rsaVerify.verify(signedData));
//			
//			PrivateKey decryptPrivateKey = bcrsaEncryption.getPrivateKey(ENC_PRIVATE_KEY_FILE, ENC_SECRET_PWD.toCharArray());;
//			Cipher decrpyCipher = Cipher.getInstance("RSA", "BC");
//			decrpyCipher.init(Cipher.DECRYPT_MODE, decryptPrivateKey);
//	        byte[] decryptedBytes  = decrpyCipher.doFinal(cipherBytes);
//	        System.out.println("Decrypted data: " + new String(Base64.getEncoder().encode(decryptedBytes)));
//	        
//			PublicKey realPublicKey = bcrsaEncryption.getPublicKey(REAL_PUBLIC_KEY_FILE);	
//			rsaVerify = Signature.getInstance("SHA256withRSA", "BC");
//			rsaVerify.initVerify(realPublicKey);
//			rsaVerify.update(decryptedBytes);
//			System.out.println("Verification: " + rsaVerify.verify(signature));
	        
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
    
    private PublicKey getPublicKey(String fileName) throws InvalidKeySpecException, NoSuchAlgorithmException {
    	PGPPublicKey pgpKey = null;
    	try {
    		InputStream in= new FileInputStream(new File(fileName));  // Read the file
    		InputStream inputStream = PGPUtil.getDecoderStream(in); // The key file is armored. This step will decode it to binay stream
    		PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(inputStream, new JcaKeyFingerprintCalculator());
    		Iterator<PGPPublicKeyRing> rIt = pubRings.getKeyRings();
    		while (rIt.hasNext()){
    			PGPPublicKeyRing pgpPub = (PGPPublicKeyRing)rIt.next();
    			Iterator<PGPPublicKey> it = pgpPub.getPublicKeys();
    			while (it.hasNext()){
    				pgpKey = (PGPPublicKey)it.next();
//    				System.out.println(pgpKey.getClass().getName()
//    						+ "\n\t KeyID: " + Long.toHexString(pgpKey.getKeyID())
//    						+ "\n\t type: " + pgpKey.getAlgorithm()
//    						+ "\n\t BitStrength: " + pgpKey.getBitStrength()
//    						);
    			}
    		}       
    	} catch(Exception ex) {
    		ex.printStackTrace();
    	}
//    	System.out.println("KeyId of public key found: " + Long.toHexString(pgpKey.getKeyID()));

    	BCPGKey bcKey = pgpKey.getPublicKeyPacket().getKey();
		if( bcKey instanceof RSAPublicBCPGKey ){
			RSAPublicBCPGKey bcRSA = (RSAPublicBCPGKey)bcKey;
//			System.out.println( bcRSA.getModulus() + " Mod:Exp " +  bcRSA.getPublicExponent());
			RSAPublicKeySpec specRSA = new RSAPublicKeySpec( bcRSA.getModulus(), bcRSA.getPublicExponent());
			return KeyFactory.getInstance("RSA").generatePublic(specRSA);
		}
		return null;
    }
    
    private PrivateKey getPrivateKey(String fileName, char[] pass) {
    	try {
    		InputStream in=new FileInputStream(new File(fileName));
    		PGPSecretKeyRingCollection privateRings = 
    				new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
    		
    		Iterator<PGPSecretKeyRing> itr  = privateRings.getKeyRings();
    		
    		PGPSecretKey pgpSecKey = null;
    		while (itr.hasNext()) {
    			PGPSecretKeyRing pgpSecretKeyRing = itr.next();
    			Iterator<PGPSecretKey> it = pgpSecretKeyRing.getSecretKeys();
    			while (it.hasNext()) {
    				PGPSecretKey secretKey = it.next();
//    				System.out.println(secretKey.getClass().getName()
//        					+ " KeyID: " + Long.toHexString(secretKey.getKeyID())
//        					+ " type: " + secretKey.getKeyEncryptionAlgorithm()
//        					+ " isSigning " + secretKey.isSigningKey()
//        					);
    				if (secretKey.isSigningKey())
    					pgpSecKey = secretKey;
    			}
    		}
    		
    		if (pgpSecKey == null)
    		{
    			return null;
    		}
    		
    		PBESecretKeyDecryptor secretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder().build(pass);
    	    PGPPrivateKey pgpPrivateKey = pgpSecKey.extractPrivateKey(secretKeyDecryptor);
//			System.out.println(pgpPrivateKey.getClass().getName()
//					+ " KeyID: " + Long.toHexString(pgpPrivateKey.getKeyID())
//					+ " type: " + pgpPrivateKey.getPublicKeyPacket().getAlgorithm()
//					);
			BCPGKey bcPrivateKey = pgpPrivateKey.getPrivateKeyDataPacket();
			if( bcPrivateKey instanceof RSASecretBCPGKey ){
				RSASecretBCPGKey bcRSA = (RSASecretBCPGKey) bcPrivateKey;
//				System.out.println(bcRSA.getModulus() + " Mod:Exp " + bcRSA.getPrivateExponent());
				RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec( bcRSA.getModulus(), bcRSA.getPrivateExponent());
				return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
			}
    	} catch(Exception ex) {
    		ex.printStackTrace();
    	}
    	return null;
    }
}