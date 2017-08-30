package com.imaginea.pgpencyption;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public abstract class BCPGPUtils {

	public static PGPPublicKey readPublicKey(String publicKeyFilePath) throws IOException, PGPException {

		InputStream keyInputStrem = new FileInputStream(new File(publicKeyFilePath));

		InputStream in = PGPUtil.getDecoderStream(keyInputStrem);
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
		PGPPublicKey key = null;

		Iterator rIt = pgpPub.getKeyRings();
		while (key == null && rIt.hasNext()) {
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator kIt = kRing.getPublicKeys();
			while (key == null && kIt.hasNext()) {
				PGPPublicKey k = (PGPPublicKey) kIt.next();
				if (k.isEncryptionKey()) {
					key = k;
				}
			}
		}

		if (key == null) {
			throw new IllegalArgumentException("Can't find encryption key in key ring.");
		}
		in.close();
		keyInputStrem.close();

		return key;
	}

	public static PGPSecretKey findSecretKey(InputStream in) throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new JcaKeyFingerprintCalculator());

		PGPSecretKey key = null;

		Iterator rIt = pgpSec.getKeyRings();
		while (key == null && rIt.hasNext()) {
			PGPSecretKeyRing kRing = (PGPSecretKeyRing) rIt.next();
			Iterator kIt = kRing.getSecretKeys();

			while (key == null && kIt.hasNext()) {
				PGPSecretKey k = (PGPSecretKey) kIt.next();
				if (k.isSigningKey()) {
					key = k;
				}
			}
		}

		if (key == null) {
			throw new IllegalArgumentException("Can't find signing key in key ring.");
		}
		in.close();
		return key;
	}
}