package com.project.doan.server.ra.webservice.server.cmp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSASigner.noneDSA;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.mysql.jdbc.util.Base64Decoder;
import com.project.doan.server.ra.util.MainUtil;
import com.project.doan.server.ra.util.MainUtilImpl;

public class GenerateCMPUtil {

	private static final Logger logger = Logger
			.getLogger(GenerateCMPUtil.class);
	private static PrivateKey raKey = getPrivateKeyFromP12File();
	private static X509Certificate racert = getCertificateFromP12File();
	private static X509Certificate cacert = getCACertFromFile("D:\\Data\\Do An\\keystore\\SubCA.pem");
	private static final String CA_HOST = "localhost";
	private static final String CA_PORT = "8080";
	private static String errorStatus = "There is no certificate is returned from CA";
	private static String stringCSR = "";
	public static char[] CM_DIGITS_CHARS = { '1', '2', '3', '4', '5', '6', '7',
			'8', '9', '0', 'q', 'Q', 'w', 'W', 'e', 'E', 'r', 'R', 't', 'T',
			'y', 'Y', 'u', 'U', 'i', 'I', 'o', 'O', 'p', 'P', 'a', 'A', 's',
			'S', 'd', 'D', 'f', 'F', 'g', 'G', 'h', 'H', 'j', 'J', 'k', 'K',
			'l', 'L', 'z', 'Z', 'x', 'X', 'c', 'C', 'v', 'V', 'b', 'B', 'n',
			'N', 'm', 'M' };
	private static ASN1InputStream derin;

	protected static PKIMessage genCertReqFromCSR(String issuerDN,
			X500Name userDN, X500Name senderDN, String altNames,
			SubjectPublicKeyInfo keyInfo, byte[] nonce, byte[] transid,
			Extensions extensions, Date notBefore, Date notAfter,
			BigInteger customCertSerno, DEROctetString senderKID)
			throws NoSuchAlgorithmException, IOException, InvalidKeyException,
			SignatureException, CertificateEncodingException,
			CertificateException, NoSuchProviderException,
			UnrecoverableKeyException, KeyStoreException {
		// Validity can have notBefore, notAfter or both
		ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
		if (notBefore != null) {
			org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(
					notBefore);
			optionalValidityV.add(new DERTaggedObject(true, 0, nb));
		}
		if (notAfter != null) {
			org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(
					notAfter);
			optionalValidityV.add(new DERTaggedObject(true, 1, na));
		}
		OptionalValidity myOptionalValidity = OptionalValidity
				.getInstance(new DERSequence(optionalValidityV));

		CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
		if (notBefore != null || notAfter != null) {
			myCertTemplate.setValidity(myOptionalValidity);
		}
		if (issuerDN != null) {
			myCertTemplate.setIssuer(new X500Name(issuerDN));
		}
		if (userDN != null) {
			// This field can be empty in the spec, and it has happened for real
			// that someone has used empty value here
			myCertTemplate.setSubject(userDN);
		}
		myCertTemplate.setPublicKey(keyInfo);
		// If we did not pass any extensions as parameter, we will create some
		// of our own, standard ones
		Extensions exts = extensions;
		if (exts == null) {

			// SubjectAltName
			// Some altNames
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream dOut = new ASN1OutputStream(bOut);
			ExtensionsGenerator extgen = new ExtensionsGenerator();
			if (altNames != null) {
				// TODO
				byte[] value = bOut.toByteArray();
				extgen.addExtension(Extension.subjectAlternativeName, false,
						value);
			}

			// KeyUsage
			/*
			 * int bcku = 0; bcku = KeyUsage.digitalSignature |
			 * KeyUsage.keyEncipherment | KeyUsage.nonRepudiation; KeyUsage ku =
			 * new KeyUsage(bcku); extgen.addExtension(Extension.keyUsage,
			 * false, new DERBitString(ku));
			 */

			// Make the complete extension package
			exts = extgen.generate();
		}
		myCertTemplate.setExtensions(exts);
		if (customCertSerno != null) {
			// Add serialNumber to the certTemplate, it is defined as a MUST NOT
			// be used in RFC4211, but we will use it anyway in order
			// to request a custom certificate serial number (something not
			// standard anyway)
			myCertTemplate.setSerialNumber(new ASN1Integer(customCertSerno));
		}

		CertRequest myCertRequest = new CertRequest(4, myCertTemplate.build(),
				null);

		// POPO
		/*
		 * PKMACValue myPKMACValue = new PKMACValue( new AlgorithmIdentifier(new
		 * ASN1ObjectIdentifier("8.2.1.2.3.4"), new DERBitString(new byte[] { 8,
		 * 1, 1, 2 })), new DERBitString(new byte[] { 12, 29, 37, 43 }));
		 * 
		 * POPOPrivKey myPOPOPrivKey = new POPOPrivKey(new DERBitString(new
		 * byte[] { 44 }), 2); //take choice pos tag 2
		 * 
		 * POPOSigningKeyInput myPOPOSigningKeyInput = new POPOSigningKeyInput(
		 * myPKMACValue, new SubjectPublicKeyInfo( new AlgorithmIdentifier(new
		 * ASN1ObjectIdentifier("9.3.3.9.2.2"), new DERBitString(new byte[] { 2,
		 * 9, 7, 3 })), new byte[] { 7, 7, 7, 4, 5, 6, 7, 7, 7 }));
		 */
		ProofOfPossession myProofOfPossession = new ProofOfPossession();

		AttributeTypeAndValue av = new AttributeTypeAndValue(
				CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String(
						"regTokenPwd"));
		AttributeTypeAndValue[] avs = { av };

		CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest,
				myProofOfPossession, avs);

		CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);

		PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(
				senderDN), new GeneralName(new X500Name(issuerDN)));

		myPKIHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
		// senderNonce
		myPKIHeader.setSenderNonce(new DEROctetString(nonce));
		// TransactionId
		myPKIHeader.setTransactionID(new DEROctetString(transid));
		// myPKIHeader.setProtectionAlg(pAlg);
		myPKIHeader.setSenderKID(senderKID);
		PKIHeader header = myPKIHeader.build();

		PKIBody myPKIBody = new PKIBody(0, myCertReqMessages); // initialization
																// request

		PKIMessage myPKIMessage = new PKIMessage(header, myPKIBody);
		return myPKIMessage;

	}

	/**
	 * 
	 * @param header
	 * @param body
	 * @return
	 */
	protected static byte[] getProtectedBytes(PKIHeader header, PKIBody body) {
		byte[] res = null;
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(header);
        v.add(body);
        ASN1Encodable protectedPart = new DERSequence(v);
        try {
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(protectedPart);
            res = bao.toByteArray();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return res;
	}

	/**
	 * Dong goi bao ve voi che do EndEntityCertificate
	 * 
	 * @author ChienNH
	 * @since 24/08/16
	 * @param pKIMessage
	 * @param extraCerts
	 * @param key
	 * @param digestAlg
	 * @param provider
	 * @return
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws SecurityException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 * @throws IOException
	 * @throws CertificateEncodingException
	 */
	protected static PKIMessage buildCertBasedPKIProtection(
			PKIMessage pKIMessage, X509Certificate certificate, PrivateKey key,
			String provider){
		// Select which signature algorithm we should use for the response,
		// based on the digest algorithm and key type.
		// According to PKCS#1 AlgorithmIdentifier for RSA-PKCS#1 has null
		// Parameters, this means a DER Null (asn.1 encoding of null), not Java
		// null.
		// For the RSA signature algorithms specified above RFC3447 states
		// "...the parameters MUST be present and MUST be NULL."
		try {
			System.out.println(certificate.getSerialNumber());
			
			PKIHeaderBuilder headerBuilder = getHeaderBuilder(pKIMessage
					.getHeader());
			String signatureAlgorithmName = certificate.getSigAlgName();
			AlgorithmIdentifier pAlg = new AlgorithmIdentifier(
					getOIDFromAlgorithmName(signatureAlgorithmName));
			;
			headerBuilder.setProtectionAlg(pAlg);
			// Most PKCS#11 providers don't like to be fed an OID as signature
			// algorithm, so
			// we use BC classes to translate it into a signature algorithm name
			// instead
			PKIHeader head = headerBuilder.build();
			if (logger.isDebugEnabled()) {
				System.out.println("Signing CMP message with signature alg: "
						+ signatureAlgorithmName);
			}
			Signature sig = Signature.getInstance(signatureAlgorithmName, provider);
			sig.initSign(key);
			
			// TODO error
			
			sig.update(getProtectedBytes(head, pKIMessage.getBody()));

			CMPCertificate[] extraCerts = getCMPCert(certificate);
			if ((extraCerts != null) && (extraCerts.length > 0)) {
				pKIMessage = new PKIMessage(head, pKIMessage.getBody(),
						new DERBitString(sig.sign()), extraCerts);
			} else {
				pKIMessage = new PKIMessage(head, pKIMessage.getBody(),
						new DERBitString(sig.sign()));
			}
			return pKIMessage;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Returns the name of the algorithm corresponding to the specified OID
	 * 
	 * @param sigAlgOid
	 * @return The name of the algorithm corresponding sigAlgOid or null if the
	 *         algorithm is not recognized.
	 */
	@SuppressWarnings("unused")
	private static String getAlgorithmNameFromOID(ASN1ObjectIdentifier sigAlgOid) {

		if (sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption)) {
			return "SIGALG_SHA1_WITH_RSA";
		}

		if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)) {
			return "SIGALG_SHA256_WITH_RSA";
		}

		if (sigAlgOid.equals(PKCSObjectIdentifiers.sha384WithRSAEncryption)) {
			return "SIGALG_SHA384_WITH_RSA";
		}

		if (sigAlgOid.equals(PKCSObjectIdentifiers.sha512WithRSAEncryption)) {
			return "SIGALG_SHA512_WITH_RSA";
		}

		return null;
	}

	private static ASN1ObjectIdentifier getOIDFromAlgorithmName(
			String sigAlgName) {

		if (sigAlgName.equalsIgnoreCase("SIGALG_SHA1_WITH_RSA")) {
			return PKCSObjectIdentifiers.sha1WithRSAEncryption;
		}

		if (sigAlgName.equalsIgnoreCase("SIGALG_SHA256_WITH_RSA")) {
			return PKCSObjectIdentifiers.sha256WithRSAEncryption;
		}

		if (sigAlgName.equalsIgnoreCase("SIGALG_SHA384_WITH_RSA")) {
			return PKCSObjectIdentifiers.sha384WithRSAEncryption;
		}

		if (sigAlgName.equalsIgnoreCase("SIGALG_SHA512_WITH_RSA")) {
			return PKCSObjectIdentifiers.sha512WithRSAEncryption;
		}

		return null;
	}

	protected static PKIHeaderBuilder getHeaderBuilder(PKIHeader head) {
		PKIHeaderBuilder builder = new PKIHeaderBuilder(head.getPvno()
				.getValue().intValue(), head.getSender(), head.getRecipient());
		builder.setFreeText(head.getFreeText());
		builder.setGeneralInfo(head.getGeneralInfo());
		builder.setMessageTime(head.getMessageTime());
		builder.setRecipKID((DEROctetString) head.getRecipKID());
		builder.setRecipNonce(head.getRecipNonce());
		builder.setSenderKID(head.getSenderKID());
		builder.setSenderNonce(head.getSenderNonce());
		builder.setTransactionID(head.getTransactionID());
		return builder;
	}

	private static CMPCertificate[] getCMPCert(Certificate cert)
			throws CertificateEncodingException, IOException {
		ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
		ASN1Primitive pcert = ins.readObject();
		ins.close();
		org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate
				.getInstance(pcert.toASN1Primitive());
		CMPCertificate[] res = { new CMPCertificate(c) };
		return res;
	}

	/**
	 * Dong goi bao ve voi che do HMAC
	 * 
	 * @author ChienNH
	 * @since 24/08/16
	 * @param msg
	 * @param badObjectId
	 * @param password
	 * @param keyId
	 * @param iterations
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 */
	protected static PKIMessage protectPKIMessage(PKIMessage msg,
			boolean badObjectId, String password, String keyId, int iterations)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException {
		Security.addProvider(new BouncyCastleProvider());
		// Create the PasswordBased protection of the message
		PKIHeaderBuilder head = getHeaderBuilder(msg.getHeader());
		if (keyId != null) {
			head.setSenderKID(new DEROctetString(keyId.getBytes()));
		}
		// SHA1
		AlgorithmIdentifier owfAlg = new AlgorithmIdentifier(
				new ASN1ObjectIdentifier("1.3.14.3.2.26"));
		// 567 iterations
		int iterationCount = iterations;
		ASN1Integer iteration = new ASN1Integer(iterationCount);
		// HMAC/SHA1
		AlgorithmIdentifier macAlg = new AlgorithmIdentifier(
				new ASN1ObjectIdentifier("1.2.840.113549.2.7"));
		byte[] salt = createSenderNonce();
		DEROctetString derSalt = new DEROctetString(salt);

		// Create the new protected return message
		String objectId = "1.2.840.113533.7.66.13";
		if (badObjectId) {
			objectId += ".7";
		}
		PBMParameter pp = new PBMParameter(derSalt, owfAlg, iteration, macAlg);
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(
				new ASN1ObjectIdentifier(objectId), pp);
		head.setProtectionAlg(pAlg);
		PKIHeader header = head.build();
		// Calculate the protection bits
		byte[] raSecret = password.getBytes();
		byte[] basekey = new byte[raSecret.length + salt.length];
		System.arraycopy(raSecret, 0, basekey, 0, raSecret.length);
		for (int i = 0; i < salt.length; i++) {
			basekey[raSecret.length + i] = salt[i];
		}
		// Construct the base key according to rfc4210, section 5.1.3.1
		MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm()
				.getId());
		for (int i = 0; i < iterationCount; i++) {
			basekey = dig.digest(basekey);
			dig.reset();
		}
		// For HMAC/SHA1 there is another oid, that is not known in BC, but the
		// result is the same so...
		String macOid = macAlg.getAlgorithm().getId();
		PKIBody body = msg.getBody();
		byte[] protectedBytes = getProtectedBytes(header, body);
		Mac mac = Mac.getInstance(macOid, "BC");
		SecretKey key = new SecretKeySpec(basekey, macOid);
		mac.init(key);
		mac.reset();
		mac.update(protectedBytes, 0, protectedBytes.length);
		byte[] out = mac.doFinal();
		DERBitString bs = new DERBitString(out);
		
		PKIMessage temp = new PKIMessage(header, body, bs);
		return temp;
	}

	public static byte[] pkiMessageToByteArray(PKIMessage msg)
			throws IOException {
		// Return response as byte array
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DEROutputStream mout = new DEROutputStream(baos);
		mout.writeObject(msg);
		mout.close();
		return baos.toByteArray();

	}

	/**
	 * 
	 * @param retMsg
	 * @return
	 * @throws IOException
	 */
	public static X509Certificate getCmpCertRepMessage(byte[] retMsg)
			throws IOException {
		//
		// Parse response message
		//
		X509Certificate resCert = null;
		ByteArrayInputStream bis = new ByteArrayInputStream(retMsg);
		ASN1InputStream stream = new ASN1InputStream(bis);
		try {

			PKIMessage mes = PKIMessage.getInstance(stream.readObject());
			PKIBody body = mes.getBody();
			if (body.getContent() instanceof CertRepMessage) {
				CertRepMessage c = (CertRepMessage) body.getContent();
				CertResponse[] respList = c.getResponse();
				logger.info("\nPKIMessageResponse :\n-PKIHeader :\n--Pvno :"
						+ mes.getHeader().getPvno().toString() + "\n--Sender :"
						+ mes.getHeader().getSender().toString()
						+ "\n--Recipient :"
						+ mes.getHeader().getRecipient().toString()
						+ "\n-PKIBody :\n--Type :" + mes.getBody().getType()
						+ "\n--Content :"
						+ mes.getBody().getContent().toString() + "");
				for (CertResponse certResponse : respList) {
					if (certResponse.getStatus().getStatusString() != null) {
						logger.info("\n---CertResponse :"
								+ "\n----Status :"
								+ certResponse.getStatus().getStatusString()
										.getStringAt(0).getString());
						errorStatus = certResponse.getStatus()
								.getStatusString().getStringAt(0).getString();
					} else if (certResponse.getCertifiedKeyPair() != null) {
						org.bouncycastle.asn1.x509.Certificate cer = certResponse
								.getCertifiedKeyPair().getCertOrEncCert()
								.getCertificate().getX509v3PKCert();
						logger.info("\n---CertResponse :"
								+ "\n----SerialNumber :"
								+ cer.getSerialNumber().getValue().toString(16)
								+ "\n----Subject :"
								+ cer.getSubject().toString()
								+ "\n----TimeValid :"
								+ cer.getStartDate().getTime() + " - "
								+ cer.getEndDate().getTime());
						CertifiedKeyPair kp = certResponse
								.getCertifiedKeyPair();
						CertOrEncCert cc = kp.getCertOrEncCert();
						CMPCertificate struct = cc.getCertificate();
						resCert = (X509Certificate) getCertfromByteArray(struct
								.getEncoded());
					}
				}
			} else if (body.getContent() instanceof ErrorMsgContent) {
				ErrorMsgContent errMsg = (ErrorMsgContent) body.getContent();
				logger.info("\nPKIMessageResponse :\n-PKIHeader :\n--Pvno :"
						+ mes.getHeader().getPvno().toString() + "\n--Sender :"
						+ mes.getHeader().getSender().toString()
						+ "\n--Recipient :"
						+ mes.getHeader().getRecipient().toString()
						+ "\n-PKIBody :\n--Type :" + mes.getBody().getType()
						+ "\n--Content :"
						+ mes.getBody().getContent().toString() + "");
				if (errMsg.getPKIStatusInfo().getStatusString() != null) {
					logger.info("\n---ErrorMsgContent :"
							+ "\n----Status :"
							+ errMsg.getPKIStatusInfo().getStatusString()
									.getStringAt(0).getString());
					errorStatus = errMsg.getPKIStatusInfo().getStatusString()
							.getStringAt(0).getString();
				}
			}

		} catch (IOException e) {
			logger.error("IOException => " + e.getMessage());
		} catch (Exception e) {
			logger.error("CertificateException => " + e.getMessage());
		} finally {
			bis.close();
			stream.close();
		}
		return resCert;
	}

	/**
	 * 
	 * @param retMsg
	 * @return
	 */
	public static X509Certificate checkCmpCertRepMessage(byte[] retMsg) {
		ASN1InputStream asn1InputStream = new ASN1InputStream(
				new ByteArrayInputStream(retMsg));
		X509Certificate cert = null;
		try {
			PKIMessage respObject = PKIMessage.getInstance(asn1InputStream
					.readObject());
			PKIBody body = respObject.getBody();
			CertRepMessage c = (CertRepMessage) body.getContent();
			CertResponse resp = c.getResponse()[0];
			// PKIStatusInfo info = resp.getStatus();
			CertifiedKeyPair kp = resp.getCertifiedKeyPair();
			CertOrEncCert cc = kp.getCertOrEncCert();
			CMPCertificate cmpcert = cc.getCertificate();
			byte[] encoded = cmpcert.getEncoded();
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			cert = (X509Certificate) cf
					.generateCertificate(new ByteArrayInputStream(encoded));
			asn1InputStream.close();
		} catch (IOException e) {
			logger.error("IOException => " + e.getMessage());
		} catch (CertificateException e) {
			logger.error("CertificateException => " + e.getMessage());
		}
		return cert;

	}

	/**
	 * 
	 * @param message
	 *            gui sang CA
	 * @param hostname
	 * @param port
	 * @return
	 */
	public static byte[] sendCmpHttp(byte[] message, String hostname,
			String port, String senderKID) {
		byte[] respBytes = null;
		HttpURLConnection con = null;
		try {
			URL url = new URL("http://" + hostname + ":" + port
					+ "/ejbca/publicweb/cmp/" + senderKID);
			con = (HttpURLConnection) url.openConnection();
			con.setDoOutput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-type", "application/pkixcmp");
			con.connect();

			OutputStream os = con.getOutputStream();
			os.write(message);
			os.close();

			// Only try to read the response if we expected a 200 (ok) response
			if (con.getResponseCode() == 200) {
				// String contentType = con.getContentType());
				// String cacheControl = con.getHeaderField("Cache-Control");
				// String pragma = con.getHeaderField("Pragma");

				// Now read in the bytes
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				// This works for small requests, and CMP requests are small
				// enough
				InputStream in = con.getInputStream();
				int b = in.read();
				while (b != -1) {
					baos.write(b);
					b = in.read();
				}
				baos.flush();
				in.close();
				respBytes = baos.toByteArray();
			} else {
				logger.info("HTTP Response Code = " + con.getResponseCode());
			}

		} catch (MalformedURLException e) {
			logger.error("MalformedURLException => " + e.getMessage());
		} catch (ProtocolException e) {
			logger.error("ProtocolException => " + e.getMessage());
		} catch (IOException e) {
			logger.error("IOException => " + e.getMessage());
		} finally {
			if (con != null) {
				con.disconnect();
			}
		}
		return respBytes;
	}

	/**
	 * 
	 * @return
	 */
	public static byte[] createSenderNonce() {
		// Sendernonce is a random number
		byte[] senderNonce = new byte[16];
		Random randomSource;
		randomSource = new Random();
		randomSource.nextBytes(senderNonce);
		return senderNonce;
	}

	/**
	 * 
	 * @return
	 */
	public static byte[] createTransactionID() {
		byte[] transactionID = new byte[16];
		Random randomSource;
		randomSource = new Random();
		randomSource.nextBytes(transactionID);
		return transactionID;
	}

	/**
	 * 
	 * @param privateKey
	 * @param certChain
	 * @param pin
	 * @param alias
	 * @return
	 * @throws NoSuchProviderException
	 */
	public static KeyStore getKeyStoreCertChainAndKey(PrivateKey privateKey,
			Certificate[] certChain, String pin, String alias)
			throws NoSuchProviderException {
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("PKCS12", "BC");
			ks.load(null, null);
			ks.setKeyEntry(alias, privateKey, pin.toCharArray(), certChain);

		} catch (KeyStoreException e) {
			e.printStackTrace();
			logger.error("KeyStoreException => " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.error("NoSuchAlgorithmException => " + e.getMessage());
		} catch (CertificateException e) {
			logger.error("CertificateException => " + e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			logger.error("IOException => " + e.getMessage());
		}
		return ks;
	}

	@SuppressWarnings({  "deprecation" })
	static private PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(
			String pem) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		PemReader pemReader = new PemReader(new StringReader(pem));
		PemObject pemObject;
		try {
			pemObject = pemReader.readPemObject();
			PKCS10CertificationRequest req = new PKCS10CertificationRequest(
					pemObject.getContent());
			return req;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static X509Certificate generateCmpFromCSR(String filePath) {
		X509Certificate cert = null;

		// Lấy nội dung chuỗi CSR

		/*
		 * PSubjectInfo subjectInfo = MessageUtil.createSubjectInfo(crh
		 * .getCustomerType(), uid, extraUid, crh.getCommonName(),
		 * crh.getEmail(), crh .getOrganizationName(),
		 * crh.getDistrict().getName(), crh .getState().getName(),
		 * crh.getCountry().getName(), crh .getMessageTemplate(), null, crh
		 * .getUidPrefix());
		 */

		// TODO
		// csr = getContentCSR(crh.getCertificateSigningRequest());
		MainUtil mainUtil = new MainUtilImpl();
		try {
			
			PKCS10CertificationRequest pcr = convertPemToPKCS10CertificationRequest(mainUtil.fileToString(filePath));
			byte[] encoded = pcr.getPublicKey().getEncoded();
			SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));
			 // Get
																					// from
																					// csr
			// TODO
			/* = pcr.getSubjectPublicKeyInfo(); */
			String sender = "CN=VietAnh,OU=VietAnh,O=VietAnh,L=VietAnh,ST=VietAnh,C=VN,E=VietAnh".trim();// name.toString();
			String altNames = "CMPConfig";
			// MessageTemplate mt = crh.getMessageTemplate();

			// Lấy EndEntityProfile theo MessageTemplate
			String senderKID = "CMPConfig".trim();
			/*
			 * if(crh.getSubjectAlternativeName()!=null &&
			 * !crh.getSubjectAlternativeName().isEmpty()){ altNames =
			 * crh.getSubjectAlternativeName(); }
			 */
			// |=> sau thoi diem nay
			DateFormat formatter = new SimpleDateFormat("MM/dd/yy");
			Date notBefore = formatter.parse("01/29/17");
			Date notAfter = formatter.parse("01/29/18");;// truoc thoi diem nay =>|

			
			PKIMessage me = genCertReqFromCSR(cacert.getSubjectDN().getName(),
					new X500Name(sender), new X500Name(sender), altNames,
					publicKeyInfo, createSenderNonce(), createTransactionID(),
					null, notBefore, notAfter, null, new DEROctetString(
							senderKID.getBytes()));

			// EndEntity dung method buildCertBasedPKIProtection, HMAC dung
			// method protectPKIMessage
			
			// RA key sign
			PKIMessage mes = buildCertBasedPKIProtection(me, getCertificateFromP12File(), 
					getPrivateKeyFromP12File(),"BC");
			
			//PKIMessage mes = me;
			/*PKIMessage mes = protectPKIMessage(me, false, "123456a@A",
						senderKID, 567);*/

			// mes = createNestedMessage(mes,
			// createSenderNonce(),createTransactionID(),
			// racert.getSubjectDN().getName(), racert.getIssuerDN().getName(),
			// pRAKey);
			// reqMsgAnalysis(mes);

			byte[] in = pkiMessageToByteArray(mes);

			long startTime = System.nanoTime();
			byte[] respBytes = sendCmpHttp(in, CA_HOST, CA_PORT, senderKID);
			long difference = System.nanoTime() - startTime;
			logExecutionTime("sendCmpHttp", difference);
			if (respBytes == null) {
				logger.error("CA server not responding");
				errorStatus = "CA server not responding";
				return cert;
			}
			startTime = System.nanoTime();
			X509Certificate resCert = getCmpCertRepMessage(respBytes);
			if (resCert == null) {
				difference = System.nanoTime() - startTime;
				logExecutionTime(
						"Analysis Response Certificate (no certificate) -",
						difference);
				return cert;
			}
			Certificate[] chain = new Certificate[2];
			chain[0] = resCert;
			chain[1] = cacert;

			cert = resCert;
			difference = System.nanoTime() - startTime;
			logExecutionTime(
					"Analysis Response Certificate (has one certificate) -",
					difference);
			// TODO
			stringCSR = mainUtil.fileToString(filePath);
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
			
		} catch (Exception e) {
			e.printStackTrace();
			
		}
		return cert;
	}

	/**
	 * Phan tich goi message gui len CA
	 * 
	 * @author ChienNH
	 * @param mes
	 */
	protected static void reqMsgAnalysis(PKIMessage mes) {
		PKIMessages bodyMes = (PKIMessages) mes.getBody().getContent();
		PKIMessage[] bodyMesList = bodyMes.toPKIMessageArray();
		logger.info("\nPKIMessageRequest :\n-PKIHeader :\n--Pvno :"
				+ mes.getHeader().getPvno().toString() + "\n--Sender :"
				+ mes.getHeader().getSender().toString() + "\n--Recipient :"
				+ mes.getHeader().getRecipient().toString()
				+ "\n-PKIBody :\n--Type :" + mes.getBody().getType()
				+ "\n--Content :" + mes.getBody().getContent().toString() + "");
		for (PKIMessage pkiMessage : bodyMesList) {
			CertReqMessages reqMes = (CertReqMessages) pkiMessage.getBody()
					.getContent();
			CertReqMsg[] reqMesList = reqMes.toCertReqMsgArray();

			logger.info("\n---PKIHeader :\n----Pvno :"
					+ pkiMessage.getHeader().getPvno().toString()
					+ "\n----Sender :"
					+ pkiMessage.getHeader().getSender().toString()
					+ "\n----Recipient :"
					+ pkiMessage.getHeader().getRecipient().toString()
					+ "\n---PKIBody :\n----Type :"
					+ pkiMessage.getBody().getType() + "\n----Content :"
					+ pkiMessage.getBody().getContent().toString() + "");

			for (CertReqMsg certReqMsg : reqMesList) {
				if (certReqMsg.getCertReq().getCertTemplate().getValidity() != null) {
					DERSequence derSequence = (DERSequence) certReqMsg
							.getCertReq().getCertTemplate().getValidity()
							.toASN1Primitive();
					logger.info("\n-----CertReqMsg :\n------CertRequest :"
							+ "\n-------CertReqId :"
							+ certReqMsg.getCertReq().getCertReqId().toString()
							+ "\n-------CertTemplate :\n--------Publickey :"
							+ certReqMsg.getCertReq().getCertTemplate()
									.getPublicKey().getAlgorithm()
									.getAlgorithm().getId()
							+ "\n--------Issuer :"
							+ certReqMsg.getCertReq().getCertTemplate()
									.getIssuer().toString()
							+ "\n--------Subject :"
							+ certReqMsg.getCertReq().getCertTemplate()
									.getSubject().toString()
							+ "\n--------StartTime :"
							+ derSequence.getObjectAt(0).toString()
							+ "\n--------EndTime :"
							+ derSequence.getObjectAt(1).toString() + "");
				} else {
					logger.info("\n-----CertReqMsg :\n------CertRequest :"
							+ "\n-------CertReqId :"
							+ certReqMsg.getCertReq().getCertReqId().toString()
							+ "\n-------CertTemplate :\n--------Publickey :"
							+ certReqMsg.getCertReq().getCertTemplate()
									.getPublicKey().getAlgorithm()
									.getAlgorithm().getId()
							+ "\n--------Issuer :"
							+ certReqMsg.getCertReq().getCertTemplate()
									.getIssuer().toString()
							+ "\n--------Subject :"
							+ certReqMsg.getCertReq().getCertTemplate()
									.getSubject().toString());
				}

			}
		}
	}

	/**
	 * 
	 * @param phase
	 * @param time
	 */
	protected static void logExecutionTime(String phase, long time) {
		logger.info(phase
				+ " execution time: "
				+ String.format(
						"%dm %ds %dms",
						TimeUnit.NANOSECONDS.toMinutes(time),
						TimeUnit.NANOSECONDS.toSeconds(time)
								- TimeUnit.MINUTES
										.toSeconds(TimeUnit.NANOSECONDS
												.toMinutes(time)),
						TimeUnit.NANOSECONDS.toMillis(time)
								- TimeUnit.SECONDS
										.toMillis(TimeUnit.NANOSECONDS
												.toSeconds(time))));
	}

	/**
	 * Hàm lấy nội dung chuỗi CSR, lọc bỏ phần <b>-----BEGIN CERTIFICATE
	 * REQUEST-----</b>,<br/>
	 * <b>-----END CERTIFICATE REQUEST-----</b> ở đầu và cuối file, và ký tự
	 * xuống dòng
	 * 
	 * @param originalCSR
	 *            chuỗi CSR gốc (lấy từ database)
	 * @author HungDMc
	 * @see createDate: 27/6/2016, modifyDate: 27/6/2016
	 * @return String
	 */
	public static String getContentCSR(String originalCSR) {
		try {
			Pattern p = Pattern
					.compile("(-{1,5})([A-Z\\s]*)(-{1,5})(.*)(-{1,5})([A-Z\\s]*)(-{1,5})");
			Matcher m = p.matcher(originalCSR);

			originalCSR = m.replaceAll("$4");
			return originalCSR.replace("\r", "").replace("\n", "").trim();
		} catch (Exception e) {
			e.printStackTrace();
			logger.error("getContentCSR() - Exception: " + e);
		}
		return null;
	}

	private static PrivateKey getPrivateKeyFromP12File() {
		String p12Pass = "1";
		String p12File = "D:\\Data\\Do An\\RACert.p12";
		PrivateKey key = null;
		try {
			KeyStore keystore = KeyStore.getInstance("PKCS12");
			keystore.load(new FileInputStream(p12File), p12Pass.toCharArray());
			Enumeration<String> aliases = keystore.aliases();
			String keyAlias = "";
			while (aliases.hasMoreElements()) {
				keyAlias = (String) aliases.nextElement();
			}
			key = (PrivateKey) keystore.getKey(keyAlias, p12Pass.toCharArray());
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return key;
	}

	private static X509Certificate getCertificateFromP12File() {
		String p12Pass = "1";
		String p12File = "D:\\Data\\Do An\\RACert.p12";
		X509Certificate certificate = null;
		try {
			KeyStore keystore = KeyStore.getInstance("PKCS12");
			keystore.load(new FileInputStream(p12File), p12Pass.toCharArray());
			Enumeration<String> aliases = keystore.aliases();
			String keyAlias = "";
			while (aliases.hasMoreElements()) {
				keyAlias = (String) aliases.nextElement();
			}
			certificate = (X509Certificate) keystore.getCertificate(keyAlias);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return certificate;
	}

	private static X509Certificate getCACertFromFile(String fileName) {
		MainUtil mainUtil = new MainUtilImpl();

		try {
			Certificate myCert = CertificateFactory.getInstance("X509")
					.generateCertificate(
					// string encoded with default charset
							new ByteArrayInputStream(mainUtil.fileToString(
									fileName).getBytes()));
			return (X509Certificate) myCert;
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		return null;
	}

	public static String getErrorStatus() {
		return errorStatus;
	}

	public static String getCSR() {
		return stringCSR;
	}

	public static void main(String[] args) {
		long startTime = System.nanoTime();
		try {
			// System.out.println(racert.getSigAlgOID());
		} catch (Exception e) {
			System.out.println(e);
		}
		long difference = System.nanoTime() - startTime;
		System.out.println("Total execution time: "
				+ String.format(
						"%dm %ds %dms",
						TimeUnit.NANOSECONDS.toMinutes(difference),
						TimeUnit.NANOSECONDS.toSeconds(difference)
								- TimeUnit.MINUTES
										.toSeconds(TimeUnit.NANOSECONDS
												.toMinutes(difference)),
						TimeUnit.NANOSECONDS.toMillis(difference)
								- TimeUnit.SECONDS
										.toMillis(TimeUnit.NANOSECONDS
												.toSeconds(difference))));
	}

	private static X509Certificate getCertfromByteArray(byte[] bytes) {
		CertificateFactory certFactory;
		try {
			certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(bytes);
			X509Certificate cert = (X509Certificate) certFactory
					.generateCertificate(in);
			return cert;
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}