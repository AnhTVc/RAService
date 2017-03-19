package com.project.doan.server.ra.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Scanner;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

public class MainUtilImpl implements MainUtil{
	public String fileToString(String pathName){

	    File file = new File(pathName);
	    StringBuilder fileContents = new StringBuilder((int)file.length());
	    Scanner scanner;
		try {
			scanner = new Scanner(file);
		    String lineSeparator = System.getProperty("line.separator");
		    try {
		        while(scanner.hasNextLine()) {
		            fileContents.append(scanner.nextLine() + lineSeparator);
		        }
		        return fileContents.toString();
		    } finally {
		        scanner.close();
		    }
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean sendMail(String toMail, String content, String subject) {
		// TODO Auto-generated method stub
		final String username = "vietanh.bkvp@gmail.com";
		final String password = "23021994";
		Properties props = new Properties();
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.starttls.enable", "true");
		props.put("mail.smtp.host", "smtp.gmail.com");
		props.put("mail.smtp.port", "587");
		
		System.out.println("Auto Sending Mail!");
		Session session = Session.getInstance(props,
		  new javax.mail.Authenticator() {
			protected PasswordAuthentication getPasswordAuthentication() {
				return new PasswordAuthentication(username, password);
			}
		  });

		try {
			Message message = new MimeMessage(session);
			message.setFrom(new InternetAddress(username));
			message.setRecipients(Message.RecipientType.TO,
				InternetAddress.parse(toMail));
			message.setSubject(subject);
			message.setText(content);

			Transport.send(message);

			System.out.println("Done");
			return true;

		} catch (MessagingException e) {
			e.printStackTrace();
			
		}
		return false;
	}

	@Override
	public String md5String(String inputStr) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(inputStr.getBytes());
			byte byteData[] = md.digest();

	        //convert the byte to hex format method 1
	        StringBuffer sb = new StringBuffer();
	        for (int i = 0; i < byteData.length; i++) {
	         sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
	        }
	        return sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		
		return null;
	}
	@Override
	public String randomString(int lenth){
		String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		SecureRandom rnd = new SecureRandom();
		StringBuilder sb = new StringBuilder( lenth );
		   for( int i = 0; i < lenth; i++ ) 
		      sb.append( AB.charAt( rnd.nextInt(AB.length()) ) );
		return sb.toString();
	}
}
