package com.project.doan.server.ra.util;
public interface MainUtil {
	/**
	 * Read file to String
	 * @param pathName
	 * @return
	 */
	public String fileToString(String pathName);
	
	/**
	 * Function send mail
	 * @param toMail: mail recent 
	 * @param message: data message
	 * @return: true and false
	 */
	public boolean sendMail(String toMail, String content, String subject);
	
	/**
	 * Function md5 hash
	 * @param inputStr: string input
	 * @return: string hash
	 */
	public String md5String(String inputStr);
	
	public String randomString(int lenth);
}
