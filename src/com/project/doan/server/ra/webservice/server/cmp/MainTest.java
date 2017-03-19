package com.project.doan.server.ra.webservice.server.cmp;

import java.security.cert.X509Certificate;

import com.project.doan.server.ra.util.MainUtil;
import com.project.doan.server.ra.util.MainUtilImpl;

public class MainTest {
	public static void main(String[] arg){
		MainUtil mainUtil = new MainUtilImpl();
		String data = mainUtil.fileToString("D:\\Data\\Do An\\keystore\\pkcs10.csr");
		X509Certificate cert =GenerateCMPUtil.generateCmpFromCSR("D:\\Data\\Do An\\keystore\\pkcs10.csr");
		System.out.print(cert.getSubjectDN());
		
	}
}
