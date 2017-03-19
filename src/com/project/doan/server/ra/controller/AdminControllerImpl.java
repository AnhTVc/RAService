package com.project.doan.server.ra.controller;

import com.project.doan.server.ra.DAO.MySQLConnector;
import com.project.doan.server.ra.DAO.MySQLConnectorImpl;
import com.project.doan.server.ra.POJO.EndUser;
import com.project.doan.server.ra.util.MainUtil;
import com.project.doan.server.ra.util.MainUtilImpl;

public class AdminControllerImpl implements AdminController {

	@Override
	public boolean importEndUser(EndUser endUser) {
		MainUtil mainUtil = new MainUtilImpl();
		MySQLConnector mySQLConnector = new MySQLConnectorImpl();
		endUser.setRegisterCode(mainUtil.randomString(6));
		if(mySQLConnector.importUser(endUser))
		{
			// send mail
			String content = "Register Code: " + endUser.getRegisterCode();
			String subject = "Mail From CA";
			return mainUtil.sendMail(endUser.getEmail(), content, subject);
			
		}else
			return false;
	}

}
