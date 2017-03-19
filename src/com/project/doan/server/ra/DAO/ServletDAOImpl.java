package com.project.doan.server.ra.DAO;

import com.project.doan.server.ra.POJO.Developer;
import com.project.doan.server.ra.POJO.EndUser;

public class ServletDAOImpl implements ServletDAO {

	@Override
	public boolean login(String username, String password) {
		Developer developer = new Developer(username, password);
		MySQLConnector myConnector = new MySQLConnectorImpl();
		return myConnector.login(developer);
	}

	@Override
	public boolean importUser(EndUser endUser) {
		// TODO Auto-generated method stub
		return false;
	}

}
