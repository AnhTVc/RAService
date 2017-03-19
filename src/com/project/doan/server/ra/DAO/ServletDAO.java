package com.project.doan.server.ra.DAO;

import com.project.doan.server.ra.POJO.EndUser;

public interface ServletDAO {

	/**
	 * Login
	 * @param username
	 * @param password
	 * @return
	 */
	public boolean login(String username, String password);
	
	public boolean importUser(EndUser endUser);
}
