package com.project.doan.server.ra.DAO;

import java.sql.PreparedStatement;
import java.sql.ResultSet;

import com.project.doan.server.ra.POJO.Developer;
import com.project.doan.server.ra.POJO.EndUser;

public interface MySQLConnector {

	
	/**
	 * Class execute SQL file in mysql
	 * @param pathFile
	 * @return
	 */
	public boolean executeSQlFile(String pathFile);
	
	/**
	 * Open Connection
	 * @return
	 */
	public boolean openConnection();
	
	/**
	 * Close connection
	 * @return
	 */
	public boolean closeConnection();
	/**
	 * Class check db.
	 * If not exist => create db and table in db
	 * If DB is exist => check table
	 * @param dbName
	 * @return true and false
	 */
	public boolean checkDB(String dbName);
	
	/**
	 * Delete database
	 * @param dbName
	 * @return
	 */
	public boolean deleteDB(String dbName);
	
	/**
	 * Truncate table
	 * @param tableName
	 * @return
	 */
	public boolean truncateTableInDB(String tableName);
	
	/**
	 * Run query select mysql
	 * @param sql
	 * @return
	 */
	public ResultSet selectSQL(PreparedStatement statement);
	
	/**
	 * Thuc hien ham login. return true or false
	 * @param developer
	 * @return
	 */
	public boolean login(Developer developer);
	
	public boolean importUser(EndUser endUser);
}
