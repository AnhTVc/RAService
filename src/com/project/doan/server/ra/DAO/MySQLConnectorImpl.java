package com.project.doan.server.ra.DAO;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.project.doan.server.ra.POJO.Developer;
import com.project.doan.server.ra.POJO.EndUser;
import com.project.doan.server.ra.util.MainUtil;
import com.project.doan.server.ra.util.MainUtilImpl;

public class MySQLConnectorImpl implements MySQLConnector{
	private static final String MYSQL_USER_NAME 			= "root";
	private static final String MYSQL_PASSWORD 				= "123456";
	private static final String URL_DBNAME 					= "jdbc:mysql://10.211.55.3:3306/raservice";
	private static final String URL_FILE_DATA				= "";
	private static boolean isOpenConnection 				= false;
	Connection connection = null;
	PreparedStatement statement = null;
	@Override
	public boolean openConnection() {
		System.out.println("Connecting to database: " + URL_DBNAME);
		try{
			Class.forName("com.mysql.jdbc.Driver");
			connection = DriverManager.getConnection(URL_DBNAME, MYSQL_USER_NAME, MYSQL_PASSWORD);
			System.out.println("Database connected!");
			isOpenConnection = true;
			return true;
		}catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean closeConnection() {
		try {
			System.out.println("Close connection to database: " + URL_DBNAME);
			connection.close();
			return true;
		} catch (SQLException e) {
			e.getSQLState();
		}
		
		isOpenConnection = false;
		return false;
	}	
	
	@Override
	public boolean checkDB(String dbName) {
		//Create data if not exit
		System.out.println("Check database!");
		
		try {
			Class.forName("com.mysql.jdbc.Driver");
	        connection = DriverManager.getConnection(URL_DBNAME,
	                MYSQL_USER_NAME, MYSQL_PASSWORD);
		} catch (Exception e) {
			System.out.println("Database not exist, create db!");
		}
		return false;
	}

	@Override
	public boolean deleteDB(String dbName) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean truncateTableInDB(String tableName) {
		try {
			String sql = "TRUNCATE TABLE ?";
			if(!isOpenConnection)
				openConnection();
			
			statement = connection.prepareStatement(sql);
			
			statement.setString(1, tableName);
			statement.executeQuery(sql);
			return false;
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
	}

	@Override
	public boolean executeSQlFile(String pathFile) {
		try {
			MainUtil mainUtil = new MainUtilImpl();
			String sqlData = mainUtil.fileToString(URL_FILE_DATA);
			
			if(!sqlData.isEmpty() && sqlData != null){
				if(!isOpenConnection){
					openConnection();
				}
				
				statement = connection.prepareStatement(sqlData);
				statement.executeQuery(sqlData);
				
				closeConnection();
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
	}

	@Override
	public ResultSet selectSQL(PreparedStatement preStatement) {
		if(!isOpenConnection)
			openConnection();
		
		try {
			ResultSet resultSet = preStatement.executeQuery();
			closeConnection();
			return resultSet;
		} catch (SQLException e) {
			e.printStackTrace();
		}
		
		closeConnection();
		return null;
	}

	@Override
	public boolean login(Developer developer) {
		if(!isOpenConnection)
			openConnection();
		System.out.println("developer login");
		
		try {
			String sql = "SELECT username, developer_id from developer where password = ?";
			statement = connection.prepareStatement(sql);
			statement.setString(1, developer.getPassword());
			
			ResultSet resultSet = selectSQL(statement);
			if(resultSet.getString(1).equals(developer.getUsername()))
				return true;
			
		} catch (SQLException e) {
			e.printStackTrace();
		}
		closeConnection();
		
		return false;
	}

	public boolean importUser(EndUser endUser) {
		if(!isOpenConnection)
			openConnection();
		System.out.println("import End User To Database");
		String sql = "INSERT INTO end_user(common_name, tax_code, country, state, district, email, organization_name, expiry_date, phone_number, register_code)"
				+ " VALUES(?, ?, ?, ?, ?, ?, ?)";
		try {
			statement = connection.prepareStatement(sql);
			statement.setString(1, endUser.getCommonName());
			statement.setString(2, endUser.getTaxCode());
			statement.setString(3, endUser.getCountry());
			statement.setString(4, endUser.getState());
			statement.setString(5, endUser.getEmail());
			statement.setString(6, endUser.getOrganizationName());
			statement.setFloat(7, endUser.getExpiryDate());
			statement.setString(8, endUser.getPhoneNumber());
			statement.setString(9, endUser.getRegisterCode());
			
			return statement.execute();
		} catch (SQLException e) {
			// TODO: handle exception
			e.getErrorCode();
		}
		return false;
	}

}
