package com.project.doan.server.ra.POJO;

public class Developer {
	private int developerId;
	private String username;
	private String password;
	
	public Developer(){
		
	}
	public Developer(String username, String password){
		this.username = username;
		this.password = password;
	}
	
	public int getDeveloperId() {
		return developerId;
	}
	public void setDeveloperId(int developerId) {
		this.developerId = developerId;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	
	
}
