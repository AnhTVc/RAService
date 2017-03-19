package com.project.doan.server.ra.POJO;

public class EndUser {
	private int endUserId;
	private String commonName;
	private String taxCode;
	private String messageTemplate;
	private int countryId;
	private int  stateId;
	private int districtId;
	private String subjectDN;
	private String email;
	private String csrPKCS10;
	private String organizationName;
	private float expiryDate;
	private String registerCode;
	private String phoneNumber;
	private String country;
	private String state;
	private String district;
	
	public EndUser(){
		
	}
	
	public EndUser(String commonName, String taxCode, String country,
			String state,String district, String email,String organizationName,
			float expiryDate, String phoneNumber){
		this.commonName = commonName;
		this.taxCode 	= taxCode;
		this.setCountry(country);
		this.setState(state);
		this.setDistrict(district);
		this.email		= email;
		this.organizationName = organizationName;
		this.phoneNumber = phoneNumber;
		this.expiryDate = expiryDate;
	}
	
	
	public int getEndUserId() {
		return endUserId;
	}
	public void setEndUserId(int endUserId) {
		this.endUserId = endUserId;
	}
	public String getCommonName() {
		return commonName;
	}
	public void setCommonName(String commonName) {
		this.commonName = commonName;
	}
	public String getTaxCode() {
		return taxCode;
	}
	public void setTaxCode(String taxCode) {
		this.taxCode = taxCode;
	}
	public String getMessageTemplate() {
		return messageTemplate;
	}
	public void setMessageTemplate(String messageTemplate) {
		this.messageTemplate = messageTemplate;
	}
	public int getCountryId() {
		return countryId;
	}
	public void setCountryId(int countryId) {
		this.countryId = countryId;
	}
	public int getStateId() {
		return stateId;
	}
	public void setStateId(int stateId) {
		this.stateId = stateId;
	}
	public int getDistrictId() {
		return districtId;
	}
	public void setDistrictId(int districtId) {
		this.districtId = districtId;
	}
	public String getSubjectDN() {
		return subjectDN;
	}
	public void setSubjectDN(String subjectDN) {
		this.subjectDN = subjectDN;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getCsrPKCS10() {
		return csrPKCS10;
	}
	public void setCsrPKCS10(String csrPKCS10) {
		this.csrPKCS10 = csrPKCS10;
	}
	public String getOrganizationName() {
		return organizationName;
	}
	public void setOrganizationName(String organizationName) {
		this.organizationName = organizationName;
	}
	public float getExpiryDate() {
		return expiryDate;
	}
	public void setExpiryDate(float expiryDate) {
		this.expiryDate = expiryDate;
	}
	public String getRegisterCode() {
		return registerCode;
	}
	public void setRegisterCode(String registerCode) {
		this.registerCode = registerCode;
	}
	public String getPhoneNumber() {
		return phoneNumber;
	}
	public void setPhoneNumber(String phoneNumber) {
		this.phoneNumber = phoneNumber;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(String country) {
		this.country = country;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public String getDistrict() {
		return district;
	}

	public void setDistrict(String district) {
		this.district = district;
	}
	
	
	
}
