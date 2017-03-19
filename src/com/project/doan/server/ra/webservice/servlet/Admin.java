package com.project.doan.server.ra.webservice.servlet;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.project.doan.server.ra.POJO.EndUser;
import com.project.doan.server.ra.controller.AdminController;
import com.project.doan.server.ra.controller.AdminControllerImpl;

/**
 * Servlet implementation class Admin
 */
@WebServlet("/nhap-lieu")
public class Admin extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    public Admin() {
        super();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
	
		response.getWriter().append("Served at: ").append(request.getContextPath());
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// Lay Thong tin cua nguoi dung
		String textCode 		= request.getParameter("taxt_code");
		String country			= request.getParameter("country");
		String state			= request.getParameter("state");
		String district			= request.getParameter("district");
		String email			= request.getParameter("email");
		String sdt				= request.getParameter("phone_number");
		String commonName		= request.getParameter("common_name");
		float expiryDate		= Float.parseFloat(request.getParameter("expiry_date"));
		String organizationName = request.getParameter("organizationName");
		
		EndUser endUser = new EndUser(commonName, textCode, country, state, district, email, organizationName, expiryDate, sdt);
		AdminController adminController = new AdminControllerImpl();
		if(adminController.importEndUser(endUser)){
			
		}
		
		doGet(request, response);
	}

}
