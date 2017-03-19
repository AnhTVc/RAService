package com.project.doan.server.ra.webservice.servlet;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.project.doan.server.ra.DAO.ServletDAO;
import com.project.doan.server.ra.DAO.ServletDAOImpl;
import com.project.doan.server.ra.util.MainUtil;
import com.project.doan.server.ra.util.MainUtilImpl;

/**
 * Servlet implementation class Login
 */
@WebServlet("/login")
public class Login extends HttpServlet {
	private static final long serialVersionUID = 1L;
       

    public Login() {
        super();
    }


	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.getWriter().append("Served at: ").append(request.getContextPath());
		
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
		String email 		= request.getParameter("email");
		String password 	= request.getParameter("password");
		
		if(email.isEmpty() || email == null
				|| password.isEmpty() || password == null){
			ServletDAO servletDAO	 	= new ServletDAOImpl();
			MainUtil mainUtil 			= new MainUtilImpl();
			if(servletDAO.login(email, mainUtil.md5String(password)))
				response.sendRedirect("admin.jsp");
			else
				response.sendRedirect("admin.jsp");
		}else
			response.sendRedirect("admin.jsp");
	}

}
