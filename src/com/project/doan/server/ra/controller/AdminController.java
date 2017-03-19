package com.project.doan.server.ra.controller;

import com.project.doan.server.ra.POJO.EndUser;

public interface AdminController {
	/**
	 * Thực hiện chức năng nhập liệu
	 * Kiểm tra đầu vào
	 * Sinh mã xác thực
	 * Nhập thông tin người dùng vào CSDL
	 * Gửi mã xác thực cho người dùng
	 * Trả lại kết quả
	 * @return
	 */
	boolean importEndUser(EndUser endUser);
	
}
