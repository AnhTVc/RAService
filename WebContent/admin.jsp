<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<%
	String url = request.getContextPath();
%>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Form Nhap Lieu</title>
<link rel="stylesheet" type="text/css" href="<%=url%>/css/index.css">
<link rel="stylesheet" type="text/css"  href="<%=url%>/lib/bootstrap/css/bootstrap.min.css">
<script src="https://npmcdn.com/tether@1.2.4/dist/js/tether.min.js"></script>
<script type="text/javascript" src="<%=url%>/lib/jquery/jquery-3.1.1.min.js"></script>
<script type="text/javascript" src="<%=url%>/lib/bootstrap/js/bootstrap.min.js"></script>
<style type="text/css">
.input-group-addon.primary {
    color: rgb(255, 255, 255);
    background-color: rgb(50, 118, 177);
    border-color: rgb(40, 94, 142);
}
.input-group-addon.success {
    color: rgb(255, 255, 255);
    background-color: rgb(92, 184, 92);
    border-color: rgb(76, 174, 76);
}
.input-group-addon.info {
    color: rgb(255, 255, 255);
    background-color: rgb(57, 179, 215);
    border-color: rgb(38, 154, 188);
}
.input-group-addon.warning {
    color: rgb(255, 255, 255);
    background-color: rgb(240, 173, 78);
    border-color: rgb(238, 162, 54);
}
.input-group-addon.danger {
    color: rgb(255, 255, 255);
    background-color: rgb(217, 83, 79);
    border-color: rgb(212, 63, 58);
}
</style>
</head>
<body>
<div class="container">
	<form action="nhap-lieu" method="POST">
		<div class="row">
			<h3>Nhập Thông Tin Người Dùng</h3>
		</div>
		<hr>
	    <div class="row">
	    	<div class="col-sm-3">
	    		<p>CMND/Mã Số Thuế</p>
	    	</div>
		    <div class="col-sm-6 form-group">
		        <div class="input-group">
		            <input type="text" class="form-control" name="taxt_code" placeholder="CMND/Mã Số Thuế ..." >
		        </div>
		    </div>
	    </div>
	    <hr>
	    <div class="row" style="font-size: 13px" >
	    	<div class="col-sm-4">
	    		<div class="col-sm-12"  style="text-align: center;">
		    		<p>Quốc Gia</p>
			    	</div>
				    <div class="col-sm-12 form-group">
				        <div class="input-group">
				            <input type="text" class="form-control" name="country" placeholder="Quốc Gia ..." >
				        </div>
				  </div>
	    	</div>
	    	<div class="col-sm-4">
	    		<div class="col-sm-12" style="text-align: center;">
	    			<p>Tỉnh/Thành phố</p>
		    	</div>
			    <div class="col-sm-12 form-group">
			        <div class="input-group">
			            <input type="text" class="form-control" name="state" placeholder="Tỉnh/Thành Phố ..." >
			        </div>
			  	</div>
	    	</div>
	    	<div class="col-sm-4">
	    		<div class="col-sm-12" style="text-align: center;">
		    		<p>Quận/Huyện</p>
			    </div>
			    <div class="col-sm-12 form-group">
			        <div class="input-group">
			            <input type="text" name="district" class="form-control"  placeholder="Quận/Huyện ..." >
			        </div>
			  	</div>
	    	</div>
	    </div>
	    <hr>
	    <div class="row" style="font-size: 13px">
	    	<div class="col-sm-6">
	    		<div class="col-sm-3" style="text-align: center;">
		    		<p>Email</p>
			    </div>
	    		<div class="col-sm-9 form-group">
		        	<div class="input-group">
		            	<input type="text" class="form-control" name="email" placeholder="email ..." >
		        	</div>
		    	</div>
	    	</div>
		    <div class="col-sm-6">
	    		<div class="col-sm-3" style="text-align: center;">
		    		<p>SDT</p>
			    </div>
	    		<div class="col-sm-9 form-group">
		        	<div class="input-group">
		            	<input type="text" class="form-control" name="phone_number" placeholder="SDT ..." >
		        	</div>
		    	</div>
	    	</div>
	    </div>
	    <div class="row">
			<h3>Thông  Chứng Thư Số</h3>
		</div>
		<hr>
		<div class="row" style="font-size: 13px">
	    	<div class="col-sm-6">
	    		<div class="col-sm-3" style="text-align: center;">
		    		<p>CommonName</p>
			    </div>
	    		<div class="col-sm-9 form-group">
		        	<div class="input-group">
		            	<input type="text" class="form-control" name="common_name" placeholder="commonname ..." >
		        	</div>
		    	</div>
	    	</div>
		    <div class="col-sm-6">
	    		<div class="col-sm-3" style="text-align: center;">
		    		<p>Hạn Sử Dụng</p>
			    </div>
	    		<div class="col-sm-9 form-group">
		        	<div class="input-group">
		            	<input type="text" class="form-control" name="expiry_date" placeholder="Hạn sử dụng ..." >
		        	</div>
		    	</div>
	    	</div>
	    </div>
	    <hr>
	    <div class="row">
			<h3>Thông tin tổ chức</h3>
		</div>
		<hr>
		<div class="row">
	    	<div class="col-sm-3">
	    		<p>Tên Tổ Chức(nếu có)</p>
	    	</div>
		    <div class="col-sm-6 form-group">
		        <div class="input-group">
		            <input type="text" class="form-control" name="organizationName" placeholder="Tên tổ chức ..." >
		        </div>
		    </div>
	    </div>
	    <button type="submit" class="btn btn-success" style="text-align: center;">Xong</button>
	</form>
</div>

</body>
</html>