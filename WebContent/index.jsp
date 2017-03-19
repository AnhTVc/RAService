<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<%
	String url = request.getContextPath();
%>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Login to PKI</title>
<link rel="stylesheet" type="text/css" href="<%=url%>/css/index.css">
<link rel="stylesheet" type="text/css"  href="<%=url%>/lib/bootstrap/css/bootstrap.min.css">
<script src="https://npmcdn.com/tether@1.2.4/dist/js/tether.min.js"></script>
<script type="text/javascript" src="<%=url%>/lib/jquery/jquery-3.1.1.min.js"></script>
<script type="text/javascript" src="<%=url%>/lib/bootstrap/js/bootstrap.min.js"></script>

</head>
<body>
<div class="container" style="margin-top: 100px">
    <div class="row">
    	<div class="col-sm-3 col-md-4 col-md-offser-4"></div>
        <div class="col-sm-6 col-md-4 col-md-offset-4">
            <h1 class="text-center login-title">Login to PKI of BKHN</h1>
            <div class="account-wall">
                <img class="profile-img" src="https://lh5.googleusercontent.com/-b0-k99FZlyE/AAAAAAAAAAI/AAAAAAAAAAA/eu7opA4byxI/photo.jpg?sz=120"
                    alt="">
                <form class="form-signin" action="login" method="POST">
	                <input type="text" class="form-control" id="email" name="email" placeholder="Email" required autofocus>
	                <input type="password" class="form-control" id="password" name="password" placeholder="Password" required>
	                <button class="btn btn-lg btn-primary btn-block" type="submit">
	                    Sign in</button>
	                <label class="checkbox pull-left">
	                    <input type="checkbox" value="remember-me">
	                    Remember me
	                </label>
	                <a href="#" class="pull-right need-help">Need help? </a><span class="clearfix"></span>
                </form>
            </div>
        </div>
    </div>
</div>
</body>
</html>