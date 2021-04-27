<?php
if(isset($_POST['data'])){
	if(isset($_POST['mode']) && $_POST['mode'] === "2"){
		$filename = tempnam("/dev/shm", "payload");
        	$myfile = fopen($filename, "w") or die("Unable to open file!");
	        $txt = $_POST['data'];
	        fwrite($myfile, $txt);
	        fclose($myfile);
	        exec("/usr/bin/jruby /opt/json_project/parse.rb $filename 2>&1", $cmdout, $ret);
	        unlink($filename);
		if($ret === 0){
			$output = '<pre>Validation successful!</pre>';
		}
		else{
			$output = '<pre>Validation failed: ' . $cmdout[1] . '</pre>';
		}
	}
	else{
	        $json_ugly = $_POST['data'];
        	$json_pretty = json_encode(json_decode($json_ugly), JSON_PRETTY_PRINT);
        	$output = '<pre>'.$json_pretty.'</pre>';
	}

}
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<title>Online JSON parser</title>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
<!--===============================================================================================-->	
	<link rel="icon" type="image/png" href="images/icons/favicon.ico"/>
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="fonts/Linearicons-Free-v1.0.0/icon-font.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/animate/animate.css">
<!--===============================================================================================-->	
	<link rel="stylesheet" type="text/css" href="vendor/css-hamburgers/hamburgers.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/select2/select2.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="css/util.css">
	<link rel="stylesheet" type="text/css" href="css/main.css">
<!--===============================================================================================-->

<style>
.own-input {
	background: #e6e6e6;
	display: block;
	color: #686868;
	line-height: 1.2;
font-size: 18px;
font-family: Raleway-SemiBold;
border-radius: 3px;
	
}
</style>
</head>
<body>
	
	<div class="limiter">
		<div class="container-login100">
			<div class="wrap-login100 p-l-50 p-r-50 p-t-77 p-b-30">
				<form class="login100-form validate-form" action="" method="post">
					<span class="login100-form-title p-b-55">
						Online JSON beautifier &amp; validator
					</span>
					<select class="form-control" name="mode">
						<option value="1">Beautify</option>
						<option value="2">Validate (beta!)</option>
					</select>
					
					<div class="wrap-input100 mt-3 ">
						<textarea class="input100" type="text" name="data" cols="50"></textarea>
						<span class="focus-input100"></span>
						<span class="symbol-input100">	
						</span>
					</div>

					<div class="wrap-input100  m-b-16">
                                        <br>
					<pre><?php if(isset($_POST['data'])) { echo $output; } else { echo 'Output goes here!';}?></pre>
					<div class="container-login100-form-btn p-t-25">
							<button class="login100-form-btn" type="submit">
								              Process
						        </button>
					</div>
				</form>
			</div>
		</div>
	</div>
	
	

	
<!--===============================================================================================-->	
	<script src="vendor/jquery/jquery-3.2.1.min.js"></script>
<!--===============================================================================================-->
	<script src="vendor/bootstrap/js/popper.js"></script>
	<script src="vendor/bootstrap/js/bootstrap.min.js"></script>
<!--===============================================================================================-->
	<script src="vendor/select2/select2.min.js"></script>
<!--===============================================================================================-->
	<script src="js/main.js"></script>

</body>
</html>
