<html>
<head>
    <title>OpenEMR Login</title>
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />

    
<link rel="stylesheet" href="/public/assets/bootstrap-3-3-4/dist/css/bootstrap.min.css?v=41" type="text/css">
<link rel="stylesheet" href="/interface/themes/style_light.css?v=41?v=41" type="text/css">
<link rel="stylesheet" href="/public/assets/jquery-ui-1-12-1/themes/ui-darkness/jquery-ui.min.css?v=41" type="text/css">
<link rel="stylesheet" href="/public/assets/font-awesome-4-6-3/css/font-awesome.min.css?v=41" type="text/css">

<script type="text/javascript" src="/public/assets/jquery-min-3-1-1/index.js?v=41"></script>
<script type="text/javascript" src="/public/assets/bootstrap-3-3-4/dist/js/bootstrap.min.js?v=41"></script>
<script type="text/javascript" src="/public/assets/jquery-ui-1-12-1/jquery-ui.min.js?v=41"></script>
<script type="text/javascript" src="/library/textformat.js?v=41"></script>
<script type="text/javascript" src="/library/dialog.js?v=41"></script>


    <link rel="stylesheet" href="../themes/login.css?v=41" type="text/css">

    <link rel="shortcut icon" href="/public/images/favicon.ico" />

    <script type="text/javascript">
        var registrationTranslations = {"title":"OpenEMR Product Registration","pleaseProvideValidEmail":"Please provide a valid email address","success":"Success","registeredSuccess":"Your installation of OpenEMR has been registered","submit":"Submit","noThanks":"No Thanks","registeredEmail":"Registered email","registeredId":"Registered id","genericError":"Error. Try again later","closeTooltip":""};

        var registrationConstants = {"webroot":""};
    </script>

    <script type="text/javascript" src="/interface/product_registration/product_registration_service.js?v=41"></script>
    <script type="text/javascript" src="/interface/product_registration/product_registration_controller.js?v=41"></script>

    <script type="text/javascript">
        jQuery(document).ready(function() {
            init();

            var productRegistrationController = new ProductRegistrationController();
            productRegistrationController.getProductRegistrationStatus(function(err, data) {
                if (err) { return; }

                if (data.statusAsString === 'UNREGISTERED') {
                    productRegistrationController.showProductRegistrationModal();
                }
            });
        });

        function init() {
            $("#authUser").focus();
        }

        function transmit_form() {
            document.forms[0].submit();
        }

        function imsubmitted() {
                            // Delete the session cookie by setting its expiration date in the past.
                // This forces the server to create a new session ID.
                var olddate = new Date();
                olddate.setFullYear(olddate.getFullYear() - 1);
                document.cookie = 'OpenEMR=7uq9jqmrng7dhvbsnabi0lh90c; path=/; expires=' + olddate.toGMTString();
                        return false; //Currently the submit action is handled by the encrypt_form().
        }
    </script>

</head>
<body class="login">
    <div class="container">
        <form method="POST" id="login_form"
            action="../main/main_screen.php?auth=login&site=default"
            target="_top" name="login_form" onsubmit="return imsubmitted();">
            <div class="row">
                <div class="col-sm-12">
                    <div>
                        <div class="center-block" style="max-width:400px">
                            <img class="img-responsive center-block" src="/public/images/login-logo.png" />
                        </div>

                        <input type='hidden' name='new_login_session_management' value='1' />

                        <input type='hidden' name='authProvider' value='Default' />
<input type='hidden' name='languageChoice' value='1' />
                    </div>
                </div>
            </div>
                                    <div class="row">
                                                <div class="col-sm-12">
                    <div class="row">
                        <div class="center-block login-title-label">
                                                    </div>
                                            </div>
                                        <div class="form-group">
                        <label for="authUser" class="control-label text-right">Username:</label>
                        <input type="text" class="form-control" id="authUser" name="authUser" placeholder="Username:">
                    </div>
                    <div class="form-group">
                        <label for="clearPass" class="control-label text-right">Password:</label>
                        <input type="password" class="form-control" id="clearPass" name="clearPass" placeholder="Password:">
                    </div>
                                                            <div class="form-group pull-right">
                        <button type="submit" class="btn btn-default btn-lg" onClick="transmit_form()"><i class="fa fa-sign-in"></i>&nbsp;&nbsp;Login</button>
                    </div>
                </div>
                <div class="col-sm-12 text-center">
                    <p class="small">
                        <a href="../../acknowledge_license_cert.html" target="main">Acknowledgments, Licensing and Certification</a>
                    </p>
                </div>
                <div class="product-registration-modal" style="display: none">
                    <p class="context">Register your installation with OEMR to receive important notifications, such as security fixes and new release announcements.</p>
                    <input placeholder="email" type="email" class="email" style="width: 100%; color: black" />
                    <p class="message" style="font-style: italic"></p>
                </div>
            </div>
        </form>
    </div>
<center>Copyright &copy; 2018 OpenEmr </center>
</body>
</html>
