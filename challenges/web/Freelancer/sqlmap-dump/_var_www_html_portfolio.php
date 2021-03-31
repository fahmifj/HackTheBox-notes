<?php
// Include config file
require_once "administrat/include/config.php";
?>
  <link rel="icon" href="favicon.ico" type="image/x-icon">
  <link href="vendor/fontawesome-free/css/all.min.css" rel="stylesheet" type="text/css">
  <!-- Portfolio Modals -->

  <!-- Portfolio Modal 1 -->
 
    <div class="modal-dialog modal-xl" role="document">
      <div class="modal-content">
 
        <div class="modal-body text-center">
          <div class="container">
            <div class="row justify-content-center">
              <div class="col-lg-8">
                <!-- Portfolio Modal - Title -->
                <!-- Icon Divider -->
                <div class="divider-custom">
 
                <!-- Portfolio Modal - Image -->
                <img class="img-fluid rounded mb-5" src="img/portfolio/cabin.png" width="300" height="300">
                <!-- Portfolio Modal - Text -->
                <p class="mb-5"><?php
 
$id = isset($_GET['id']) ? $_GET['id'] : '';
 
$query = "SELECT * FROM portfolio WHERE id = $id";
if ($result = mysqli_query($link, $query)) {

    /* fetch associative array */
    while ($row = mysqli_fetch_row($result)) {
        printf ("%s - %s\n", $row[1], $row[2]);
    }

    /* free result set */
    mysqli_free_result($result);
}

/* close connection */
mysqli_close($link);
?></p>
 
 
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
 
