<?php
$server = 'sql5.freesqldatabase.com';
$username = 'sql5706169';
$password = 'jdvXSsNUgl';
$database = 'sql5706169';

//check
// Check if any POST data is set (this condition might not be necessary for a welcome page)
if (isset($_POST)) {
    // Attempt to establish a connection to the database
    $conn = new mysqli($server, $username, $password, $database);

    // Check if the connection was successful
    if ($conn->connect_error) {
        die('Connection failed: ' . $conn->connect_error);
    } else {
        // Connection successful
        // You can perform further actions here if needed
        // For example, fetching user data from the database
    }
} else {
    //  // Handle the case where no POST data is set (if applicable)
    echo "No POST data received.";
}
?>
