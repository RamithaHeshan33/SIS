<?php
session_start();
include_once('connection.php');

if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    if (empty($username) || empty($password)) {
        $message = 'Please Fill ';
        if (empty($username)) $message .= 'Username ';
        if (empty($password)) $message .= 'Password ';
        echo "<script>alert('$message'); window.location='index.php';</script>";
        exit;
    } else {
        // Use prepared statements to prevent SQL injection
        $stmt = $conn->prepare("SELECT * FROM `login_tbl` WHERE `username` = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $storedUsername = $row['username'];
            $storedPassword = $row['password']; // Assume this is hashed

            // Use password_verify to check hashed password
            if (password_verify($password, $storedPassword)) {
                $_SESSION['name'] = $row['name'];
                $_SESSION['username'] = $storedUsername;
                header('Location: welcome.php');
                exit;
            } else {
                echo "<script>alert('Invalid Username or Password'); window.location='index.php';</script>";
                exit;
            }
        } else {
            echo "<script>alert('Invalid Username or Password'); window.location='index.php';</script>";
            exit;
        }
    }
}
?>
