<?php

session_start();

/* ================= CONEXION SQL SERVER ================= */

$serverName = "localhost";

$connectionOptions = array(

    "Database" => "EMI_DB",
    "Uid" => "sa",
    "PWD" => "12345",
    "CharacterSet" => "UTF-8"

);

$conn = sqlsrv_connect($serverName, $connectionOptions);

if(!$conn){

    die("Error de conexión");

}

/* ================= LOGIN ================= */

if(isset($_POST['login'])){

    $usuario = $_POST['usuario'];
    $password = $_POST['password'];

    $sql = "SELECT * FROM usuarios 
            WHERE usuario = ? 
            AND password = ?";

    $params = array($usuario, $password);

    $stmt = sqlsrv_query($conn, $sql, $params);

    if(sqlsrv_has_rows($stmt)){

        $_SESSION['usuario'] = $usuario;

        header("Location: panel.php");

    }else{

        echo "<script>
        alert('Usuario o contraseña incorrectos');
        window.location='index.php';
        </script>";

    }

}

?>