<?php
// Démarre une session pour gérer les utilisateurs connectés
session_start();

// Connexion à la base de données
$servername = "localhost";
$username = "ton_utilisateur_mysql";
$password = "ton_mot_de_passe";
$dbname = "nom_de_ta_base";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection échouée: " . $conn->connect_error);
}

// Traitement du formulaire d'inscription
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['inscription'])) {
    if (isset($_POST['username']) && isset($_POST['email']) && isset($_POST['password']) && isset($_POST['confirm'])) {
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = $_POST['password'];
        $confirm = $_POST['confirm'];

        // Vérification si les mots de passe sont identiques
        if ($password === $confirm) {
            // Hash du mot de passe avant de le stocker
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // Préparer la requête pour insérer les données de l'utilisateur
            $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $email, $hashed_password);

            if ($stmt->execute()) {
                // Inscription réussie, rediriger vers la page d'accueil
                header("Location: accueil.php");
                exit();
            } else {
                echo "Erreur lors de l'inscription: " . $stmt->error;
            }
            $stmt->close();
        } else {
            echo "Les mots de passe ne correspondent pas.";
        }
    }
}

// Traitement du formulaire de connexion
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['connexion'])) {
    if (isset($_POST['login_username']) && isset($_POST['login_password'])) {
        $login_username = $_POST['login_username'];
        $login_password = $_POST['login_password'];

        // Vérifier les informations d'identification
        $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $login_username);
        $stmt->execute();
        $stmt->bind_result($user_id, $stored_password);

        if ($stmt->fetch()) {
            // Vérification du mot de passe
            if (password_verify($login_password, $stored_password)) {
                // Authentification réussie, démarrer une session
                $_SESSION['user_id'] = $user_id; // Stocker l'ID utilisateur dans la session
                $_SESSION['username'] = $login_username; // Stocker le nom d'utilisateur dans la session

                // Rediriger vers la page d'accueil après la connexion réussie
                header("Location: accueil.html");
                exit();
            } else {
                echo "Nom d'utilisateur ou mot de passe incorrect.";
            }
        } else {
            echo "Utilisateur non trouvé.";
        }
        $stmt->close();
    }
}

// Fermer la connexion à la base de données
$conn->close();
?>