<?php
// db.php
$host = 'pilaztd42.mysql.db'; // Ton serveur (pris sur l'image)
$db   = 'pilaztd42';           // Chez OVH le nom de la base = nom d'utilisateur souvent
$user = 'pilaztd42';           // Ton utilisateur
$pass = 'efRfqmdnNwDRm8c';     // Ton mot de passe (celui de l'image)
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
    
    // Migration automatique : ajouter les colonnes is_admin et is_active si elles n'existent pas
    try {
        $pdo->exec("ALTER TABLE projet42_users 
                    ADD COLUMN is_admin BOOLEAN DEFAULT FALSE,
                    ADD COLUMN is_active BOOLEAN DEFAULT TRUE");
    } catch (PDOException $e) {
        // Les colonnes existent déjà, pas de problème
    }
    
    // S'assurer que papilaz est admin
    $pdo->exec("UPDATE projet42_users SET is_admin = TRUE WHERE login = 'papilaz'");
    
} catch (\PDOException $e) {
    // En production, on évite d'afficher l'erreur exacte pour la sécurité, 
    // mais pour le debug c'est utile :
    die("Erreur de connexion : " . $e->getMessage());
}
?>
