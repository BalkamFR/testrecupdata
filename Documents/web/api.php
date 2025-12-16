<?php
// api.php - VERSION ULTIME (Login, Message, Options, Liste Users)
header('Content-Type: application/json');
require 'db.php';

// Augmentation mémoire pour les images Base64
ini_set('memory_limit', '256M');

// Récupération input (supporte JSON et POST Form)
$action = $_POST['action'] ?? '';
if (empty($action)) {
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';
} else {
    $input = $_POST;
}

$response = ['status' => 'error', 'message' => 'Action inconnue'];

// --- 1. LOGIN / INSCRIPTION ---
if ($action === 'login') {
    $login = trim($input['login'] ?? '');
    $pass = $input['password'] ?? '';
    if ($login && $pass) {
        $stmt = $pdo->prepare("SELECT * FROM projet42_users WHERE login = ?");
        $stmt->execute([$login]);
        $user = $stmt->fetch();
        if (!$user) {
            // Inscription
            $hashed_pass = password_hash($pass, PASSWORD_DEFAULT);
            // CORRECTION: Compte désactivé par défaut (doit être validé par un admin)
            $stmt = $pdo->prepare("INSERT INTO projet42_users (login, password, is_active) VALUES (?, ?, FALSE)");
            $stmt->execute([$login, $hashed_pass]);
            $response = ['status' => 'success', 'message' => 'Compte créé. Attendez la validation par un admin.', 'user_id' => $pdo->lastInsertId(), 'is_admin' => false, 'is_active' => false];
        } else {
            // Connexion
            if (password_verify($pass, $user['password'])) {
                $is_active = $user['is_active'] ?? true;
                $is_admin = $user['is_admin'] ?? false;
                $response = [
                    'status' => 'success',
                    'message' => 'Connecté',
                    'user_id' => $user['id'],
                    'is_admin' => $is_admin,
                    'is_active' => $is_active
                ];
            } else {
                $response = ['status' => 'error', 'message' => 'Mauvais mot de passe'];
            }
        }
    }
}

// --- 2. RÉCUPÉRER LA LISTE DES UTILISATEURS (Pour la Sidebar) ---
if ($action === 'get_users') {
    $my_id = $input['user_id'] ?? 0;

    // Récupérer les infos de l'utilisateur connecté pour vérifier s'il est admin
    $stmt = $pdo->prepare("SELECT is_admin FROM projet42_users WHERE id = ?");
    $stmt->execute([$my_id]);
    $me = $stmt->fetch();
    $is_admin = $me['is_admin'] ?? false;

    // Récupérer tous les utilisateurs avec leurs infos
    if ($is_admin) {
        $stmt = $pdo->prepare("SELECT id, login, is_active, is_admin FROM projet42_users ORDER BY login ASC");
    } else {
        // CORRECTION: On retourne la même structure pour tout le monde pour éviter les bugs JS
        // Mais on filtre uniquement les actifs pour les non-admins
        $stmt = $pdo->prepare("SELECT id, login, is_active, is_admin FROM projet42_users WHERE is_active = TRUE ORDER BY login ASC");
    }
    $stmt->execute();
    $users = $stmt->fetchAll();

    $response = ['status' => 'success', 'users' => $users, 'is_admin' => $is_admin];
}

// --- 3. ENVOYER UN MESSAGE (Avec Options) ---
if ($action === 'send_message') {
    $sender_id = $input['sender_id'] ?? 0;
    $receiver_login = $input['receiver_login'] ?? '';

    // Vérifier si l'utilisateur est actif
    $stmt = $pdo->prepare("SELECT is_active FROM projet42_users WHERE id = ?");
    $stmt->execute([$sender_id]);
    $sender = $stmt->fetch();

    if (!$sender || !$sender['is_active']) {
        $response = ['status' => 'error', 'message' => 'Votre compte est désactivé. Vous ne pouvez pas envoyer de messages.'];
    } else {

        // Paramètres custom
        $duration = (int) ($input['duration'] ?? 10);
        $color = $input['color'] ?? '#00ff00';
        $size = (int) ($input['size'] ?? 40);

        $type = 'text';
        $content = '';

        // Gestion Image
        if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
            $type = 'image';
            $ext = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
            $filename = uniqid('img_') . '.' . $ext;

            // Création dossier si inexistant
            if (!is_dir(__DIR__ . '/uploads/'))
                mkdir(__DIR__ . '/uploads/', 0777, true);

            move_uploaded_file($_FILES['image']['tmp_name'], __DIR__ . '/uploads/' . $filename);
            $content = __DIR__ . '/uploads/' . $filename;
        } else {
            $content = htmlspecialchars($input['message'] ?? '');
        }

        // Récup ID destinataire
        $stmt = $pdo->prepare("SELECT id FROM projet42_users WHERE login = ?");
        $stmt->execute([$receiver_login]);
        $receiver = $stmt->fetch();

        if ($receiver) {
            $stmt = $pdo->prepare("INSERT INTO projet42_messages (sender_id, receiver_id, message, type, duration, color, size) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$sender_id, $receiver['id'], $content, $type, $duration, $color, $size]);
            $response = ['status' => 'success', 'message' => 'Message envoyé !'];
        } else {
            $response = ['status' => 'error', 'message' => 'Destinataire introuvable.'];
        }
    }
}

// --- 4. RÉCUPÉRER LES MESSAGES NON LUS (Pour l'extension) ---
if ($action === 'get_unread') {
    $my_id = $input['user_id'] ?? 0;

    $sql = "SELECT m.id, m.message, m.type, m.duration, m.color, m.size, u.login as sender 
            FROM projet42_messages m 
            JOIN projet42_users u ON m.sender_id = u.id 
            WHERE m.receiver_id = ? AND m.is_read = FALSE";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([$my_id]);
    $messages = $stmt->fetchAll();

    // Conversion Images en Base64 pour éviter les problèmes de droits/URL
    foreach ($messages as &$msg) {
        if ($msg['type'] === 'image') {
            $path = $msg['message'];
            if (file_exists($path)) {
                $data = file_get_contents($path);
                $msg['message'] = base64_encode($data);
            } else {
                $msg['type'] = 'text';
                $msg['message'] = "[Image introuvable sur le serveur]";
            }
        }
    }

    // Marquer comme lu
    if ($messages) {
        $ids = array_column($messages, 'id');
        $in = str_repeat('?,', count($ids) - 1) . '?';
        $pdo->prepare("UPDATE projet42_messages SET is_read = TRUE WHERE id IN ($in)")->execute($ids);
    }
    $response = ['status' => 'success', 'messages' => $messages];
}

// --- 5. SUPPRIMER UN UTILISATEUR (Admin uniquement) ---
if ($action === 'delete_user') {
    $admin_id = $input['admin_id'] ?? 0;
    $user_id_to_delete = $input['user_id'] ?? 0;

    // Vérifier que l'utilisateur est admin
    $stmt = $pdo->prepare("SELECT is_admin FROM projet42_users WHERE id = ?");
    $stmt->execute([$admin_id]);
    $admin = $stmt->fetch();

    if ($admin && $admin['is_admin']) {
        // Empêcher la suppression de son propre compte
        if ($admin_id == $user_id_to_delete) {
            $response = ['status' => 'error', 'message' => 'Vous ne pouvez pas supprimer votre propre compte.'];
        } else {
            // Supprimer les messages de l'utilisateur
            $pdo->prepare("DELETE FROM projet42_messages WHERE sender_id = ? OR receiver_id = ?")->execute([$user_id_to_delete, $user_id_to_delete]);

            // Supprimer l'utilisateur
            $stmt = $pdo->prepare("DELETE FROM projet42_users WHERE id = ?");
            $stmt->execute([$user_id_to_delete]);

            $response = ['status' => 'success', 'message' => 'Utilisateur supprimé avec succès.'];
        }
    } else {
        $response = ['status' => 'error', 'message' => 'Accès refusé. Vous devez être administrateur.'];
    }
}

// --- 6. ACTIVER/DÉSACTIVER UN UTILISATEUR (Admin uniquement) ---
if ($action === 'toggle_user_status') {
    $admin_id = $input['admin_id'] ?? 0;
    $user_id_to_toggle = $input['user_id'] ?? 0;
    $new_status = $input['is_active'] ?? true;

    // Vérifier que l'utilisateur est admin
    $stmt = $pdo->prepare("SELECT is_admin FROM projet42_users WHERE id = ?");
    $stmt->execute([$admin_id]);
    $admin = $stmt->fetch();

    if ($admin && $admin['is_admin']) {
        // Empêcher la désactivation de son propre compte
        if ($admin_id == $user_id_to_toggle) {
            $response = ['status' => 'error', 'message' => 'Vous ne pouvez pas désactiver votre propre compte.'];
        } else {
            // DEBUG LOGGING
            $log = date('Y-m-d H:i:s') . " - Action: toggle_user_status\n";
            $log .= "Input is_active: " . ($input['is_active'] ?? 'N/A') . "\n";
            $log .= "New Status (raw): " . $new_status . "\n";
            $log .= "New Status (bool): " . ($new_status ? 'TRUE' : 'FALSE') . "\n";
            file_put_contents('debug_log.txt', $log, FILE_APPEND);

            $stmt = $pdo->prepare("UPDATE projet42_users SET is_active = ? WHERE id = ?");
            $val = $new_status ? 1 : 0;
            $stmt->execute([$val, $user_id_to_toggle]);

            $log = "Executing update with value: $val for user $user_id_to_toggle\n----------------\n";
            file_put_contents('debug_log.txt', $log, FILE_APPEND);

            $status_text = $new_status ? 'activé' : 'désactivé';
            $response = ['status' => 'success', 'message' => "Utilisateur $status_text avec succès ($val)."];
        }
    } else {
        $response = ['status' => 'error', 'message' => 'Accès refusé. Vous devez être administrateur.'];
    }
}

echo json_encode($response);
?>