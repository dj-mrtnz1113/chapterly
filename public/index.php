<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
require_once 'db.php';

$app = new \Slim\App;

// User registration endpoint
$app->post('/register', function (Request $request, Response $response) {
    $data = $request->getParsedBody();

    // Validate input data
    $username = isset($data['username']) ? trim($data['username']) : null;
    $password = isset($data['password']) ? trim($data['password']) : null;
    $role_id = isset($data['role_id']) ? (int)$data['role_id'] : null;

    if (!$username || !$password || !$role_id) {
        $response->getBody()->write(json_encode(['error' => 'Invalid input. All fields are required.']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    try {
        $db = new Db();
        $conn = $db->connect();

        // Check if username already exists
        $checkUserQuery = "SELECT * FROM users WHERE username = :username";
        $stmt = $conn->prepare($checkUserQuery);
        $stmt->bindParam(':username', $username);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $response->getBody()->write(json_encode(['error' => 'Username already exists.']));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        // Insert the new user
        $query = "INSERT INTO users (username, password, role_id) VALUES (:username, :password, :role_id)";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->bindParam(':role_id', $role_id);
        $stmt->execute();

        $response->getBody()->write(json_encode(['message' => 'User registered successfully.']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(['error' => 'Database error: ' . $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    } finally {
        $db = null;
    }
});

$app->run();
?>
