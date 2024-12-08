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

    if (!$username || !$password) {
        // Send a response with error message
        $errorResponse = ['error' => 'Invalid input. All fields are required.'];
        $response->getBody()->write(json_encode($errorResponse));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    // Hash the password
    $hashedPassword = hash('sha256', $password);

    try {
        $db = new Database();
        $conn = $db->getConnection();

        // Check if username already exists
        $checkUserQuery = "SELECT * FROM users WHERE username = :username";
        $stmt = $conn->prepare($checkUserQuery);
        $stmt->bindParam(':username', $username);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            // Username already exists
            $errorResponse = ['error' => 'Username already exists.'];
            $response->getBody()->write(json_encode($errorResponse));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        // Insert the new user
        $query = "INSERT INTO users (username, password) VALUES (:username, :password)";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->execute();

        // Success response
        $successResponse = ['message' => 'User registered successfully.'];
        $response->getBody()->write(json_encode($successResponse));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);

    } catch (PDOException $e) {
        // Database error
        $errorResponse = ['error' => 'Database error: ' . $e->getMessage()];
        $response->getBody()->write(json_encode($errorResponse));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    } finally {
        $db = null;
    }
});

// Secret key for JWT
define('JWT_SECRET', 'your_secret_key');

// User authentication endpoint
$app->post('/login', function (Request $request, Response $response) {
    $data = $request->getParsedBody();

    // Validate input data
    $username = isset($data['username']) ? trim($data['username']) : null;
    $password = isset($data['password']) ? trim($data['password']) : null;

    if (!$username || !$password) {
        $response->getBody()->write(json_encode(['error' => 'Invalid input. Username and password are required.']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    try {
        $db = new Database();
        $conn = $db->getConnection();

        // Check if username exists
        $query = "SELECT * FROM users WHERE username = :username";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->execute();

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || hash('sha256', $password) !== $user['password']) {
            $response->getBody()->write(json_encode(['error' => 'Invalid username or password.']));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
        }

        // Generate JWT token
        $issuedAt = time();
        $expirationTime = $issuedAt + 3600; // Token valid for 1 hour
        $payload = [
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            'sub' => $user['userid'],
            'role' => $user['role_id'],
        ];

        $token = JWT::encode($payload, JWT_SECRET, 'HS256');

        // Set token in HTTP-only cookie
        setcookie('auth_token', $token, [
            'expires' => $expirationTime,
            'path' => '/',
            'domain' => '', // Set your domain here if needed
            'secure' => true, // Use HTTPS in production
            'httponly' => true,
            'samesite' => 'Strict',
        ]);

        $response->getBody()->write(json_encode(['message' => 'Login successful.']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(['error' => 'Database error: ' . $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    } finally {
        $db = null;
    }
});

$app->run();
?>
