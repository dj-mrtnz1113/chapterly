document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const toggleSwitch = document.querySelector('.toggle');

    // Handle Login form submission
    loginForm.addEventListener('submit', function (e) {
        e.preventDefault();
        
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        // Validate user input
        if (username.trim() === '' || password.trim() === '') {
            alert('Please fill out all fields.');
            return;
        }

        // Hash the password before sending (for security)
        const hashedPassword = sha256(password);  // Using the sha256 function

        // Prepare the data to be sent to the server (AJAX request)
        const loginData = {
            username: username,
            password: hashedPassword
        };

        // Example of sending the data to the server using Fetch API for login
        fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(loginData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.message === 'Login successful') {
                alert('Login successful!');
                // Optionally, redirect the user to a dashboard or home page
                window.location.href = '/dashboard';  // Example redirect
            } else {
                alert('Login failed: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error during login:', error);
            alert('An error occurred. Please try again.');
        });
    });

    // Handle Register form submission
    registerForm.addEventListener('submit', function (e) {
        e.preventDefault();

        const username = document.getElementById('register-username').value;
        const password = document.getElementById('register-password').value;

        // Validate user input
        if (username.trim() === '' || password.trim() === '') {
            alert('Please fill out all fields.');
            return;
        }

        // Password validation (ensure minimum length)
        if (password.length < 6) {
            alert('Password should be at least 6 characters long.');
            return;
        }

        // Hash the password using SHA-256 (or any other method)
        const hashedPassword = sha256(password);  // Example of password hashing function

        // Prepare the data to be sent to the server (AJAX request)
        const registerData = {
            username: username,
            password: hashedPassword
        };

        // Example of sending the data to the server using Fetch API for registration
        fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(registerData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.message === 'User registered successfully.') {
                alert('Registration successful! Please log in.');
                // You can redirect to the login page here or automatically trigger login
                window.location.href = '/login';  // Example redirect
            } else {
                alert('Registration failed: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error during registration:', error);
            alert('An error occurred. Please try again.');
        });
    });
});

// Example function for password hashing (SHA-256)
function sha256(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    return crypto.subtle.digest('SHA-256', data).then(hashBuffer => {
        const hashArray = Array.from(new Uint8Array(hashBuffer)); 
        const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
        return hashHex; // Return hashed password
    });
}
