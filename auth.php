<?php

$conn = new mysqli('localhost', 'root', '', 'store_db');
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$error = '';  

function handleLogin($conn, &$error) {
    if (isset($_POST['login'])) {
        $email = $_POST['email'];
        $password = $_POST['password'];

        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                session_start();
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['first_name'] = $user['first_name'];
                echo "<script>alert('Login successful.'); window.location.href = 'index.html';</script>";
            } else {
                $error = 'Invalid email or password.';
            }
        } else {
            $error = 'Invalid email or password.';
        }
    }
}


function handleSignup($conn, &$error) {
    if (isset($_POST['signup'])) {
        $first_name = $_POST['first_name'];
        $last_name = $_POST['last_name'];
        $email = $_POST['email'];
        $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $error = 'Email is already registered.';
        } else {
            $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $first_name, $last_name, $email, $password);
            if ($stmt->execute()) {
                echo "<script>alert('Signup successful. Please login.'); window.location.href = 'index.html';</script>";
            } else {
                $error = 'Error signing up. Please try again.';
            }
        }
    }
}


function handleForgotPassword($conn, &$error) {
    if (isset($_POST['reset_password'])) {
        $email = $_POST['email'];
        $error = "A password reset link has been sent to $email.";
    }
}

$page = isset($_GET['page']) ? $_GET['page'] : 'login';

switch ($page) {
    case 'login':
        handleLogin($conn, $error);
        break;
    case 'signup':
        handleSignup($conn, $error);
        break;
    case 'forgot_password':
        handleForgotPassword($conn, $error);
        break;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Signup - Hamilton E-commerce</title>
  <link rel="stylesheet" href="css/styles.css">
  <link rel="stylesheet" href="css/mobile.css">
  <link rel="stylesheet" href="css/tablet.css">
  <link rel="stylesheet" href="css/signin.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</head>

<body>

<header>
    <div class="header">
      <div class="logo">
        <a href="index.html">
          <img src="imgs/logo.png" alt="Hamilton E-commerce Logo" class="logo-img">
        </a>
      </div>
        <h1>Hamilton E-commerce</h1>
      </div>
      <nav>
        <ul>
          <li><a href="index.html">Home</a></li>
          <li><a href="">Products</a></li>
          <li><a href="">Cart</a></li>
          <li><a href="">About</a></li>
          <li><a href="">Contact</a></li>
          <li><a href="auth.php">Sign in</a></li>
        </ul>
      </nav>
 
      
    </div>
    <div class="SearchBar">
      <input type="text" placeholder="Clothes">
      <button type="button">Search</button>
    </div>
    </div>
   
  </header>

<main>
<div id="success-message" class="success-message" style="display:none;"></div>
  <?php if ($page == 'login'): ?>
      <div class="signup-container">
          <h2 class="signup-header">Login</h2>
          
          <?php if (!empty($error)): ?>
              <div class="error-message"><?php echo $error; ?></div>
          <?php endif; ?>
          <form action="auth.php?page=login" method="POST" class="signup-form">
              <div class="form-group">
                  <label for="email">Email:</label>
                  <input type="email" name="email" required>
              </div>
              <div class="form-group">
                  <label for="password">Password:</label>
                  <input type="password" name="password" required>
              </div>
              <button type="submit" name="login">Login</button>
          </form>
          <div class="login-options">
              <p>New user? <a href="auth.php?page=signup">Sign up here</a></p>
              <p><a href="auth.php?page=forgot_password">Forgot your password?</a></p>
          </div>
      </div>

  <?php elseif ($page == 'signup'): ?>
      <div class="signup-container">
          <h2 class="signup-header">Signup</h2>
          
          <?php if (!empty($error)): ?>
              <div class="error-message"><?php echo $error; ?></div>
          <?php endif; ?>
          <form action="auth.php?page=signup" method="POST" class="signup-form">
              <div class="form-group">
                  <label for="first_name">First Name:</label>
                  <input type="text" id="first_name" name="first_name" required>
              </div>
              <div class="form-group">
                  <label for="last_name">Last Name:</label>
                  <input type="text" id="last_name" name="last_name" required>
              </div>
              <div class="form-group">
                  <label for="email">Email:</label>
                  <input type="email" id="email" name="email" required>
              </div>
              <div class="form-group">
                  <label for="password">Password:</label>
                  <input type="password" id="password" name="password" required>
              </div>
              <button type="submit" name="signup">Signup</button>
          </form>
          <div class="login-options">
              <p>Already registered? <a href="auth.php?page=login">Login here</a></p>
          </div>
      </div>

  <?php elseif ($page == 'forgot_password'): ?>
      <div class="signup-container">
          <h2 class="signup-header">Forgot Password</h2>
          
          <?php if (!empty($error)): ?>
              <div class="error-message"><?php echo $error; ?></div>
          <?php endif; ?>
          <form action="auth.php?page=forgot_password" method="POST" class="signup-form">
              <div class="form-group">
                  <label for="email">Email:</label>
                  <input type="email" name="email" required>
              </div>
              <button type="submit" name="reset_password">Reset Password</button>
          </form>
          <div class="login-options">
              <p>Remembered? <a href="auth.php?page=login">Login here</a></p>
          </div>
      </div>
  <?php endif; ?>
</main>


<footer>
    <div class="Footer">
      <div class="Footer-links">
        <h5>Quick Links</h5>
        <ul>
          <li><a href="#">Home</a></li>
          <li><a href="#">Products</a></li>
          <li><a href="#">About Us</a></li>
          <li><a href="#">Contact</a></li>
        </ul>
      </div>
      <div class="footer-contact">
        <h5>Contact Us</h5>
        <p>123 Street, Hamilton, ON</p>
        <p>+1 123 000 7800</p>
      </div>
      <div class="footer-logo">
        <a href="index.html">
          <img src="imgs/logo.png" alt="Hamilton E-commerce Logo" class="logo-img">
        </a>
      </div>
      <div class="footer-social">
        <h5>Follow Us</h5>
        <a href="https://facebook.com" target=""><i class="fab fa-facebook"></i></a>
        <a href="https://twitter.com" target=""><i class="fab fa-twitter"></i></a>
        <a href="https://instagram.com" target=""><i class="fab fa-instagram"></i></a>
        <a href="https://linkedin.com" target=""><i class="fab fa-linkedin"></i></a>
      </div>
    </div>
  </footer>

</body>
</html>
