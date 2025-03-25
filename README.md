# auth-micro

# Authentication Microservice

A standalone authentication microservice built with Node.js, Express, Passport, and JSON Web Tokens (JWT). This service supports both traditional username/password login and one‑click sign‑ins via Google OAuth 2.0.

## Features

- **Local Authentication:**  
  Secure login using username/password with bcrypt for password hashing and JWT for session management.

- **Google OAuth 2.0 Integration:**  
  One‑click sign‑in with Google. Users are redirected to Google’s consent screen and, on success, a JWT is issued.

- **Protected Endpoints:**  
  Middleware to verify JWT tokens, ensuring that only authenticated users can access protected resources.

- **Environment-Based Configuration:**  
  Uses environment variables to securely manage sensitive credentials (Google Client ID, Client Secret, etc.).

## Table of Contents

- [Installation](#installation)
- [Environment Setup](#environment-setup)
- [Usage](#usage)
  - [Local Login Flow](#local-login-flow)
  - [Google OAuth Flow](#google-oauth-flow)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/auth-microservice.git
   cd auth-microservice
