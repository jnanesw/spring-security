🔐 Spring Security JWT Authentication Project
A Spring Boot application demonstrating stateless authentication and authorization using Spring Security and JSON Web Tokens (JWT).
This project showcases best practices for securing REST APIs, including password hashing with BCrypt, custom filters, and exception handling.

✨ Features
- ✅ User authentication with JWT (login endpoint issues tokens)
- ✅ Stateless API security (no HTTP sessions)
- ✅ Custom AuthTokenFilter to validate tokens on each request
- ✅ Custom AuthenticationEntryPoint to return JSON error responses for unauthorized access
- ✅ Password hashing with BCrypt (secure storage, salted & adaptive)
- ✅ H2 in‑memory database with schema.sql for users and authorities tables
- ✅ Role‑based access control with Spring Security annotations (@PreAuthorize)
- ✅ Secure HTTP headers (X-Frame-Options, etc.)

🏗️ Project Structure
src/main/java/com/example/security
 ├── config
 │    └── SecurityConfig.java        # Security filter chain configuration
 ├── controller
 │    └── AuthController.java        # Authentication endpoint
 ├── filter
 │    └── AuthTokenFilter.java       # Custom JWT validation filter
 ├── exception
 │    └── CustomAuthEntryPoint.java  # Handles unauthorized access
 ├── model
 │    └── User.java                  # User entity
 ├── repository
 │    └── UserRepository.java
 ├── service
 │    └── UserDetailsServiceImpl.java
 └── util
      └── JwtUtil.java               # JWT generation & validation



⚙️ Tech Stack
- Spring Boot 3+
- Spring Security
- JWT (jjwt library)
- H2 Database (for demo)
- Maven

🚀 Getting Started
1. Clone the repository
git clone https://github.com/your-username/spring-security-jwt.git
cd spring-security-jwt


2. Run the application
mvn spring-boot:run


3. Access H2 Console (for dev only)
- URL: http://localhost:8080/h2-console
- JDBC URL: jdbc:h2:mem:testdb
- User: sa
- Password: (leave blank)

🔑 Authentication Flow
- Login
- Endpoint: POST /authenticate
- Request body:
{
  "username": "jnaneswar",
  "password": "password"
}
- Response:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR..."
}
- Access Protected Endpoint
- Add header:
Authorization: Bearer <token>
- Example: GET /api/secure-data

🗄️ Database Schema (H2)
CREATE TABLE users (
    username VARCHAR(50) NOT NULL PRIMARY KEY,
    password VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL
);

CREATE TABLE authorities (
    username VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY(username) REFERENCES users(username)
);

CREATE UNIQUE INDEX ix_auth_username ON authorities (username, authority);

🔒 Security Highlights
- BCrypt for password hashing (adaptive, salted, industry standard).
- JWT for stateless authentication.
- Custom filters (AuthTokenFilter) to validate tokens.
- Custom entry point (CustomAuthEntryPoint) for clean JSON error responses.
- Role-based authorization with @PreAuthorize.

📌 Next Steps
- Add refresh tokens for long-lived sessions.
- Integrate with a persistent DB (PostgreSQL/MySQL).
- Add unit/integration tests for security flows.

👨‍💻 Author
Built with ❤️ by Jnaneswar while exploring Spring Security best practices.

👉 This README is ready to drop into your repo. Do you want me to also create a sample data.sql with a preloaded user (BCrypt‑encoded password) so anyone cloning your project can log in immediately?
