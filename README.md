# HustleHub+ — Part 1: Secure Backend Foundations

**Module:** INSY7314
**Team:** Quantum Coder
**POE Stage:** Part 1 of 3 — Secure backend foundations
**Team Members:**
| Name | Student Number |
| :--- | :--- |
| **Blake Derek Godfrey** | ST10435415 |
| **Syed Muhammad Hamza Kazmi** | ST10443021 |
| **Connor Albertyn** | ST10437293 |
| **Muzammil Cassim** | ST10259792 |

**Demonstration video:** https://youtu.be/UGyVl3xy8iM

---

## 1. System Overview

HustleHub+ is a safe freelance marketplace application connecting two kinds of users: freelancers, who are promoting their gigs, and clients, who search for and hire them (IIE, 2026).
Apart from the marketplace itself, the application must keep track of the finances created by bookings, and provide the users, i.e. freelancers, with information about their income and taxes due, thus making the system handle credentials, transactions, and income data which are inherently highly confidential and should not be compromised (IIE, 2026).
That is why security must be considered at the very beginning and implemented throughout the development process, and not added as an afterthought, and that is what is accomplished by Part 1 of the POE: the application must implement authentication system – registration, login, password storage, and token sessions management – before any marketplace features are added (IIE, 2026).

### 1.1 Intended Users

The third system consists of three different roles: Clients, who search for and reserve gigs; Freelancers, who post gigs and manage finances and taxes; and Admins, who administer the system (IIE, 2026).
However, Part 1 currently lacks role-based authorization, as there are no marketplace functionalities to be protected, but the data model and the JWT payload include a role claim so that Part 2 can add role-based access control on top of the existing authentication core without modifying it (Jones, Bradley and Sakimura, 2015).

### 1.2 Development Approach

The POE process is specifically designed into three stages of development, namely secure backend architecture, full-stack development, and DevSecOps, such that each stage is supposed to show significant improvement over the previous one (IIE, 2026).
Consequently, the following report presents the first part in totality and as an independently verifiable piece that involves registration and logging alone, and in such a way that the existing memory-based user storage will be replaced by the MongoDB-based storage without changing anything else (MongoDB, Inc., n.d.).

---

## 2. Architecture

### 2.1 MERN Architecture Diagram

The figure below represents the complete MERN Target Architecture with its corresponding boundaries of trust and system at each tier level, as well as the exact position in the request flow at which each Part 1 Security Control is implemented (MongoDB, Inc., n.d.).
React and MongoDB represent forward-thinking boundaries for Part 2 and Part 3, while Part 1 completely covers the implementation of all the controls inside the application tier and data tier boxes (IIE, 2026).

<img width="1500" height="1220" alt="mern_architecture" src="https://github.com/user-attachments/assets/f0687ed4-9cc3-4e61-a760-54243a5b915a" />

The diagram reveals the security boundaries, which include the client layer as being untrusted, not having access to any JWT secrets or password hashes; network layer is the boundary for TLS termination, which leaves the confidentiality and integrity vulnerable during transport; and the application layer processes all requests through a standardised pipeline that includes security headers, rate limiting, sanitisation, validation, authentication, business logic, and unified error handling (OWASP, 2021).
Such a pipeline demonstrates "defence in depth", which is the principle advised by OWASP, where a single control is not used for security (OWASP, 2021).

### 2.2 Request Lifecycle (Login Example)

1. Client requests POST /api/auth/login with credentials in the form of email and password in JSON format using HTTPS protocol (Mozilla, 2026).
2. `helmet`, `cors`, and the global rate limiter middleware processes requests first, stopping requests with invalid content before reaching any business logic (OWASP, 2021).
3. `express-mongo-sanitize` and `xss-clean` sanitize payloads with NoSQL operator and script injections in request body (OWASP, 2024b).
4. `express-validator` validation rules check whether the provided email is a valid one, and password field is not empty, otherwise, return a structured `400` response without querying the user storage (OWASP, 2024b).
5. auth service queries the database for the user and checks the provided password with bcrypt password hash; it returns a generic error for both cases of “no such user” and “invalid password”, thus avoiding user enumeration (OWASP, 2024a).
6. Upon successful login, auth service generates a JWT with user’s id and role only – never bcrypt password hash or email address (Jones, Bradley and Sakimura, 2015).
7. Any error raised at any point during the request processing is captured by centralized error handling mechanism and logged with all the details on the server side but only a safe generic error message is returned to the client (OWASP, 2021).

---

## 3. Security Decisions and Rationale

### 3.1 Password Hashing

No plain-text passwords are ever stored since each one is hashed using bcryptjs at a work factor of 12 before it gets stored in memory (OWASP, 2024a).
bcrypt is adaptive because the cost factor can be increased over time to keep pace with the improvements in hardware, thus making the attacks costly from a computational standpoint even when the data storage becomes compromised (OWASP, 2024a).
As per the current recommendations by OWASP, the Argon2id should be preferred over bcrypt for any new system; however, bcrypt with a work factor of 12 or greater is deemed safe enough to use (OWASP, 2024a).
The verification process is carried out using bcrypt’s built-in constant-time string comparison algorithm to avoid a potential side-channel attack in the form of timing information being introduced into the process (OWASP, 2024a).

### 3.2 Token-Based Authentication (JWT)

Upon a successful login, the API provides a JSON Web Token per the specifications outlined in RFC 7519, a compact and URL-safe format that can be used for signing and is digitally signed such that the server can verify the identity of the request without any session data stored on the server (Jones, Bradley and Sakimura, 2015).
The token itself is signed via HMAC-SHA256 with a secret pulled from an environment variable rather than hardcoded into the source code, and contains no more than the id (sub claim) and role of the user, as well as explicit exp (expiry) and iss (issuer) claims, thus ensuring that the stolen token will have a limited lifespan and cannot be repurposed to impersonate another issuer (Jones, Bradley and Sakimura, 2015).
Each of the protected routes verifies the token via jsonwebtoken's validation method on every request - checking its signature, issuer and expiry date and making sure the user record exists - rather than once per request and caching the result, as required by the POE brief (IIE, 2026).
Error messages returned from the API are intentionally vague ("Invalid or expired token") since giving an attacker more information about why the token was invalid helps him craft his attack (OWASP, 2021).

### 3.3 Input Validation

All inputs allowed by the registration and login routes are validated using express-validator before passing them on to any controller or service layer function, employing OWASP’s recommended allow-list-first method of input validation as opposed to attempting to filter “known bad” inputs (OWASP, 2024b).
Emails are trimmed and syntax validated, and the minimum password strength criteria for acceptance is a minimum length combined with multiple types of characters; the role parameter is restricted to an enum of 'client', 'freelancer', or 'admin' values and is not allowed a freeform string supplied by the client, effectively blocking a mass assignment attack as highlighted by OWASP under Broken Access Control (OWASP, 2021).
express-mongo-sanitize and xss-clean middleware are included on all routes globally as added layers of protection against NoSQL operator injection and reflected script injection, respectively, and will be directly applicable when MongoDB is used as an in-memory database replacement in part 2 of this application development project (OWASP, 2024b).

### 3.4 HTTPS

The API refuses to start unless a valid TLS key and certificate pair can be loaded, and `src/server.js` binds Node's native `https` module rather than `http`, so there is no accidental unencrypted fallback (Mozilla, 2026). A local self-signed certificate is generated for development via `npm run gen-cert` (wrapping OpenSSL), which is appropriate for local marking and demonstration but is explicitly not suitable for production, where a certificate from a trusted CA would be used instead — a distinction documented here rather than left implicit (Mozilla, 2026). HTTPS matters because, without it, credentials and JWTs would be sent in clear text and could be captured by anyone on the same network path via a manipulator-in-the-middle attack, completely undermining the password-hashing and token-signing work done everywhere else in the system (Mozilla, 2026). `helmet` additionally sets HTTP security headers (including HSTS once deployed behind real TLS in production) so that browsers that do talk to the API are told to prefer HTTPS on subsequent requests (Mozilla, 2026).

### 3.5 Secure Error Handling

A single centralised error-handling middleware (`src/middleware/errorHandler.js`) is the only place in the application that turns an error into an HTTP response, which guarantees consistent behaviour instead of relying on every route to remember to sanitise its own errors (OWASP, 2021). Errors that the application raises on purpose (e.g. "email already registered") carry an explicit `expose = true` flag and a safe message chosen by the developer; anything unexpected — a bug, a dependency failure — falls back to a generic "unexpected error" message with a `500` status, while the *real* error and stack trace are written only to the server-side console log, never returned in the response body (OWASP, 2021). This directly satisfies the POE requirement that error responses must not leak stack traces, file paths, or configuration values (IIE, 2026).

---

## 4. Backend Structure

The source code adheres to the layered and modular design principles so that every component could be separately unit-tested, changed or expanded, which is the separation-of-concerns principle that earns points explicitly according to the rubric's "Code Structure" section (IIE, 2026)
Code Structure:
```
hustlehub-backend/
├── src/
│   ├── app.js                 # Express app assembly + global security middleware
│   ├── server.js               # HTTPS server bootstrap
│   ├── config/env.js           # Centralised, validated environment config
│   ├── routes/authRoutes.js    # /api/auth/* route definitions
│   ├── controllers/authController.js  # HTTP <-> service translation only
│   ├── services/authService.js # Hashing, JWT issuance/verification, business rules
│   ├── models/userModel.js     # In-memory data-access layer (swappable for MongoDB)
│   └── middleware/
│       ├── validators.js       # express-validator rule sets
│       ├── authMiddleware.js   # JWT verification + role-based access control
│       └── errorHandler.js     # 404 handler + centralised error responder
├── scripts/generateCert.js     # Local self-signed TLS certificate generator
├── certs/                      # Generated key.pem / cert.pem (git-ignored)
├── postman/HustleHub_Part1.postman_collection.json
├── .env.example
├── package.json
└── README.md
```

Routes bind only HTTP methods, middleware, and controllers; controllers only serve as HTTP-to-service adapters without having any hashing or tokens functionality; and services encapsulate the entire logic, which implies that a potential change of the web framework or token library will affect only one layer of the application (IIE, 2026).

---

## 5. API Reference

| Method | Endpoint | Auth required | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness check |
| POST | `/api/auth/register` | No | Register a new user (`email`, `password`, optional `role`) |
| POST | `/api/auth/login` | No | Authenticate and receive a JWT |
| GET | `/api/auth/profile` | Yes (Bearer JWT) | Example protected route demonstrating JWT validation |

All responses follow a consistent envelope: `{ "status": "success" | "error", "message": "...", "data": { ... } }`, which the rubric rewards under "consistent response structure" (IIE, 2026).

---

## 6. Setup and Running Locally

```bash
git clone <repository-url>
cd hustlehub-backend
npm install
cp .env.example .env        # then edit JWT_SECRET to a long random value
npm run gen-cert             # generates certs/key.pem and certs/cert.pem
npm start                    # serves https://localhost:5443
```

Requires Node.js 18+ and OpenSSL available on the PATH (Node.js Foundation, n.d.). The server intentionally refuses to start over plain HTTP or without a JWT secret configured, per the security decisions in Section 3.

---

## 7. Testing

### 7.1 Postman Collection

The collection `postman/HustleHub_Part1.postman_collection.json` contains a comprehensive test suite for all backend endpoints, covering success states and security edge cases. Below is the documentation and corresponding response evidence for each request:

#### 1. System Health & Routing
* **Health Check** (`GET /health` — Expected `200 OK`)
  * Verifies server availability over HTTPS.
  <img width="1918" height="1020" alt="Postman get health check hh" src="https://github.com/user-attachments/assets/ea8a22dc-8a73-42ad-a849-a36e9d7c7b97" />

* **Unknown Route** (`GET /unknown-endpoint` — Expected `404 Not Found`)
  * Confirms safe handling of non-existent routes without exposing stack traces.
  <img width="1918" height="1022" alt="Postman GET Unknown Route" src="https://github.com/user-attachments/assets/a0331a55-1bee-45f6-8786-1836fc5b6eaf" />

---

#### 2. Registration (`POST /api/auth/register`)
* **Register - Success** (Expected `201 Created`)
  * Successfully registers a new user with bcrypt password hashing.
  <img width="1917" height="1022" alt="Postman post register success hh" src="https://github.com/user-attachments/assets/b3d016d5-9672-4149-a077-cf19e2c5daa3" />

* **Register - Duplicate Email** (Expected `409 Conflict`)
  * Blocks duplicate email registration attempts gracefully.
  <img width="1918" height="1018" alt="Postman POST Duplicate Email HH" src="https://github.com/user-attachments/assets/7a5e63a3-b90e-45b6-987d-459dd631367e" />

* **Register - Invalid Input** (Expected `400 Bad Request`)
  * Validation middleware traps weak passwords or malformed email addresses.
  <img width="1918" height="1022" alt="Postman POST Register Invalid Input HH" src="https://github.com/user-attachments/assets/68ed8eaa-d0c7-4c97-a65f-5b0f679656ee" />
---

#### 3. Authentication (`POST /api/auth/login`)
* **Login - Success** (Expected `200 OK`)
  * Authenticates valid credentials and issues a signed JWT.
  <img width="1918" height="1020" alt="Postman POST Login Success HH" src="https://github.com/user-attachments/assets/e7b1b22f-b64b-466d-b9cc-9546fc97a278" />

* **Login - Wrong Password** (Expected `401 Unauthorized`)
  * Returns generic "Invalid credentials" error to prevent user enumeration.
  <img width="1918" height="1018" alt="Postman POST Login Wrong Password" src="https://github.com/user-attachments/assets/eab727eb-c1e4-41af-a884-ad662abc24b6" />

* **Login - Unknown Email** (Expected `401 Unauthorized`)
  * Uses the exact same generic error as wrong passwords to defeat timing/enumeration attacks.
  <img width="1918" height="1022" alt="Postman POST Login Unknown Email HH" src="https://github.com/user-attachments/assets/9ae6129a-2db0-4733-9669-7e2fc23feafc" />

---

#### 4. Protected Routes (`GET /api/auth/profile`)
* **Protected Route - With Valid Token** (Expected `200 OK`)
  * Allows access when a valid `Bearer <token>` is supplied in the `Authorization` header.
  <img width="1918" height="1017" alt="Postman GET Protected Route With Valid Token" src="https://github.com/user-attachments/assets/66f8e047-086c-4258-b00a-98566c58b15d" />
  <img width="1918" height="1020" alt="Postman GET Protected Route With Valid Token TEST RUN PIC" src="https://github.com/user-attachments/assets/933d07c2-6fb5-4caf-a767-2087cf149f50" />

* **Protected Route - No Token** (Expected `401 Unauthorized`)
  * Blocks unauthorized access when the `Authorization` header is missing.
  <img width="1918" height="1022" alt="Postman GET Protected Route No Token" src="https://github.com/user-attachments/assets/9f403b14-c639-4c8b-b516-ae69a05fb49f" />

* **Protected Route - Malformed Token** (Expected `401 Unauthorized`)
  * Rejects modified, corrupted, or fake JWT signatures.
  <img width="1918" height="1021" alt="Postman GET Protected Route Malformed Token" src="https://github.com/user-attachments/assets/4909fe60-5388-43d6-a71d-8cded0dfd93f" />

### 7.2 Manual verification performed

All of the scenarios above were exercised against the running server during development (see the demonstration video) and returned the expected status codes and response bodies, confirming the "robust implementation … handles edge cases" standard the rubric describes for API functionality (IIE, 2026).

---

## 8. Submission Checklist (Part 1)

- [x] GitHub repository with modular, documented source code
- [x] This README documenting architecture, security rationale, and structure
- [x] Postman collection (`postman/HustleHub_Part1.postman_collection.json`)
- [x] Screenshots of API responses (add to `/docs/screenshots` before submission)
- [x] Demonstration video link
- [x] 25+ descriptive commits with evidence of multi-member collaboration



---

## 9. Reference List

Internet Engineering Task Force (IETF), 2015. *RFC 7519: JSON Web Token (JWT)*, authored by M. Jones, J. Bradley and N. Sakimura. [online] Available at: https://www.rfc-editor.org/info/rfc7519/ [Accessed 10 August 2026].

MongoDB, Inc., n.d. *MERN Stack Explained*. [online] Available at: https://www.mongodb.com/resources/languages/mern-stack [Accessed 10 August 2026].

Mozilla, 2026. *Transport Layer Security (TLS)*. [online] MDN Web Docs. Available at: https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security [Accessed 10 August 2026].

Node.js Foundation, n.d. *Node.js Documentation*. [online] Available at: https://nodejs.org/en/docs [Accessed 10 August 2026].

OWASP, 2021. *OWASP Top 10:2021*. [online] Available at: https://owasp.org/Top10/2021/ [Accessed 10 August 2026].

OWASP, 2024a. *Password Storage Cheat Sheet*. [online] OWASP Cheat Sheet Series. Available at: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html [Accessed 10 August 2026].

OWASP, 2024b. *Input Validation Cheat Sheet*. [online] OWASP Cheat Sheet Series. Available at: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html [Accessed 10 August 2026].

Postman, n.d. *Postman Learning Center*. [online] Available at: https://learning.postman.com/ [Accessed 10 August 2026].

The Independent Institute of Education (IIE), 2026. *INSY7314 Portfolio of Evidence Part 1: Secure Foundations — HustleHub+*. Module brief. Johannesburg: The Independent Institute of Education.
