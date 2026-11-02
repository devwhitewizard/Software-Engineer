# Authentication and Authorization API – Learning Project

## About This Project

This is my practical project focused on learning **authentication and authorization using Node.js and Express.js**.

Github link: https://github.com/manfraio/rest_api_auth_nodejs
Tutorial Link :

My goal is not just to make the API work.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Node.js | JavaScript runtime for the backend |
| Express.js | Building API routes and middleware |
| NeDB | Storing application data |
| bcryptjs | Hashing and comparing passwords |
| jsonwebtoken (JWT) | Creating and verifying authentication tokens |
| otplib | Generating and verifying 2FA codes |
| qrcode | Generating QR codes for 2FA setup |
| crypto | Cryptographic operations |
| node-cache | Temporary in-memory data storage |
| Postman | Testing API endpoints |

---

# 1. API Routes and What They Do

This section documents the main routes I created and what I am learning from each one.

## A. User Registration

**Route:** `POST /api/auth/register`

**Purpose:** Allows a new user to create an account.

What happens inside this route:

1. Receives user information from `req.body`.
2. Checks whether the required fields have been provided.
3. Checks whether the email is already registered.
4. Hashes the user's password using bcrypt.
5. Creates a new user in the database.
6. Assigns a default role, such as `member`.
7. Initializes the user's 2FA settings.

**Important concepts:**
- `req.body`
- Input validation
- `bcrypt.hash()`
- Database insertion
- Duplicate user checking
- Default values

## B. User Login

**Route:** `POST /api/auth/login`

**Purpose:** Allows an existing user to log in.

What happens inside this route:

1. Receives the user's email and password.
2. Searches the database for the user.
3. Checks whether the user exists.
4. Uses `bcrypt.compare()` to compare the submitted password with the stored password hash.
5. Checks whether the user has enabled 2FA.
6. If 2FA is not enabled, generates an access token and refresh token.
7. Saves the refresh token in the database.
8. Returns the authentication response to the client.

**Important concepts:**
- `bcrypt.compare()`
- User verification
- `jwt.sign()`
- Access tokens
- Refresh tokens
- Conditional statements

**Something I need to understand better:** How the login process should work when a user has enabled 2FA. My current implementation indicates that a TOTP is required, but the complete second-step login process still needs to be implemented.

## C. Refresh Token

**Route:** `POST /api/auth/refresh`

**Purpose:** Allows a user to obtain a new access token when the current access token expires, provided their refresh token is still valid.

What happens inside this route:

1. Receives a refresh token.
2. Verifies the refresh token using `jwt.verify()`.
3. Checks whether the token exists in the database.
4. Removes the old refresh token.
5. Generates a new access token and refresh token.
6. Saves the new refresh token.

This process is called **refresh token rotation**.

**Important concepts:**
- `jwt.verify()`
- Token expiration
- Refresh tokens
- Token rotation
- Database updates

## D. Generate 2FA QR Code

**Route:** `GET /api/auth/2fa/generate`

**Purpose:** Allows an authenticated user to start setting up two-factor authentication.

What happens inside this route:

1. Checks whether the user is authenticated using `ensureAuthenticated`.
2. Finds the user's account in the database.
3. Generates a 2FA secret using `authenticator.generateSecret()`.
4. Creates an authentication URL using `authenticator.keyuri()`.
5. Stores the secret in the user's database record.
6. Generates a QR code using the `qrcode` package.
7. Sends the QR code as a PNG image.

The user can scan the QR code using an authenticator application.

**Important concepts:**
- Two-factor authentication
- `authenticator.generateSecret()`
- `authenticator.keyuri()`
- QR code generation
- `qrcode.toBuffer()`
- Sending images as HTTP responses

## E. Validate 2FA OTP

**Route:** `POST /api/auth/2fa/validate`

**Purpose:** Checks whether the OTP submitted by the user is valid.

What happens inside this route:

1. Receives the OTP from `req.body`.
2. Finds the authenticated user.
3. Retrieves the user's stored 2FA secret.
4. Uses `authenticator.check()` to verify the submitted OTP.
5. If the OTP is valid, enables 2FA for the user.
6. Returns an appropriate response.

**Important concepts:**
- OTP (One-Time Password)
- TOTP (Time-Based One-Time Password)
- `authenticator.check()`
- Conditional statements
- Updating user records

## F. User Logout

**Route:** `POST /api/auth/logout`

**Purpose:** Allows an authenticated user to log out.

What happens inside this route:

1. Receives the logout request.
2. Identifies the user's tokens.
3. Removes the refresh token from the database.
4. Adds the access token to an invalid-token collection.
5. Returns a logout response.

**Why is this important?**

JWTs are usually stateless. This means that simply logging out does not automatically make an already-issued access token invalid.

By maintaining an invalid-token list, the application can reject tokens that have been logged out before their expiry.

**Important concepts:**
- Token invalidation
- Refresh token deletion
- Access token blacklisting
- Database updates
- Logout logic

## G. Get Current User

**Route:** `GET /api/users/current`

**Purpose:** Returns information about the currently authenticated user.

What happens inside this route:

1. The request passes through `ensureAuthenticated`.
2. The middleware verifies the access token.
3. The decoded user information is attached to `req.user`.
4. The route uses `req.user` to identify the current user.
5. The user's information is returned.

**Important concepts:**
- Protected routes
- Authentication middleware
- `req.user`
- `jwt.verify()`
- Bearer tokens

## H. Admin Route

**Route:** `GET /api/admin`

**Purpose:** Restricts access to users who have the administrator role.

What happens:

1. The user must first be authenticated.
2. The authorization middleware checks the user's role.
3. If the user has the `admin` role, access is granted.
4. Otherwise, the request is rejected.

**Important concepts:**
- Role-based authorization
- Middleware chaining
- User roles
- Access control

## I. Moderator Route

**Route:** `GET /api/moderator`

**Purpose:** Restricts access to users who have the moderator role.

The route uses authentication and authorization middleware to determine whether the user can access it.

**Important concepts:**
- Role-based access control
- Permissions
- Middleware
- User roles

---

# 2. Understanding the Middleware

## ensureAuthenticated

This middleware checks whether a request contains a valid access token.

Its responsibilities include:

1. Reading the authorization header.
2. Extracting the Bearer token.
3. Verifying the token using `jwt.verify()`.
4. Checking whether the token has been invalidated.
5. Attaching decoded user information to `req.user`.
6. Calling `next()` if the request passes the checks.

Example:

```js
function ensureAuthenticated(req, res, next) {
    // Authentication checks happen here.

    next();
}
```

The actual middleware contains the token verification and error handling.

## authorize(roles = [])

This middleware checks whether an authenticated user has permission to access a particular route.

For example:

```js
authorize(['admin'])
```

This means that the user must have the `admin` role to access the protected route.

The difference:

- `ensureAuthenticated` checks who the user is.
- `authorize()` checks what the user is allowed to access.

---

# 3. Important Concepts I'm Learning

## Authentication

Authentication answers:

**Who are you?**

It checks whether a user is who they claim to be.

Example: Checking email and password during login.

## Authorization

Authorization answers:

**What are you allowed to access?**

Example: An administrator can access an admin route, while an ordinary member cannot.

## Password Hashing

Passwords should not be stored as plain text.

I use `bcryptjs` to hash passwords before saving them.

```js
const hashedPassword = await bcrypt.hash(password, 10);
```

When a user logs in, I compare the submitted password with the stored hash:

```js
const isValid = await bcrypt.compare(
    password,
    user.password
);
```

## JWT (JSON Web Token)

JWT is used to represent information about an authenticated user.

**jwt.sign()**

Creates and signs a token.

```js
const token = jwt.sign(
    { userId: user._id },
    secret,
    { expiresIn: '15m' }
);
```

**jwt.verify()**

Checks whether a token has a valid signature and has not expired.

```js
const decoded = jwt.verify(token, secret);
```

## Access Tokens

An access token is used when a client requests a protected resource.

It is usually short-lived.

## Refresh Tokens

A refresh token allows the client to request a new access token without requiring the user to log in again, provided the refresh token remains valid.

## Middleware

Middleware is a function that runs during the Express request-response process.

It can inspect a request, perform checks, modify the request object, send a response, or pass control to the next middleware.

## The next() Function

`next()` tells Express to continue to the next middleware or route handler.

```js
function exampleMiddleware(req, res, next) {
    console.log('Middleware executed');

    next();
}
```

If middleware neither sends a response nor calls `next()`, the request may remain pending.

## Two-Factor Authentication (2FA)

2FA adds another verification step to the login process.

In this project, I am practising:

- Generating a 2FA secret.
- Creating a QR code.
- Scanning the QR code with an authenticator app.
- Verifying a TOTP.
- Enabling 2FA after successful verification.

---

# 4. How the Authentication Process Works

The general flow:

1. A user registers an account.
2. The password is hashed and stored.
3. The user logs in.
4. The server compares the submitted password with the stored hash.
5. If the credentials are valid, the server generates JWT tokens.
6. The client stores and sends the access token when accessing protected routes.
7. Authentication middleware verifies the token.
8. Authorization middleware checks the user's role when necessary.
9. If the user has the required permissions, the request continues.

For users with 2FA enabled, an additional OTP verification step is needed before completing login. This is an area I still need to practise and complete.

---

# 5. Testing the API with Postman

I use Postman to test my endpoints and understand how the server responds to different requests.

Things I practise:

- Sending POST requests for registration and login.
- Sending GET requests to protected routes.
- Sending JSON request bodies.
- Using Bearer Token authentication.
- Testing valid and invalid credentials.
- Testing access and refresh tokens.
- Testing logout.
- Testing routes with different user roles.
- Testing 2FA QR code generation.
- Testing OTP verification.

---

# 6. My Learning Roadmap

I want to understand each topic before moving to the next one.

- [ ] Understand Express routes.
- [ ] Understand `req` and `res`.
- [ ] Understand middleware.
- [ ] Understand `next()`.
- [ ] Understand user registration.
- [ ] Understand password hashing with bcrypt.
- [ ] Understand user login.
- [ ] Understand `jwt.sign()`.
- [ ] Understand `jwt.verify()`.
- [ ] Understand access tokens.
- [ ] Understand refresh tokens.
- [ ] Understand refresh token rotation.
- [ ] Understand logout and token invalidation.
- [ ] Understand authentication middleware.
- [ ] Understand authorization middleware.
- [ ] Understand user roles.
- [ ] Understand protected routes.
- [ ] Understand 2FA.
- [ ] Understand QR code generation.
- [ ] Understand OTP and TOTP verification.
- [ ] Complete the 2FA login flow.
- [ ] Practise testing all endpoints with Postman.

---

# 7. Questions I Should Be Able to Answer

As I continue practising, I want to be able to answer these questions without simply memorising the code.

### Registration and Login

1. Why do we hash passwords?
2. What is the difference between `bcrypt.hash()` and `bcrypt.compare()`?
3. Why do we check whether an email already exists?
4. What happens when a user logs in?

### JWT and Tokens

5. What does `jwt.sign()` do?
6. What does `jwt.verify()` do?
7. What is the difference between an access token and a refresh token?
8. Why do access tokens expire?
9. What is refresh token rotation?
10. Why do we invalidate tokens during logout?

### Middleware and Authorization

11. What is middleware in Express?
12. Why do we use `next()`?
13. What is the purpose of `ensureAuthenticated`?
14. What is the purpose of `authorize()`?
15. What is the difference between authentication and authorization?
16. Why can an authenticated user still be denied access to a route?

### Two-Factor Authentication

17. What is 2FA?
18. What is a TOTP?
19. Why do we generate a secret?
20. Why do we use a QR code?
21. How does an authenticator app generate OTP codes?
22. Why should 2FA only be enabled after successful verification?

---

# 8. My Personal Goal

This project is a learning exercise.

I don't expect to understand everything immediately. I want to take my time, revisit the code, add comments, experiment with the endpoints, and understand why every important line exists.

**My goal is to move from copying code from tutorials to being able to build authentication systems independently.**

*Learning one concept at a time.*