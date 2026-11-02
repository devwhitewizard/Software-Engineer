/*
 * REST API: Authentication, Authorization and Two-Factor Authentication
 *
 * BIG PICTURE
 *
 * 1. Register: Save a new user with a hashed password.
 * 2. Login: Check credentials and generate JWT tokens.
 * 3. Refresh token: Generate new tokens when an access token expires.
 * 4. 2FA setup: Generate a secret and return a QR code.
 * 5. 2FA validation: Verify an OTP before enabling 2FA.
 * 6. Protected routes: Check whether a user is authenticated.
 * 7. Authorization: Check whether a user has permission to access a route.
 * 8. Logout: Invalidate the user's tokens.
 */

const express = require('express')
const Datastore = require('nedb-promises')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { authenticator } = require('otplib')
const qrcode = require('qrcode')
const crypto = require('crypto')
const NodeCache = require('node-cache')

const config = require('./config')

// EXPRESS APP
// Create the Express application.
// This allows us to define routes and handle HTTP requests.
const app = express();

// BODY PARSER
// Converts incoming JSON request bodies into JavaScript objects.
// This allows us to access submitted data using req.body.
app.use(express.json());

// DATABASE SETUP
// We are using NeDB as a lightweight database for this project.
// Each Datastore represents a separate database file.

const users = Datastore.create('Users.db');

// Stores refresh tokens belonging to logged-in users.
const userRefreshTokens = Datastore.create('UserRefreshTokens.db');

// Stores access tokens that have been invalidated during logout.
const userInvalidTokens = Datastore.create('UserInvalidTokens.db');

// Creates an in-memory cache.
// Data stored here disappears when the Node.js server restarts.
const cache = new NodeCache();


// HOME ROUTE
// A simple route to check whether the API is running.
app.get('/', (req, res) => {
    res.send('REST API Authentication and Authorization');
});

// USER REGISTRATION
// This route allows a new user to create an account.
//
// Flow:
// 1. Receive user details.
// 2. Check that required fields are provided.
// 3. Check whether the email already exists.
// 4. Hash the password.
// 5. Save the new user in the database.

app.post('/api/auth/register', async (req, res) => {

    try {

        // Extract registration details from the request body.
        const { name, email, password, role } = req.body;

        // Make sure required fields are provided.
        if (!name || !email || !password) {
            return res.status(422).json({
                message: 'Please provide name, email and password'
            });
        }

        // Check whether another user already registered with this email.
        if (await users.findOne({ email })) {
            return res.status(409).json({
                message: 'Email already exists'
            });
        }

        // HASH PASSWORD
        // Never store plain-text passwords in the database.
        // bcrypt converts the password into a secure hash.
        // 10 represents the hashing cost factor.
        const hashedPassword = await bcrypt.hash(password, 10);

        // SAVE USER
        const newUser = await users.insert({

            name,
            email,

            // Store the hashed password instead of the original password.
            password: hashedPassword,

            // If no role is provided, assign the default role of member.
            role: role ?? 'member',

            // New users have not enabled 2FA yet.
            '2faEnabled': false,

            // No 2FA secret has been generated yet.
            '2faSecret': null
        });

        // Return a successful registration response.
        return res.status(201).json({
            message: 'User registered successfully',
            id: newUser._id
        });

    } catch (error) {

        // Handle unexpected errors.
        return res.status(500).json({
            message: error.message
        });
    }
});

// USER LOGIN
//
// Flow:
// 1. Receive email and password.
// 2. Find the user in the database.
// 3. Compare the submitted password with the stored hash.
// 4. Check whether 2FA is enabled.
// 5. Generate an access token and refresh token.
// 6. Save the refresh token in the database.
// 7. Return the tokens to the client.

app.post('/api/auth/login', async (req, res) => {

    try {

        // Extract login credentials.
        const { email, password } = req.body;

        // Check whether both fields were provided.
        if (!email || !password) {
            return res.status(422).json({
                message: 'Please fill in all fields (email and password)'
            });
        }

        // Find the user using their email address.
        const user = await users.findOne({ email });

        // If the user does not exist, reject the login.
        if (!user) {
            return res.status(401).json({
                message: 'Email or password is invalid'
            });
        }

        // COMPARE PASSWORDS
        // bcrypt.compare() compares the submitted password
        // against the hashed password stored in the database.
        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        // Reject incorrect passwords.
        if (!passwordMatch) {
            return res.status(401).json({
                message: 'Email or password is invalid'
            });
        }

        // CHECK TWO-FACTOR AUTHENTICATION
        // If 2FA is enabled, the user must also provide a TOTP code.
        if (user['2faEnabled']) {

            return res.status(401).json({
                message: 'TOTP is required'
            });
        }

        // GENERATE ACCESS TOKEN
        // An access token is used to access protected API endpoints.
        // It normally has a shorter expiration time.
        const accessToken = jwt.sign(
            { userId: user._id },
            config.accessTokenSecret,
            {
                subject: 'accessApi',
                expiresIn: config.accessTokenExpiresIn
            }
        );

        // GENERATE REFRESH TOKEN
        // A refresh token allows the client to obtain a new access token
        // without requiring the user to log in again.
        const refreshToken = jwt.sign(
            { userId: user._id },
            config.refreshTokenSecret,
            {
                subject: 'refreshApi',
                expiresIn: config.refreshTokenExpiresIn
            }
        );

        // SAVE REFRESH TOKEN
        // Store the refresh token and the user it belongs to.
        await userRefreshTokens.insert({
            refreshToken,
            userId: user._id
        });

        // Return user information and both tokens.
        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email,
            accessToken,
            refreshToken
        });

    } catch (error) {

        return res.status(500).json({
            message: error.message
        });
    }
});

// REFRESH TOKEN
//
// Purpose:
// When an access token expires, the user can use their refresh token
// to obtain a new access token.
//
// Flow:
// 1. Receive refresh token.
// 2. Verify the refresh token.
// 3. Check whether it exists in the database.
// 4. Remove the old refresh token.
// 5. Generate a new access token and refresh token.
// 6. Save the new refresh token.

app.post('/api/auth/refresh-token', async (req, res) => {

    try {

        // Extract the refresh token from the request body.
        const { refreshToken } = req.body;

        // Make sure a refresh token was provided.
        if (!refreshToken) {
            return res.status(401).json({
                message: 'Refresh token not found'
            });
        }

        // VERIFY REFRESH TOKEN
        // jwt.verify() checks whether the token is valid
        // and whether it has expired.
        // It also returns the information stored inside the token.
        const decodedRefreshToken = jwt.verify(
            refreshToken,
            config.refreshTokenSecret
        );

        // Check whether this refresh token exists in our database
        // and belongs to the user identified inside the token.
        const userRefreshToken = await userRefreshTokens.findOne({
            refreshToken,
            userId: decodedRefreshToken.userId
        });

        // Reject tokens that are not stored in the database.
        if (!userRefreshToken) {
            return res.status(401).json({
                message: 'Refresh token is invalid or expired'
            });
        }

        // TOKEN ROTATION
        // Remove the old refresh token so it cannot be reused.
        await userRefreshTokens.remove({
            _id: userRefreshToken._id
        });

        // Save the database changes.
        await userRefreshTokens.compactDatafile();

        // Generate a new access token.
        const accessToken = jwt.sign(
            { userId: decodedRefreshToken.userId },
            config.accessTokenSecret,
            {
                subject: 'accessApi',
                expiresIn: config.accessTokenExpiresIn
            }
        );

        // Generate a new refresh token.
        const newRefreshToken = jwt.sign(
            { userId: decodedRefreshToken.userId },
            config.refreshTokenSecret,
            {
                subject: 'refreshApi',
                expiresIn: config.refreshTokenExpiresIn
            }
        );

        // Store the new refresh token.
        await userRefreshTokens.insert({
            refreshToken: newRefreshToken,
            userId: decodedRefreshToken.userId
        });

        // Return the new tokens.
        return res.status(200).json({
            accessToken,
            refreshToken: newRefreshToken
        });

    } catch (error) {

        // Handle invalid or expired JWTs.
        if (
            error instanceof jwt.TokenExpiredError ||
            error instanceof jwt.JsonWebTokenError
        ) {
            return res.status(401).json({
                message: 'Refresh token is invalid or expired'
            });
        }

        return res.status(500).json({
            message: error.message
        });
    }
});

// TWO-FACTOR AUTHENTICATION: GENERATE QR CODE
//
// Purpose:
// Generate a secret that will be shared between our application
// and the user's authenticator application.
//
// Flow:
// 1. Authenticate the user.
// 2. Find the user in the database.
// 3. Generate a secret.
// 4. Generate an otpauth URL.
// 5. Save the secret.
// 6. Convert the URL into a QR code.
// 7. Return the QR code as a PNG image.

app.get('/api/auth/2fa/generate', ensureAuthenticated, async (req, res) => {

    try {

        // Find the currently authenticated user.
        // req.user.id was added by ensureAuthenticated middleware.
        const user = await users.findOne({
            _id: req.user.id
        });

        // Generate a new secret for TOTP authentication.
        const secret = authenticator.generateSecret();

        // Create an otpauth URL.
        // This URL contains the information needed by authenticator apps.
        //
        // user.email = account identifier.
        // nexus = application/issuer name.
        // secret = shared authentication secret.
        const url = authenticator.keyuri(
            user.email,
            'nexus',
            secret
        );

        // SAVE SECRET
        // Save the secret in the database.
        // Keep 2FA disabled until the user successfully verifies a code.
        await users.update(
            { _id: req.user.id },
            {
                $set: {
                    '2faEnabled': false,
                    '2faSecret': secret
                }
            }
        );

        // Save database changes.
        await users.compactDatafile();

        // GENERATE QR CODE
        // Convert the otpauth URL into PNG image data.
        const qrCode = await qrcode.toBuffer(url, {
            type: 'image/png',
            margin: 1
        });

        // Tell the client that the response is a PNG image.
        res.setHeader(
            'Content-Disposition',
            'attachment; filename="qrcode.png"'
        );

        // Send the QR code image to Postman or another client.
        return res.status(200).type('image/png').send(qrCode);

    } catch (error) {

        return res.status(500).json({
            message: error.message
        });
    }
});

// TWO-FACTOR AUTHENTICATION: VALIDATE OTP
//
// Purpose:
// Check whether the code submitted by the user matches
// the secret stored in our database.
//
// Flow:
// 1. Authenticate the user.
// 2. Receive the OTP.
// 3. Find the user.
// 4. Verify the OTP using the saved secret.
// 5. If valid, enable 2FA.

app.post('/api/auth/2fa/validate', ensureAuthenticated, async (req, res) => {

    try {

        // Extract the OTP submitted by the user.
        const { totp } = req.body;

        // Check whether the OTP was provided.
        if (!totp) {
            return res.status(422).json({
                message: 'TOTP is required'
            });
        }

        // Find the authenticated user.
        const user = await users.findOne({
            _id: req.user.id
        });

        // CHECK OTP
        // authenticator.check() compares the submitted OTP
        // against the user's stored secret.
        const verified = authenticator.check(
            totp,
            user['2faSecret']
        );

        // Reject an incorrect or expired OTP.
        if (!verified) {
            return res.status(400).json({
                message: 'TOTP is not correct or expired'
            });
        }

        // ENABLE 2FA
        // Only enable 2FA after successful OTP verification.
        // The secret was already saved during QR generation.
        await users.update(
            { _id: req.user.id },
            {
                $set: {
                    '2faEnabled': true
                }
            }
        );

        // Save database changes.
        await users.compactDatafile();

        // Inform the user that 2FA setup was successful.
        return res.status(200).json({
            message: 'TOTP validated successfully'
        });

    } catch (error) {

        return res.status(500).json({
            message: error.message
        });
    }
});

// USER LOGOUT
//
// Purpose:
// Log the user out by invalidating their access token
// and removing their refresh token.
//
// Flow:
// 1. Authenticate the user.
// 2. Receive the refresh token.
// 3. Remove the refresh token from the database.
// 4. Add the access token to the invalid-token database.
// 5. Return a successful logout response.

app.post('/api/auth/logout', ensureAuthenticated, async (req, res) => {

    try {

        // Extract the refresh token from the request body.
        const { refreshToken } = req.body;

        // Remove the refresh token from the database.
        await userRefreshTokens.remove({
            refreshToken: refreshToken
        });

        // INVALIDATE ACCESS TOKEN
        // Save the current access token in the invalid-token database.
        // This prevents it from being reused before it expires.
        await userInvalidTokens.insert({

            token: req.accessToken.value,

            // Store the user who owns this token.
            userId: req.user.id,

            // Store the token's expiry timestamp.
            expirationTime: req.accessToken.exp
        });

        // HTTP 204 means the request succeeded
        // and there is no response body.
        return res.status(204).send();

    } catch (error) {

        return res.status(500).json({
            message: error.message
        });
    }
});


 // Authentication Middleware
// CURRENT USER
//
// Purpose:
// Return information about the user who is currently logged in.
//
// ensureAuthenticated runs first.
// If the token is invalid, this route will not execute.

app.get('/api/users/current', ensureAuthenticated, async (req, res) => {

    try {

        // Find the currently authenticated user.
        const user = await users.findOne({
            _id: req.user.id
        });

        // Check whether the user still exists.
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            });
        }

        // Return safe user information.
        // Never return the password hash or 2FA secret.
        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email
        });

    } catch (error) {

        return res.status(500).json({
            message: error.message
        });
    }
});

app.get('/api/admin', ensureAuthenticated, authorize(['admin']), (req, res) => {
    return res.status(200).json({ message: 'Only admin can access this route!' })
})

app.get('/api/moderator', ensureAuthenticated, authorize(['admin','moderator']), (req, res) => {
    return res.status(200).json({ message: 'Only admin and moderators can access this route!' })
})


// AUTHENTICATION MIDDLEWARE
//
// IMPORTANT CONCEPT:
//
// Middleware is a function that runs between receiving a request
// and sending a response.
//
// ensureAuthenticated checks whether the user has a valid access token.
//
// next() tells Express to continue to the next middleware or route handler.
//
// For example:
//
// app.get('/api/users/current', ensureAuthenticated, callback)
//
// ensureAuthenticated runs before callback.

async function ensureAuthenticated(req, res, next) {

    // Get the Authorization header sent by the client.
    //
    // Postman Bearer Token sends:
    // Authorization: Bearer YOUR_ACCESS_TOKEN

    const authHeader = req.headers.authorization;

    // Extract the actual JWT from the Bearer header.
    const accessToken = authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.slice(7)
        : authHeader;

    // Check whether a token was provided.
    if (!accessToken) {
        return res.status(401).json({
            message: 'Access token not found'
        });
    }

    // Check whether the token has already been invalidated.
    // For example, a user may have logged out.
    if (await userInvalidTokens.findOne({ token: accessToken })) {

        return res.status(401).json({
            message: 'Access token is invalid',
            code: 'AccessTokenInvalid'
        });
    }

    try {

        // VERIFY ACCESS TOKEN
        // jwt.verify() checks the signature and expiration date.
        // It returns the information stored inside the token.
        const decodedAccessToken = jwt.verify(
            accessToken,
            config.accessTokenSecret
        );

        // Store the token and its expiration time in the request.
        // Other routes can access these values.
        req.accessToken = {
            value: accessToken,
            exp: decodedAccessToken.exp
        };

        // Attach the authenticated user's ID to the request.
        // Other routes can now identify the logged-in user.
        req.user = {
            id: decodedAccessToken.userId
        };

        // NEXT()
        // Tell Express that authentication succeeded.
        // Continue to the next middleware or route handler.
        next();

    } catch (error) {

        // Handle expired tokens separately.
        if (error instanceof jwt.TokenExpiredError) {

            return res.status(401).json({
                message: 'Access token expired',
                code: 'AccessTokenExpired'
            });

        } else if (error instanceof jwt.JsonWebTokenError) {

            // The token is invalid or its signature is incorrect.
            return res.status(401).json({
                message: 'Access token Invalid',
                code: 'AccessTokenInvalid'
            });

        } else {

            // Handle unexpected errors.
            return res.status(500).json({
                message: error.message
            });
        }
    }
}

// AUTHORIZATION MIDDLEWARE
//
// Difference between authentication and authorization:
//
// AUTHENTICATION:
// Are you really who you claim to be?
//
// AUTHORIZATION:
// Are you allowed to access this particular resource?
//
// Example:
// An admin and a normal member may both be authenticated.
// However, only the admin should access the admin route.

function authorize(roles = []) {

    return async function(req, res, next) {

        // Find the authenticated user in the database.
        const user = await users.findOne({
            _id: req.user.id
        });

        // Check whether:
        // 1. The user exists.
        // 2. Their role is included in the allowed roles.
        //
        // roles.includes(user.role) checks whether
        // the user's role exists in the roles array.

        if (!user || !roles.includes(user.role)) {

            return res.status(403).json({
                message: 'Access Denied'
            });
        }

        // If the role is allowed, continue to the route handler.
        next();
    };
}

// START EXPRESS SERVER
//
// The application listens for incoming requests on port 3000.
//
// Open http://localhost:3000 in your browser or Postman
// to check whether the server is running.

app.listen(3000, () => {
    console.log('Server running on port 3000');
});