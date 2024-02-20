const express = require("express");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const pgp = require("pg-promise")();
const axios = require("axios");
const cookieParser = require("cookie-parser");

const { ComplyCube, EventVerifier } = require("@complycube/api");

dotenv.config();

const db = pgp(process.env.DATABASE_URL);
// Provide your webhook secret to the EventVerifier
const webhookSecret = process.env.COMPLYCUBE_WEBHOOK_SECRET;
const eventVerifier = new EventVerifier(webhookSecret);

const complycube = new ComplyCube({
    apiKey: process.env.COMPLY_CUBE_API_KEY,
});

const app = express();
const port = process.env.PORT || 8000;
app.use(cors({ credentials: true, origin: "http://localhost:3000" }));
app.use(bodyParser.json());
app.use(cookieParser());

app.get("/", async (req, res) => {
    // const token = await getToken();
    // res.send(token);
    res.send("Hey this is my API running 🥳");
});

// Middleware to verify JWT token
// eslint-disable-next-line consistent-return
const authenticateToken = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    try {
        const decodedToken = jwt.verify(token, "your_secret_key"); // replace with your actual secret key

        const user = await db.one("SELECT email,first_name,last_name  FROM users WHERE email = $1", [
            decodedToken.email,
        ]);

        req.user = user;
        next();
    } catch (error) {
        console.error("Error verifying JWT:", error);
        res.status(403).json({ error: "Forbidden" });
    }
};

// Register a new user
app.post("/register", async (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await db.none("INSERT INTO users(first_name, last_name, email, password) VALUES($1, $2, $3, $4)", [
            firstName,
            lastName,
            email,
            hashedPassword,
        ]);

        const token = jwt.sign({ email }, "your_secret_key", { expiresIn: "5h" });

        // Set the token in an HTTP-only cookie
        res.cookie("token", token, { httpOnly: true });
        res.status(201).json({ message: "Signup successful" });
    } catch (error) {
        console.error("Error during signup:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Login and generate JWT token
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await db.one("SELECT * FROM users WHERE email = $1", [email]);

        if (await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ email }, "your_secret_key", { expiresIn: "5h" });
            res.cookie("token", token, { httpOnly: true });
            res.status(200).json({ message: "Login successful" });
        } else {
            res.status(401).json({ error: "Authentication failed" });
        }
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get("/user-profile", authenticateToken, async (req, res) => {
    // req.user contains the user data from the JWT payload
    const userEmail = req.user.email;

    try {
        const user = await db.one("SELECT email,first_name,last_name FROM users WHERE email = $1", [userEmail]);
        res.json(user);
    } catch (error) {
        console.error("Error fetching user data:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/logout", (req, res) => {
    // Clear the authentication token on the server side
    res.clearCookie("token");
    res.status(200).json({ message: "Logout successful" });
});

// Protected route
app.get("/user", authenticateToken, (req, res) => {
    res.json(req.user);
});

// Match the raw body to content type application/json
app.post("/webhook", bodyParser.json(), (request, response) => {
    const signature = request.headers["complycube-signature"];

    let event;

    try {
        event = eventVerifier.constructEvent(JSON.stringify(request.body), signature);
    } catch (err) {
        response.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event
    switch (event.type) {
        case "check.completed": {
            const checkId = event.payload.id;
            const checkOutCome = event.payload.outcome;
            console.log(`Check ${checkId} completed with outcome ${checkOutCome}`);
            break;
        }
        case "check.pending": {
            const checkId = event.payload.id;
            console.log(`Check ${checkId} is pending`);
            break;
        }
        case "check.completed.match_confirmed": {
            const checkId = event.payload.id;
            console.log(`Check ${checkId} is confirmed`);
        }

        // ... handle other event types
        default: {
            // Unexpected event type
            return response.status(400).end();
        }
    }

    // Return a response to acknowledge receipt of the event
    response.json({ received: true });
});

app.get("/ipaddress", async (req, res) => {
    try {
        const { ip } = req.query;
        const response = await axios.get(
            `https://proxyradar.io/v1/check?key=${process.env.REACT_APP_PROXY_RADAR_API_KEY}&ip=${ip}&format=json`,
        );

        res.send({
            is_proxy: !!response.data.proxy,
        });
    } catch (error) {
        console.error("Error checking IP address:", error);
        res.sendStatus(500);
    }
});

app.get("/kyc-token", authenticateToken, async (req, res) => {
    const client = await complycube.client.create({
        type: "person",
        email: req.user.email,
        personDetails: {
            firstName: req.user.first_name,
            lastName: req.user.last_name,
            //   dob: '1990-01-01',
        },
    });

    //TODO: Save into DB  with user
    console.log(client.id);

    const token = await complycube.token.generate(client.id, {
        referrer: "*://*/*",
    });

    res.send({ kycToken: token });
});

app.listen(port, () => {
    console.log(`Server is Fire at http://localhost:${port}`);
});
