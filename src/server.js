require('dotenv').config();

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const mongoose = require('mongoose')
const User = require('./models/User.js');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { Web3 } = require('web3');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'Authentication and Ethereum API',
      version: '1.0.0',
      description: 'API documentation for authentication and Ethereum balance retrieval',
    },
    components: {
        securitySchemes: {
            Authorization: {
                type: "http",
                scheme: "bearer",
                bearerFormat: "JWT",
                value: "Bearer <JWT token here>"
            }
        }
    },
    servers: [{ url: 'http://localhost:3000', description: 'Development server' }],
  },
  apis: ['src/server.js'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

app.use(express.json());
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));



const web3 = new Web3(`http://localhost:8545/`)



PORT = process.env.PORT || 3000;
ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
publicApiUrl = process.env.PUBLIC_API_URL


/**
 * @swagger
 * /hello:
 *   get:
 *     summary: Get a greeting message.
 *     description: Returns "Hello" message.
 *     responses:
 *       200:
 *         description: Successful operation. Returns "Hello".
 */
app.get('/hello', authenticateToken, (req, res) => res.send("Hello"));


/**
 * @swagger
 * /signup:
 *   post:
 *     summary: Register a new user.
 *     description: Creates a new user account.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: User successfully registered.
 *       500:
 *         description: Internal server error.
 */
app.post('/signup', async (req, res) => {
    try{
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        const createdUser = await User.create({ username: req.body.username, password: hashedPassword });
        res.status(201).json(createdUser);
    } catch {
        res.status(500).send();
    }
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Authenticate user and generate JWT token.
 *     description: Validates user credentials and returns a JWT token for accessing protected APIs.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: JWT token generated successfully.
 *       400:
 *         description: Invalid username.
 *       500:
 *         description: Internal server error.
 */
app.post('/login', async (req, res) => {
    const user = await User.findOne({ username: req.body.username });

    if(user == null) return res.status(400).send('Invalid username!');

    try{
        const result = await bcrypt.compare(req.body.password, user.password);
        if(result) {
            const accessToken = jwt.sign({ username: user.username}, ACCESS_TOKEN_SECRET, { expiresIn: process.env.EXPIRATION_MINUTES});

            res.json({ accessToken: accessToken });
        }
        else res.send('Invalid password');
    } catch {
        res.status(500);
    }
    
});


/**
 * @swagger
 * /filter:
 *   get:
 *     summary: Filter public APIs by category.
 *     description: Fetches public APIs and filters them by category.
 *     parameters:
 *       - in: query
 *         name: category
 *         description: Category to filter by.
 *         required: false
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         description: Maximum number of results to return.
 *         required: false
 *         schema:
 *           type: integer
 *     security:
 *       - Authorization: []
 *     responses:
 *       200:
 *         description: Filtered list of public APIs.
 *       500:
 *         description: Internal server error.
 */
app.get('/filter', authenticateToken, async (req, res) => {
    try {
        const response = await axios.get(publicApiUrl);
        let filteredEntries = response.data.entries;

        // Filter by Category
        if (req.query.category) {
            filteredEntries = filteredEntries.filter(entry => entry.Category.toLowerCase() === req.query.category.toLowerCase());
        }

        // Limit the number of results if limit parameter is provided
        let limit = req.query.limit ? parseInt(req.query.limit) : filteredEntries.length;
        filteredEntries = filteredEntries.slice(0, limit);

        res.json({ count: filteredEntries.length, entries: filteredEntries });
    } catch (error) {
        console.error('Error fetching data:', error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



/**
 * @swagger
 * /balance:
 *   get:
 *     summary: Get balance of an Ethereum account.
 *     description: Fetches the balance of an Ethereum account.
 *     parameters:
 *       - in: query
 *         name: account
 *         description: Ethereum account address.
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Balance of the Ethereum account.
 *       400:
 *         description: Ethereum account address is required.
 *       500:
 *         description: Internal server error.
 */
app.get('/balance', authenticateToken, async(req, res) => {
        
    try{
        const account = req.query.account;

        if (!account) {
            return res.status(400).json({ error: 'Ethereum account address is required' });
        }

        const balance = await web3.eth.getBalance(account);
        const balanceInEther = web3.utils.fromWei(balance, 'ether');

        res.json({ balance: balanceInEther });
    } catch {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

mongoose.connect(process.env.DB_URL);


function authenticateToken(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if(token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user)=> {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}



app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});