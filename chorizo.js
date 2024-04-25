const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "chorizo"
});

connection.connect(err => {
  if (err) {
    console.error('Error connecting to database: ' + err.stack);
    return;
  }
  console.log('Connected to database as id ' + connection.threadId);
});

app.use(bodyParser.json());

const JWT_SECRET = 'superhemlignyckel';

function generateToken(userId, username) {
  return jwt.sign({ sub: userId, username }, JWT_SECRET, { expiresIn: '2h' });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (authHeader === undefined) {
    return res.status(401).send("Wlla auth token saknas bre!");
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userInfo = { userId: decoded.sub, username: decoded.username };
    next();
  } catch (error) {
    console.error(error);
    return res.status(401).send("Invalid auth token");
  }
}

app.get('/', (req, res) => {
  res.send(`
    <h1>API Routes</h1>
    <ul>
      <li><a href="/users">/users</a></li>
      <li><a href="/login">/login</a></li>
    </ul>
  `);
});

app.get('/users', authenticateToken, (req, res) => {
  const sql = 'SELECT * FROM users';
  connection.query(sql, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

app.get('/users/:id', authenticateToken, (req, res) => {
  const userId = req.params.id;
  const sql = 'SELECT * FROM users WHERE id = ?';
  connection.query(sql, [userId], (error, results) => {
    if (error) throw error;
    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  });
});

app.put('/users/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const { username, name, password } = req.body;

  if (!username || !name || !password) {
    return res.status(400).send('Username, name, and password are required');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'UPDATE users SET username = ?, name = ?, password = ? WHERE id = ?';
    connection.query(sql, [username, name, hashedPassword, userId], (error, result) => {
      if (error) {
        console.error('Error updating user: ' + error.message);
        return res.status(500).send('Internal Server Error');
      }
      
      if (result.affectedRows === 0) {
        return res.status(400).send('User not found or nothing to update');
      }
      
      res.status(200).send('User updated successfully');
    });
  } catch (error) {
    console.error('Error hashing password:', error);
    return res.status(500).send('Internal Server Error');
  }
});

app.post('/users', authenticateToken, async (req, res) => {
  const { username, name, password } = req.body;

  if (!username || !name || !password) {
    return res.status(422).json({ error: "Missing required fields" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO users (username, name, password) VALUES (?, ?, ?)';
    connection.query(sql, [username, name, hashedPassword], (error, result) => {
      if (error) throw error;
      const createdUser = {
        id: result.insertId,
        username: username,
        name: name
      };
      res.json(createdUser);
    });
  } catch (error) {
    console.error('Error hashing password:', error);
    return res.status(500).send('Internal Server Error');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const sql = 'SELECT * FROM users WHERE username = ?';
  connection.query(sql, [username], async (error, results) => {
    if (error) {
      console.error('Error retrieving user:', error.message);
      return res.status(500).send('Internal Server Error');
    }

    if (results.length === 0) {
      return res.status(401).send('Authentication failed: User not found');
    }

    const user = results[0];

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send('Authentication failed: Incorrect password');
    }

    const token = generateToken(user.id, user.username);
    res.json({ token });
  });
});

app.get('/users/me', authenticateToken, (req, res) => {
  const userId = req.userInfo.userId;
  const sql = 'SELECT * FROM users WHERE id = ?';
  connection.query(sql, [userId], (error, results) => {
    if (error) {
      console.error('Error retrieving user:', error.message);
      return res.status(500).send('Internal Server Error');
    }
    if (results.length === 0) {
      return res.status(404).send('User not found');
    }
    const user = results[0];
    delete user.password;
    res.json(user);
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
