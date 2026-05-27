'use strict';
const express = require('express');
const path = require('path'); 
const session = require('express-session');
const bcrypt = require('bcrypt');

const db = require('./database');

const app = express();
const SALT_ROUNDS = 10;
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true })); 
app.use(express.static(path.join(__dirname, 'public'))); 

app.use(session({
  secret: 'sfsu-dealership-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 600000 } // Session lasts 10 minutes
}));

app.use((req, res, next) => {
  res.locals.user = req.session.user; 
  next();
});

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));




// --- Auth Routes ---

app.post('/register', async (req, res) => {
  const { username, password, confirmPassword } = req.body;
  if (password !== confirmPassword) {
    return res.render('register', { error: "Passwords do not match." });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
      if (err) return res.render('register', { error: "Username already taken." });
      res.render('login', { success: "Account created! You can now log in." });
    });
  } catch (error) {
    res.render('register', { error: "Error creating account. Please try again." });
  }
});

app.get('/register', (req, res) => res.render('register'));

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) return res.render('login', { error: "Database error. Please try again." });
    if (!user) return res.render('login', { error: "Invalid username or password." });
    try {
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        req.session.user = user;
        db.all("SELECT * FROM inventory", (err, rows) => {
          res.render('products', { 
            inventory: rows, 
            welcomeMsg: `Welcome back, ${user.username}!` 
          });
        });
      } else {
        res.render('login', { error: "Invalid username or password." });
      }
    } catch (error) {
      res.render('login', { error: "Error logging in. Please try again." });
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});




// --- API Routes (JSON) ---

app.get('/api/products', (req, res) => {
  db.all("SELECT * FROM inventory", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(200).json(rows);
  });
});

app.get('/api/products/:mileage', (req, res) => {
  db.get("SELECT * FROM inventory WHERE mileage = ?", [req.params.mileage], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Vehicle not found' });
    res.status(200).json(row);
  });
});




// --- View Routes (HTML) ---

app.get('/', (req, res) => res.render('home'));

app.get('/products', (req, res) => {
  db.all("SELECT * FROM inventory", (err, rows) => {
    if (err) return res.status(500).send("Database error");
    res.render('products', { inventory: rows });
  });
});

app.get('/products/:model', (req, res) => {
  db.get("SELECT * FROM inventory WHERE model = ?", [req.params.model], (err, row) => {
    if (err) return res.status(500).send("Database error");
    if (!row) return res.status(404).render('404', { id: req.params.model });
    res.render('product-detail', { car: row });
  });
});




// --- Cart Functionality ---

app.post('/cart/add', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const userId = req.session.user.id;
  const productId = req.body.model; 

  db.run("INSERT OR IGNORE INTO cart (user_id, product_id) VALUES (?, ?)", [userId, productId], function(err) {
    if (err) {
      return res.status(500).send("Error adding to cart: " + err.message);
    }
    res.redirect('/cart');
  });
});

app.get('/cart', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const userId = req.session.user.id;

  const query = `
    SELECT inventory.* FROM inventory 
    JOIN cart ON inventory.model = cart.product_id 
    WHERE cart.user_id = ?
  `;

  db.all(query, [userId], (err, items) => {
    if (err) return res.status(500).send("Error fetching cart");
    res.render('cart', { cartItems: items });
  });
});

app.post('/cart/remove', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const userId = req.session.user.id;
  const productId = req.body.model; 

  db.run("DELETE FROM cart WHERE user_id = ? AND product_id = ?", [userId, productId], (err) => {
    res.redirect('/cart');
  });
});

app.post('/checkout', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const userId = req.session.user.id;

  const query = `
    SELECT inventory.* FROM inventory 
    JOIN cart ON inventory.model = cart.product_id 
    WHERE cart.user_id = ?
  `;

  db.all(query, [userId], (err, items) => {
    if (err) return res.status(500).send("Error processing checkout");
    if (!items || items.length === 0) return res.redirect('/cart');

    const totalAmount = items.reduce((sum, item) => sum + item.price, 0);
    const itemCount = items.length;

    db.run("DELETE FROM cart WHERE user_id = ?", [userId], (err) => {
      if (err) return res.status(500).send("Error clearing cart");
      res.render('checkout-success', { 
        totalAmount, 
        itemCount 
      });
    });
  });
});

app.get('/login', (req, res) => res.render('login'));

app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('profile');
});


// 404 Catcher
app.use((req, res) => {
  res.status(404).render('404', { id: req.originalUrl });
});


app.listen(PORT, () => {
  console.log(`SFSU Dealership Server running at http://localhost:${PORT}`);
});