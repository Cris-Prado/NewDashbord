require('dotenv').config(); // Carregar variáveis de ambiente
const express = require('express');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;

// Configuração do banco de dados
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
});

db.connect((err) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
        process.exit(1);
    }
    console.log('Conectado ao banco de dados.');
});

// Configuração do middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'src/public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'src/templates'));

// Configuração da sessão
app.use(
    session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 },
    })
);

// Rota para exibir o formulário de registro
app.get('/register', (req, res) => {
    res.render('register');
});

// Rota para lidar com o registro
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const query = 'INSERT INTO mydashbord(username, password) VALUES (?, ?)';
        db.query(query, [username, hashedPassword], (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).send('Usuário já existe.');
                }
                return res.status(500).send('Erro ao registrar usuário.');
            }
            res.redirect('/login');
        });
    } catch (err) {
        res.status(500).send('Erro no servidor.');
    }
});

// Rota para exibir o formulário de login
app.get('/login', (req, res) => {
    res.render('login');
});

// Rota para lidar com o login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM mydashbordWHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).send('Usuário ou senha incorretos.');
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send('Usuário ou senha incorretos.');
        }

        req.session.user = { id: user.id, username: user.username };
        res.redirect('/success');
    });
});

// Rota para a página de sucesso
app.get('/success', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.render('success', { username: req.session.user.username });
});

// Rota para logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// Iniciar o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});


