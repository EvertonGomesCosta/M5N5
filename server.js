const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();

app.use(bodyParser.json());

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

require('dotenv').config();
const secret = 'minhaChaveSecreta'; // Substitua por uma chave segura e use variáveis de ambiente



// Funções de geração e verificação de token JWT
function generateToken(user) {
  return jwt.sign(
    { id: user.id, perfil: user.perfil },
    secret,
    { expiresIn: '1h' } // O token expira em 1 hora
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, secret);
  } catch (err) {
    return null;
  }
}

// Middleware de autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401); // Sem token, não autorizado

  const decoded = verifyToken(token);
  if (!decoded) return res.sendStatus(403); // Token inválido ou expirado

  req.user = decoded; // Salva os dados do usuário no objeto de request
  next();
}

// Mock de dados de usuários
const users = [
  { "username": "user", "password": "123456", "id": 123, "email": "user@dominio.com", "perfil": "user" },
  { "username": "admin", "password": "123456789", "id": 124, "email": "admin@dominio.com", "perfil": "admin" },
  { "username": "colab", "password": "123", "id": 125, "email": "colab@dominio.com", "perfil": "user" },
];

// Endpoint para login do usuário
app.post('/api/auth/login', (req, res) => {
  const credentials = req.body;
  const userData = users.find(user => user.username === credentials.username && user.password === credentials.password);

  if (userData) {
    const token = generateToken(userData);
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Endpoint para recuperar dados do usuário logado
app.get('/api/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  res.json({ data: user });
});

// Endpoint para recuperação dos dados de todos os usuários cadastrados
app.get('/api/users', authenticateToken, (req, res) => {
  if (req.user.perfil !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }
  res.status(200).json({ data: users });
});

// Endpoint para recuperação dos contratos existentes
app.get('/api/contracts/:empresa/:inicio', authenticateToken, (req, res) => {
  const empresa = req.params.empresa;
  const dtInicio = req.params.inicio;

  // Mock de contratos, substitua por sua lógica de busca real
  const contracts = [
    { empresa: 'empresa1', inicio: '2023-01-01', contrato: 'Contrato 1' },
    { empresa: 'empresa2', inicio: '2023-01-01', contrato: 'Contrato 2' }
  ];

  const result = contracts.filter(contract => contract.empresa === empresa && contract.inicio === dtInicio);
  if (result.length > 0) {
    res.status(200).json({ data: result });
  } else {
    res.status(404).json({ data: 'Dados não encontrados' });
  }
});
