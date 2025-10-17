const express = require('express');
const fs = require('fs');
const csv = require('csv-parser');
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');
const {
  calculateL,
  calculateN,
  calculateEntropy,
  checkPasswordStrength,
  calculateCrackTime,
} = require('./passwordLogic');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Carga del Diccionario de Contraseñas ---
const commonPasswords = new Set();
const csvFilePath = './data/1millionPasswords.csv';
console.log('Cargando diccionario de contraseñas comunes...');
fs.createReadStream(csvFilePath)
  .pipe(csv())
  .on('data', (row) => {
    if (row.password) {
      commonPasswords.add(row.password);
    }
  })
  .on('end', () => {
    console.log(`Diccionario cargado. ${commonPasswords.size} contraseñas comunes en memoria.`);
  });

app.use(express.json());

// --- CONFIGURACIÓN DE SWAGGER ---
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Evaluación de Contraseñas',
      version: '1.0.0',
      description: 'Una API para calcular la entropía y fortaleza de una contraseña.',
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Servidor de Desarrollo Local'
      }
    ],
  },
  apis: ['./index.js'], 
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.get('/', (req, res) => {
  res.send('API funcionando. Visita /api-docs para ver la documentación interactiva.');
});

/**
 * @swagger
 * /api/v1/password/evaluate:
 *   post:
 *     summary: Evalúa la fortaleza de una contraseña.
 *     description: Recibe una contraseña y devuelve un análisis completo que incluye entropía, nivel de fortaleza, si es una contraseña común y el tiempo estimado para crackearla.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               password:
 *                 type: string
 *                 description: La contraseña a evaluar.
 *                 example: "MyP@ssw0rd!"
 *     responses:
 *       '200':
 *         description: Análisis de la contraseña exitoso.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 password:
 *                   type: string
 *                   example: "***"
 *                 evaluation:
 *                   type: object
 *                   properties:
 *                     length:
 *                       type: integer
 *                       example: 11
 *                     keyspace:
 *                       type: integer
 *                       example: 94
 *                     entropy:
 *                       type: number
 *                       example: 72.14
 *                     strength:
 *                       type: string
 *                       example: "Fuerte"
 *                     isCommon:
 *                       type: boolean
 *                       example: false
 *                 security_tips:
 *                   type: object
 *                   properties:
 *                     estimatedCrackTime:
 *                       type: string
 *                       example: "3,775.25 años"
 *                     recommendation:
 *                       type: string
 *                       example: "¡Buena contraseña!"
 *       '400':
 *         description: Petición inválida. El cuerpo de la petición debe contener una propiedad "password" de tipo string.
 */
app.post('/api/v1/password/evaluate', (req, res) => {
  const { password } = req.body;

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'La contraseña es requerida y debe ser un texto (string).' });
  }

  const L = calculateL(password);
  const N = calculateN(password);
  const entropy = calculateEntropy(L, N);
  const strength = checkPasswordStrength(entropy);
  const crackTime = calculateCrackTime(entropy);
  const isCommon = commonPasswords.has(password);

  let finalStrength = strength;
  let recommendation = "Excelente contraseña!";

  if (isCommon) {
    finalStrength = 'Contraseña muy Débil (Común)';
    recommendation = "Esta contraseña es extremadamente común y fácil de adivinar. Se recomienda cambiarla inmediatamente.";
  }
  
  const response = {
    password: '***',
    evaluation: {
      length: L,
      keyspace: N,
      entropy: parseFloat(entropy.toFixed(2)),
      strength: finalStrength,
      isCommon: isCommon,
    },
    security_tips: {
      estimatedCrackTime: isCommon ? "Instantáneo (está en listas de filtraciones)" : crackTime,
      recommendation: recommendation,
    }
  };

  res.status(200).json(response);
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  console.log(`Documentación de la API disponible en http://localhost:${PORT}/api-docs`);
});