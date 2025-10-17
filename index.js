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
  findPartialMatch, // <-- 1. Se importa la nueva función de passwordLogic.js
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
        url: 'https://evaluador-de-contraseñas.onrender.com', 
        description: 'Servidor de Producción'
      },
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
 *     description: Recibe una contraseña y devuelve un análisis completo que incluye entropía, fortaleza, y si es una contraseña común (exacta o parcial).
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
 *                 example: "Mi-password-123"
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
 *                       example: "Débil (Predecible)"
 *                     isCommon:
 *                       type: boolean
 *                       description: "Indica si la contraseña es una coincidencia EXACTA en el dataset."
 *                       example: false
 *                     containedCommonWord:
 *                       type: string
 *                       nullable: true
 *                       description: "Si se encuentra una coincidencia PARCIAL, muestra la palabra común contenida."
 *                       example: "password"
 *                 security_tips:
 *                   type: object
 *                   properties:
 *                     estimatedCrackTime:
 *                       type: string
 *                       example: "3,775.25 años"
 *                     recommendation:
 *                       type: string
 *                       example: "Tu contraseña contiene la palabra común 'password', lo que la hace predecible."
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

  // --- 2. LÓGICA: Búsqueda exacta y parcial ---
  let finalStrength = strength;
  let recommendation = "¡Buena contraseña!"; 
  let partialMatch = null;

  if (isCommon) {
    // Caso 1: La contraseña es una coincidencia EXACTA
    finalStrength = 'Muy Débil (Común)';
    recommendation = "Esta contraseña es comun entre las contraseñas filtradas. Cambiala por una más segura.";
  } else {
    // Caso 2: Si no es exacta, buscar si CONTIENE una contraseña común
    partialMatch = findPartialMatch(password, commonPasswords);
    if (partialMatch) {
      finalStrength = 'Débil (Predecible)';
      recommendation = `Tu contraseña contiene la palabra común '${partialMatch}'`;
    }
  }
  
  // --- 3. RESPUESTA ACTUALIZADA: Se añade el campo `containedCommonWord` ---
  const response = {
    password: '***',
    evaluation: {
      length: L,
      keyspace: N,
      entropy: parseFloat(entropy.toFixed(2)),
      strength: finalStrength,
      isCommon: isCommon, 
      containedCommonWord: partialMatch, 
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