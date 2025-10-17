/**
 * passwordLogic.js
 * * Contiene todas las funciones de cálculo para la evaluación de contraseñas.
 */

const calculateL = (password) => {
  if (!password) return 0;
  return password.length;
};

const calculateN = (password) => {
  if (!password) return 0;
  let nSize = 0;
  if (/[a-z]/.test(password)) nSize += 26;
  if (/[A-Z]/.test(password)) nSize += 26;
  if (/[0-9]/.test(password)) nSize += 10;
  if (/[ `!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/.test(password)) nSize += 32;
  return nSize;
};

/**
 * Calcula la Entropía (E) de la contraseña en bits.
 */
const calculateEntropy = (L, N) => {
  if (N === 0) return 0;
  return L * Math.log2(N);
};

/**
 * Asigna una categoría de fuerza basada en la entropía.
 */
const checkPasswordStrength = (entropy) => {
  if (entropy < 60) return 'Débil';
  if (entropy >= 60 && entropy < 80) return 'Fuerte';
  return 'Muy Fuerte';
};


const calculateCrackTime = (entropy) => {
  const attemptsPerSecond = 1e11; 
  const totalCombinations = Math.pow(2, entropy);
  const seconds = totalCombinations / attemptsPerSecond;

  if (seconds < 1) return 'Instantáneo';
  if (seconds < 60) return `${seconds.toFixed(2)} segundos`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes.toFixed(2)} minutos`;
  const hours = minutes / 60;
  if (hours < 24) return `${hours.toFixed(2)} horas`;
  const days = hours / 24;
  if (days < 365) return `${days.toFixed(2)} días`;
  const years = days / 365;
  if (years < 1e6) return `${years.toLocaleString('es-MX')} años`;
  return 'Millones de años';
};

/**

 * @param {string} password La contraseña del usuario.
 * @param {Set<string>} commonPasswordsSet El Set con las contraseñas comunes.
 * @returns {string|null} La subcadena común encontrada, o null si no se encuentra ninguna.
 */
const findPartialMatch = (password, commonPasswordsSet) => {
  const MIN_LENGTH = 5;

  for (const commonPass of commonPasswordsSet) {
    if (commonPass.length >= MIN_LENGTH && password.toLowerCase().includes(commonPass)) {
      return commonPass; 
    }
  }

  return null;
};


// Exportamos todas las funciones
module.exports = {
  calculateL,
  calculateN,
  calculateEntropy,
  checkPasswordStrength,
  calculateCrackTime,
  findPartialMatch,
};