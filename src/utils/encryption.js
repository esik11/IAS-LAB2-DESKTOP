const crypto = require('crypto');
const algorithm = 'aes-256-gcm';
const ivLength = 16;
const saltLength = 64;
const tagLength = 16;
const keyLength = 32;
const iterations = 100000;

class Encryption {
  static generateKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512');
  }

  static encrypt(text, encryptionKey = process.env.ENCRYPTION_KEY) {
    try {
      // Generate salt and IV
      const salt = crypto.randomBytes(saltLength);
      const iv = crypto.randomBytes(ivLength);

      // Generate key from password and salt
      const key = this.generateKey(encryptionKey, salt);

      // Create cipher
      const cipher = crypto.createCipheriv(algorithm, key, iv);

      // Encrypt the text
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      // Get auth tag
      const tag = cipher.getAuthTag();

      // Combine all components
      const result = salt.toString('hex') + 
                    iv.toString('hex') + 
                    tag.toString('hex') + 
                    encrypted;

      return result;
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  static decrypt(encryptedData, encryptionKey = process.env.ENCRYPTION_KEY) {
    try {
      // Extract components
      const salt = Buffer.from(encryptedData.slice(0, saltLength * 2), 'hex');
      const iv = Buffer.from(encryptedData.slice(saltLength * 2, (saltLength + ivLength) * 2), 'hex');
      const tag = Buffer.from(encryptedData.slice((saltLength + ivLength) * 2, (saltLength + ivLength + tagLength) * 2), 'hex');
      const encrypted = encryptedData.slice((saltLength + ivLength + tagLength) * 2);

      // Generate key from password and salt
      const key = this.generateKey(encryptionKey, salt);

      // Create decipher
      const decipher = crypto.createDecipheriv(algorithm, key, iv);
      decipher.setAuthTag(tag);

      // Decrypt the text
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt data');
    }
  }

  static hashPassword(password, salt = crypto.randomBytes(16)) {
    try {
      const hash = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512');
      return {
        hash: hash.toString('hex'),
        salt: salt.toString('hex')
      };
    } catch (error) {
      console.error('Password hashing error:', error);
      throw new Error('Failed to hash password');
    }
  }

  static verifyPassword(password, hash, salt) {
    try {
      const verifyHash = crypto.pbkdf2Sync(
        password,
        Buffer.from(salt, 'hex'),
        iterations,
        64,
        'sha512'
      ).toString('hex');
      return verifyHash === hash;
    } catch (error) {
      console.error('Password verification error:', error);
      throw new Error('Failed to verify password');
    }
  }

  // Encrypt object fields
  static encryptFields(obj, fields) {
    const encrypted = { ...obj };
    for (const field of fields) {
      if (obj[field]) {
        encrypted[field] = this.encrypt(obj[field].toString());
      }
    }
    return encrypted;
  }

  // Decrypt object fields
  static decryptFields(obj, fields) {
    const decrypted = { ...obj };
    for (const field of fields) {
      if (obj[field]) {
        try {
          decrypted[field] = this.decrypt(obj[field]);
        } catch (error) {
          console.error(`Failed to decrypt field ${field}:`, error);
          decrypted[field] = null;
        }
      }
    }
    return decrypted;
  }
}

module.exports = Encryption; 