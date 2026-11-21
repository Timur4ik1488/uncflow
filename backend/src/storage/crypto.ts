import * as crypto from 'crypto';

export class SecretVault {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly MASTER_KEY = process.env.VAULT_SECRET_KEY || 'cyber-garden-2026-master-key-32b'; // 32 chars
  private static readonly KEY = crypto.scryptSync(this.MASTER_KEY, 'salt', 32);

  /**
   * Encrypt sensitive string (e.g. Telegram token, DB password)
   */
  public static encrypt(plainText: string): string {
    if (!plainText) return '';
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.ALGORITHM, this.KEY, iv);
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
  }

  /**
   * Decrypt sensitive string
   */
  public static decrypt(cipherText: string): string {
    if (!cipherText || !cipherText.includes(':')) return cipherText;
    try {
      const [ivHex, authTagHex, encryptedHex] = cipherText.split(':');
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      const decipher = crypto.createDecipheriv(this.ALGORITHM, this.KEY, iv);
      decipher.setAuthTag(authTag);
      let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch {
      return cipherText;
    }
  }

  /**
   * Masks secret for UI and logs (e.g., "ghp_12345678" -> "ghp_••••••78")
   */
  public static mask(secret: string): string {
    if (!secret) return '';
    if (secret.length <= 6) return '••••••';
    return secret.substring(0, 3) + '••••••••' + secret.substring(secret.length - 3);
  }

  /**
   * Cryptographically hashes user password with unique salt using scrypt
   */
  public static hashPassword(password: string): string {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
  }

  /**
   * Verifies plaintext password against stored salt:hash
   */
  public static verifyPassword(password: string, stored: string): boolean {
    if (!stored || !stored.includes(':')) return false;
    const [salt, hash] = stored.split(':');
    if (!salt || !hash) return false;
    try {
      const testHash = crypto.scryptSync(password, salt, 64).toString('hex');
      return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(testHash, 'hex'));
    } catch {
      return false;
    }
  }
}
