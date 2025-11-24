"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const SALT_LENGTH_BYTES = 16;
const AES_GCM_IV_LENGTH = 12;
const PADDED_RECORD_LENGTH = MAX_PASSWORD_LENGTH + 1; // 1 byte for length metadata
const VERSION = 1;

const DOMAIN_INFO = "domain-key-derivation";
const ENCRYPTION_INFO = "encryption-key-derivation";
const VERIFIER_INFO = "password-verifier";

function ensureString(value, label) {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
}

async function deriveMasterBits(password, salt) {
  const passwordKey = await subtle.importKey(
    "raw",
    stringToBuffer(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    passwordKey,
    256
  );

  return Buffer.from(derivedBits);
}

async function importHmacKey(rawKey) {
  return subtle.importKey(
    "raw",
    rawKey,
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );
}

async function deriveSubKey(masterHmacKey, label) {
  const material = await subtle.sign("HMAC", masterHmacKey, stringToBuffer(label));
  return Buffer.from(material);
}

async function deriveKeyMaterial(password, salt) {
  const masterBits = await deriveMasterBits(password, salt);
  const masterHmacKey = await importHmacKey(masterBits);

  const domainKeyMaterial = await deriveSubKey(masterHmacKey, DOMAIN_INFO);
  const encryptionKeyMaterial = await deriveSubKey(masterHmacKey, ENCRYPTION_INFO);
  const verifierMaterial = await deriveSubKey(masterHmacKey, VERIFIER_INFO);

  const domainLookupKey = await subtle.importKey(
    "raw",
    domainKeyMaterial,
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const passwordEncryptionKey = await subtle.importKey(
    "raw",
    encryptionKeyMaterial,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );

  return {
    domainLookupKey,
    passwordEncryptionKey,
    verifier: encodeBuffer(verifierMaterial),
  };
}

async function computeSha256Base64(serialized) {
  const buffer = typeof serialized === "string" ? stringToBuffer(serialized) : serialized;
  const digest = await subtle.digest("SHA-256", buffer);
  return encodeBuffer(Buffer.from(digest));
}

function padPassword(value) {
  const valueBuffer = stringToBuffer(value);
  if (valueBuffer.length > MAX_PASSWORD_LENGTH) {
    throw new Error("Password exceeds maximum supported length");
  }
  const padded = new Uint8Array(PADDED_RECORD_LENGTH);
  padded[0] = valueBuffer.length;
  padded.set(valueBuffer, 1);

  if (valueBuffer.length < MAX_PASSWORD_LENGTH) {
    const padding = getRandomBytes(MAX_PASSWORD_LENGTH - valueBuffer.length);
    padded.set(padding, 1 + valueBuffer.length);
  }

  return padded;
}

function unpadPassword(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    buffer = new Uint8Array(buffer);
  }

  if (buffer.length < PADDED_RECORD_LENGTH) {
    throw new Error("Corrupted record detected");
  }

  const length = buffer[0];
  if (length > MAX_PASSWORD_LENGTH) {
    throw new Error("Invalid password length metadata");
  }

  const passwordBytes = buffer.slice(1, 1 + length);
  return bufferToString(passwordBytes);
}

function createEmptyKvs() {
  return Object.create(null);
}

function cloneKvs(kvs) {
  const result = createEmptyKvs();
  for (const key of Object.keys(kvs || {})) {
    const entry = kvs[key];
    if (
      entry &&
      typeof entry === "object" &&
      typeof entry.iv === "string" &&
      typeof entry.ciphertext === "string"
    ) {
      result[key] = { iv: entry.iv, ciphertext: entry.ciphertext };
    } else {
      throw new Error("Invalid KVS record detected");
    }
  }
  return result;
}

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor({ data, secrets } = {}) {
    if (!data || !secrets) {
      throw new Error("Keychain must be initialized using init or load");
    }
    this.data = data;
    this.secrets = secrets;
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    ensureString(password, "password");
    const saltBytes = getRandomBytes(SALT_LENGTH_BYTES);
    const { domainLookupKey, passwordEncryptionKey, verifier } = await deriveKeyMaterial(password, saltBytes);

    const data = {
      version: VERSION,
      salt: encodeBuffer(saltBytes),
      verifier,
      kvs: createEmptyKvs(),
    };

    const secrets = {
      domainLookupKey,
      passwordEncryptionKey,
    };

    return new Keychain({ data, secrets });
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    ensureString(password, "password");
    ensureString(repr, "representation");

    if (trustedDataCheck !== undefined) {
      ensureString(trustedDataCheck, "trustedDataCheck");
      const computed = await computeSha256Base64(repr);
      if (computed !== trustedDataCheck) {
        throw new Error("Trusted data hash mismatch detected");
      }
    }

    const parsed = JSON.parse(repr);
    if (!parsed || typeof parsed !== "object") {
      throw new Error("Invalid serialized keychain");
    }

    if (!parsed.salt || typeof parsed.salt !== "string") {
      throw new Error("Missing salt in serialized data");
    }

    if (!parsed.verifier || typeof parsed.verifier !== "string") {
      throw new Error("Missing verifier in serialized data");
    }

    const saltBytes = decodeBuffer(parsed.salt);
    const { domainLookupKey, passwordEncryptionKey, verifier } = await deriveKeyMaterial(password, saltBytes);

    if (verifier !== parsed.verifier) {
      throw new Error("Invalid password for keychain");
    }

    const data = {
      version: parsed.version || VERSION,
      salt: parsed.salt,
      verifier: parsed.verifier,
      kvs: cloneKvs(parsed.kvs || {}),
    };

    const secrets = {
      domainLookupKey,
      passwordEncryptionKey,
    };

    return new Keychain({ data, secrets });
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    const serialized = JSON.stringify({
      version: this.data.version,
      salt: this.data.salt,
      verifier: this.data.verifier,
      kvs: this.data.kvs,
    });

    const checksum = await computeSha256Base64(serialized);
    return [serialized, checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    ensureString(name, "name");
    const domainRef = await this._computeDomainReference(name);
    const record = this.data.kvs[domainRef.key];
    if (!record) {
      return null;
    }

    try {
      const plaintext = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: decodeBuffer(record.iv),
          additionalData: domainRef.aad,
        },
        this.secrets.passwordEncryptionKey,
        decodeBuffer(record.ciphertext)
      );

      return unpadPassword(new Uint8Array(plaintext));
    } catch (err) {
      throw new Error("Tampering detected while decrypting record");
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    ensureString(name, "name");
    ensureString(value, "value");

    const domainRef = await this._computeDomainReference(name);
    const padded = padPassword(value);
    const iv = getRandomBytes(AES_GCM_IV_LENGTH);

    const ciphertext = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: domainRef.aad,
      },
      this.secrets.passwordEncryptionKey,
      padded
    );

    this.data.kvs[domainRef.key] = {
      iv: encodeBuffer(iv),
      ciphertext: encodeBuffer(ciphertext),
    };
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    ensureString(name, "name");
    const domainRef = await this._computeDomainReference(name);
    if (!(domainRef.key in this.data.kvs)) {
      return false;
    }

    delete this.data.kvs[domainRef.key];
    return true;
  };

  async _computeDomainReference(name) {
    const mac = await subtle.sign(
      "HMAC",
      this.secrets.domainLookupKey,
      stringToBuffer(name)
    );

    const macBuffer = Buffer.from(mac);
    return {
      key: encodeBuffer(macBuffer),
      aad: macBuffer,
    };
  }
};

module.exports = { Keychain }
