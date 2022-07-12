import crypto from 'crypto';


/**
 * @module LdapSsha
 ***/

export default class LdapSsha {
	constructor() {
		this._hashes = crypto.getHashes();
		this._hashLength = {};
	}

	/**
	 * List of system supported hash algorithms.
	 *
	 * @property _hashes
	 * @private
	 **/

	 /**
	  * Cache of hash lengths keyed by algorithm.
	  *
	  * @property _hashLength
	  * @private
	  **/


	/**
	 * Create a hash for a given salt algorithm.  Example SSHA, SSHA256
	 *
	 * @method _createHash
	 * @private
	 * @param {String} algorithm
	 * @return {Hash}
	 **/

	_createHash(algorithm) {
		if (algorithm.slice(0,4) !== 'SSHA') {
			throw new Error(`Unsupported algorithm "${algorithm}".`);
		}

		let hashAlgorithm = algorithm.slice(1).toLowerCase();

		// 	Translate {SSHA} to sha1
		if (hashAlgorithm === 'sha') {
			hashAlgorithm += '1';
		}


		// Make sure it is a supported algorithm.
		if (this._hashes.indexOf(hashAlgorithm) === -1) {
			throw new Error(`Unsupported algorithm "${algorithm}".`);
		}

		return crypto.createHash(hashAlgorithm);
	}


	/**
	 * Get the byte length of a hash algorithm.
	 *
	 * @method _getHashLength
	 * @private
	 * @param {String} algorithm
	 * @return {Number}
	 **/

	_getHashLength(algorithm) {
		if (!this._hashLength[algorithm]) {
			let hash = this._createHash(algorithm);
  			hash.update('foo');

  			let buf = hash.digest();
			this._hashLength[algorithm] = buf.length;
		}

		return this._hashLength[algorithm];
	}


	/**
	 * Verify a salted hash and secret.
	 *
	 * @method verify
	 * @param {String} secret
	 * @param {String} saltedHash
	 * @return {Boolean}
	 **/

	verify(secret, saltedHash) {
		let end = saltedHash.indexOf('}');
		if (end === -1) {
			throw new Error('Invalid salted hash.');
		}

		let algorithm = saltedHash.slice(1, end);
		let hashLen = this._getHashLength(algorithm);

		let buf = Buffer.from(saltedHash.slice(end + 1), "base64");

		let hash = buf.slice(0, hashLen);
		let salt = buf.slice(hashLen);

		return (this.hash(algorithm, secret, salt) === saltedHash);
	}


	/**
	 * Create a salted hash from a secret and optional salt.  If no salt is provided, one will be automatically generated.
	 *
	 * @method verify
	 * @param {String} algorithm
	 * @param {String} secret
	 * @param {String} [salt]
	 * @return {String}
	 **/

	hash(algorithm, secret, salt) {
		if (!salt) {
			salt = crypto.randomBytes(32);
		}

		let hash = this._createHash(algorithm);
		hash.update(secret);
		hash.update(salt);

		let buf = hash.digest();
		buf = Buffer.concat([buf, salt]);

		return `{${algorithm}}` + buf.toString('base64');
	}
}
