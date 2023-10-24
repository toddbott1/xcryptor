"use strict";

// Note sjcl.js must be loaded into the page before this file

/** @class Encrypts and decrypts data in the browser for APEX apps. Also hashes passwords. */
class XCryptor {

	// Constants

	static get HEXTAG_DEK () { return "786b3031"; } // Hex tag for XCryptor v1 dek ("xk01" in ascii)
	static get HEXTAG_DATA () { return "78643031"; } // Hex tag for XCryptor v1 data ("xd01" in ascii)
	static get PARANOIA () { return 6; } // The sjcl paranoia level
	static get BITSPERBYTE () { return 8; } // 8-bit bytes
	static get BYTESPERWORD () { return 4; } // 2-byte words
	static get DERIVATION_ROUNDS () { return 10000; } // 10k rounds for pwd-to-key derivation
	static get SALT_SIZE () { return 8; } // In bytes
	static get TAG_SIZE () { return 4; } // In bytes
	static get IV_SIZE () { return 16; } // In bytes
	static get HMAC_SIZE () { return 32; } // In bytes
	static get BLOCK_SIZE () { return 16; } // In bytes. Note AES block size is always 128 bits
	static get KEY_WRAPPER_EXACT_SIZE () { return XCryptor.TAG_SIZE
		+ XCryptor.SALT_SIZE // Salt for crypt
		+ XCryptor.SALT_SIZE // Salt for hmac
		+ XCryptor.IV_SIZE
		+ XCryptor.HMAC_SIZE
		+ XCryptor.BLOCK_SIZE; } // Block for start of CBC chain
	static get DATA_WRAPPER_MAX_SIZE () { return XCryptor.TAG_SIZE
		+ XCryptor.IV_SIZE
		+ XCryptor.HMAC_SIZE
		+ XCryptor.BLOCK_SIZE // Block for start of CBC chain
		+ XCryptor.BLOCK_SIZE ;} // Possible block for padding up to block boundary

	static get PLAIN_DEK_SIZE () { return 32; } // Size of plain 256 bit dek in bytes
	static get ENCRYPTED_DEK_SIZE () { return XCryptor.PLAIN_DEK_SIZE // Size of encrypted dek in bytes
		+ XCryptor.KEY_WRAPPER_EXACT_SIZE; }

	static get ENCRYPTED_DATA_MIN_SIZE () { return XCryptor.BLOCK_SIZE; } // In bytes
	static get ENCRYPTED_NOTE_MAX_SIZE () { return 32767;} // In bytes
	static get ENCRYPTED_FILENAME_MAX_SIZE () { return 256;} // In bytes
	static get ENCRYPTED_FILETYPE_MAX_SIZE () { return 256;} // In bytes
	static get ENCRYPTED_FILEDATA_MAX_SIZE () { return 16777216;} // In bytes

	static get PLAIN_DATA_MIN_SIZE () { return 1; } // In bytes
	static get PLAIN_NOTE_MAX_SIZE () { return XCryptor.ENCRYPTED_NOTE_MAX_SIZE // In bytes
		- XCryptor.DATA_WRAPPER_MAX_SIZE; }
	static get PLAIN_FILENAME_MAX_SIZE () { return XCryptor.ENCRYPTED_FILENAME_MAX_SIZE // In bytes
		- XCryptor.DATA_WRAPPER_MAX_SIZE; }
	static get PLAIN_FILETYPE_MAX_SIZE () { return XCryptor.ENCRYPTED_FILETYPE_MAX_SIZE // In bytes
		- XCryptor.DATA_WRAPPER_MAX_SIZE; }
	static get PLAIN_FILEDATA_MAX_SIZE () { return XCryptor.ENCRYPTED_FILEDATA_MAX_SIZE // In bytes
		- XCryptor.DATA_WRAPPER_MAX_SIZE; }

	static get PWD_MIN_LENGTH () { return 15; } // In characters
	static get PWD_MAX_LENGTH () { return 64; } // In characters
	static get PWD_SALT_SIZE () { return 32; } // In bytes
	static get PWD_DIGEST_SIZE () { return 32; } // In bytes

	static get TYPE_NOTE () { return 0; }
	static get TYPE_FILENAME () { return 1; }
	static get TYPE_FILETYPE () { return 2; }
	static get TYPE_FILEDATA () { return 3; }

	// Errors and warnings

	static get WARN_CBC_USED () { return "CBC mode is dangerous because it doesn't protect message "
		+ "integrity.";}
	static get ERR_NOT_READY () { return "Crypto number generator not ready"; }
	static get ERR_BAD_PWD () { return "Missing or invalid password. It must be " + XCryptor.PWD_MIN_LENGTH
		+ "-" +  XCryptor.PWD_MAX_LENGTH + " characters long"; }
	static get ERR_BAD_PWD_DIGEST () { return "Missing or invalid digest input to password check"; }
	static get ERR_BAD_PWD_SALT () { return "Missing or invalid salt input to password check"; }
	static get ERR_BAD_DEK () { return "Invalid encrypted dek. Wrong type or length"; }
	static get ERR_BAD_TAG () { return "Invalid encryption tag. Not recognized, or wrong version"; }
	static get ERR_BAD_HMAC_CHECK () { return "Integrity check failed. Wrong password, or encrypted "
		+ "data is altered"; }
	static get ERR_BAD_INPUT_PARAMS () { return "Missing or invalid params passed to crypto"; }
	static get ERR_BAD_INPUT_TYPE () { return "Missing or invalid type input to crypto"; }
	static get ERR_BAD_INPUT_DATA () { return "Missing or invalid data input to crypto"; }

	// Static methods

	/**
	 * Detects a recent/supported browser.
	 * 
	 * @return {Boolean} True if supported browser, false if not.
	 */
	static detectBrowser () {
		let result = true;
		// Check for existance of a fairly recent CSS property (i.e. grid-row). If present, then EM6 and Crypto will be present too (verified at caniuse.com)
		if (!("gridRow" in document.createElement("div").style)) { result = false; }
		return result;
	}

	/**
	 * Hashes a password. Returns resulting password digest.
	 * 
	 * @param {String} pwd Password.
	 * @return {String} The resulting password digest as a b64 string.
	 * @throws {XCryptor.ERR_BAD_PWD} If password not passed or is invalid.
	 */
	static createPwdDigest (pwd) {
		if (!(pwd // Note trailing spaces in pwd are okay, so do not trim
			&& typeof pwd === "string"
			&& pwd.length >= XCryptor.PWD_MIN_LENGTH
			&& pwd.length <= XCryptor.PWD_MAX_LENGTH))
		{
			throw new Error(XCryptor.ERR_BAD_PWD);
		}

		return sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(pwd));
	}

	// Private methods

	/**
	 * Internal helper function to create 256-bit symmetric key from a password following the PBKDF2 standard. Note by using SJCL's default PBKDF2 implementation instead of adding a custom pseudo-random function, this will use sha256 as the hasher instead of sha1 (which is dictated by PBKDF2 spec).
	 * 
	 * @param {String} pwd Password.
	 * @param {Array} salt Salt as sjcl.bitArray.
	 * @return {Array} The key as sjcl.bitArray.
	 */
	_keyFromPwd (pwd, salt) {
		return sjcl.misc.pbkdf2(pwd, salt, XCryptor.DERIVATION_ROUNDS, XCryptor.PLAIN_DEK_SIZE * XCryptor.BITSPERBYTE);
	}

	// Public mehtods

	/**
	 * Creates an instance of XCryptor.
	 * 
	 * @constructor
	 * @param {String} pwd Password.
	 * @param {String} dek Encrypted dek (optional) as b64 string. If not passed, an encrypted dek is created and cached internally.
	 * @throws {XCryptor.ERR_NOT_READY} If crypto randomness is not ready.
	 * @throws {XCryptor.ERR_BAD_PWD} If password not passed or is invalid.
	 * @throws {XCryptor.ERR_BAD_DEK} If encrypted dek is invalid type or length.
	 * @throws {XCryptor.ERR_BAD_TAG} If encrypted dek is invalid - not recognized or wrong version.
	 * @throws {XCryptor.ERR_BAD_HMAC_CHECK} If wrong password or encrypted dek is altered.
	 */
	constructor (pwd, dek = "") {
		if (!sjcl.random.isReady(XCryptor.PARANOIA)) {
			throw new Error(XCryptor.ERR_NOT_READY);
		}

		if (!(pwd // Note trailing spaces in pwd are okay, so do not trim
			&& typeof pwd === "string"
			&& pwd.length >= XCryptor.PWD_MIN_LENGTH
			&& pwd.length <= XCryptor.PWD_MAX_LENGTH))
		{
			throw new Error(XCryptor.ERR_BAD_PWD);
		}

		let dekbits = [];

		if (dek) {
			if (!(typeof dek === "string"
				&& Array.isArray(dekbits = sjcl.codec.base64.toBits(dek))
				&& sjcl.bitArray.bitLength(dekbits) / XCryptor.BITSPERBYTE === XCryptor.ENCRYPTED_DEK_SIZE))
			{
				throw new Error(XCryptor.ERR_BAD_DEK);
			} else {
				let index = 0;

				if (sjcl.codec.hex.fromBits(sjcl.bitArray.bitSlice(dekbits, index * XCryptor.BITSPERBYTE, (index + XCryptor.TAG_SIZE) * XCryptor.BITSPERBYTE)).toUpperCase() !== XCryptor.HEXTAG_DEK.toUpperCase()) {
					throw new Error(XCryptor.ERR_BAD_TAG);
				}
				index += XCryptor.TAG_SIZE;
	
				let saltkeyforcrypt = sjcl.bitArray.bitSlice(dekbits, index * XCryptor.BITSPERBYTE, (index + XCryptor.SALT_SIZE) * XCryptor.BITSPERBYTE);
				let keyforcrypt = this._keyFromPwd(pwd, saltkeyforcrypt);
				index += XCryptor.SALT_SIZE;
				let saltkeyforhmac = sjcl.bitArray.bitSlice(dekbits, index * XCryptor.BITSPERBYTE, (index + XCryptor.SALT_SIZE) * XCryptor.BITSPERBYTE);
				let keyforhmac = this._keyFromPwd(pwd, saltkeyforhmac);
				index += XCryptor.SALT_SIZE;
				let ivforcrypt = sjcl.bitArray.bitSlice(dekbits, index * XCryptor.BITSPERBYTE, (index + XCryptor.IV_SIZE) * XCryptor.BITSPERBYTE);
				index += XCryptor.IV_SIZE;
	
				let hmaclocation = sjcl.bitArray.bitLength(dekbits) - (XCryptor.HMAC_SIZE * XCryptor.BITSPERBYTE);
				let hmacactual = sjcl.bitArray.bitSlice(dekbits, hmaclocation);
				let hmacexpected = new sjcl.misc.hmac(keyforhmac, sjcl.hash.sha256)
					.encrypt(sjcl.bitArray.bitSlice(dekbits, 0, hmaclocation));
				if (!sjcl.bitArray.equal(hmacactual, hmacexpected)) {
					throw new Error(XCryptor.ERR_BAD_HMAC_CHECK);
				}

				let aescrypt = new sjcl.cipher.aes(keyforcrypt);
				sjcl.beware[XCryptor.WARN_CBC_USED]();
				dekbits = sjcl.mode.cbc.decrypt(aescrypt, sjcl.bitArray.bitSlice(dekbits, index * XCryptor.BITSPERBYTE, hmaclocation), ivforcrypt);
			}
		}
		else {
			dekbits = sjcl.random.randomWords((XCryptor.PLAIN_DEK_SIZE / XCryptor.BYTESPERWORD), XCryptor.PARANOIA);
		}

		/** @member {String} _pwd The user password. */
		this._pwd = pwd;

		/** @member {Array} _dekbits Plain data encryption key as sjcl.bitArray. */
		this._dekbits = dekbits;
	}

	/**
	 * Sets the password. This is what the caller should invoke to execute password rotation.
	 * 
	 * @param {String} pwd New password.
	 * @throws {XCryptor.ERR_BAD_PWD} If password not passed or is invalid.
	 */
	set pwd (pwd) {
		if (!(pwd // Note trailing spaces in pwd are okay, so do not trim
			&& typeof pwd === "string"
			&& pwd.length >= XCryptor.PWD_MIN_LENGTH
			&& pwd.length <= XCryptor.PWD_MAX_LENGTH))
		{
			throw new Error(XCryptor.ERR_BAD_PWD);
		}

		this._pwd = pwd;

		// From here, the caller can then invoke XCryptor.dek getter method to obtain encrypted dek that is stamped with this new password. See immediately below
	}
	
	/**
	 * Returns the encrypted dek.
	 * 
	 * @return {String} The encrypted dek (as b64 string).
	 */
	get dek () {
		let encdek = sjcl.bitArray.concat([], sjcl.codec.hex.toBits(XCryptor.HEXTAG_DEK));

		let saltkeyforcrypt = sjcl.random.randomWords((XCryptor.SALT_SIZE / XCryptor.BYTESPERWORD)
			, XCryptor.PARANOIA);
		let keyforcrypt = this._keyFromPwd(this._pwd, saltkeyforcrypt);
		encdek = sjcl.bitArray.concat(encdek, saltkeyforcrypt);

		let saltkeyforhmac = sjcl.random.randomWords((XCryptor.SALT_SIZE / XCryptor.BYTESPERWORD)
			, XCryptor.PARANOIA);
		let keyforhmac = this._keyFromPwd(this._pwd, saltkeyforhmac);
		encdek = sjcl.bitArray.concat(encdek, saltkeyforhmac);

		let ivforcrypt = sjcl.random.randomWords((XCryptor.IV_SIZE / XCryptor.BYTESPERWORD)
			, XCryptor.PARANOIA);
		encdek = sjcl.bitArray.concat(encdek, ivforcrypt);

		let aescrypt = new sjcl.cipher.aes(keyforcrypt);
		sjcl.beware[XCryptor.WARN_CBC_USED]();
		encdek = sjcl.bitArray.concat(encdek, sjcl.mode.cbc.encrypt(aescrypt, this._dekbits, ivforcrypt));

		let hmac = new sjcl.misc.hmac(keyforhmac, sjcl.hash.sha256).encrypt(encdek);

		return sjcl.codec.base64.fromBits(sjcl.bitArray.concat(encdek, hmac));
	}

	/**
	 * Encrypts data using the cached dek.
	 * 
	 * @param {Object} params The input/output. Object used so can pass large amount of data by ref instead of by value (e.g. for large file data). Should contain a data property and a type property. The type property should be one of XCryptor.TYPE_NOTE, XCryptor.TYPE_FILENAME, XCryptor.TYPE_FILETYPE, or XCryptor.TYPE_FILEDATA. The data property should be plain data in and will be encrypted data out. For anything but TYPE_FILEDATA, the data property should be passed as regular string and will be returned as b64 string. Specifically for TYPE_FILEDATA, the data property should be passed as ArrayBuffer and will be returned as b64 string.
	 * @throws {XCryptor.ERR_BAD_INPUT_PARAMS} If params is not passed.
	 * @throws {XCryptor.ERR_BAD_INPUT_DATA} If data input is not passed or is invalid.
	 * @throws {XCryptor.ERR_BAD_INPUT_TYPE} If type input is not passed or is invalid.
	 */
	encrypt (params) {
		if (!params) {
			throw new Error(XCryptor.ERR_BAD_INPUT_PARAMS);
		}

		if (!("type" in params)
			|| typeof params.type !== "number"
			|| (params.type !== XCryptor.TYPE_NOTE
				&& params.type !== XCryptor.TYPE_FILENAME
				&& params.type !== XCryptor.TYPE_FILETYPE
				&& params.type !== XCryptor.TYPE_FILEDATA))
		{
			throw new Error(XCryptor.ERR_BAD_INPUT_TYPE);
		}

		let datalength = -1;

		if (!("data" in params)
			|| (params.type === XCryptor.TYPE_NOTE
				&& (typeof params.data !== "string"
					|| !Array.isArray(params.data = sjcl.codec.utf8String.toBits(params.data))
					|| (datalength = sjcl.bitArray.bitLength(params.data) / XCryptor.BITSPERBYTE) > XCryptor.PLAIN_NOTE_MAX_SIZE))
			|| (params.type === XCryptor.TYPE_FILENAME
				&& (typeof params.data !== "string"
					|| !Array.isArray(params.data = sjcl.codec.utf8String.toBits(params.data))
					|| (datalength = sjcl.bitArray.bitLength(params.data) / XCryptor.BITSPERBYTE) > XCryptor.PLAIN_FILENAME_MAX_SIZE))
			|| (params.type === XCryptor.TYPE_FILETYPE
				&& (typeof params.data !== "string"
					|| !Array.isArray(params.data = sjcl.codec.utf8String.toBits(params.data))
					|| (datalength = sjcl.bitArray.bitLength(params.data) / XCryptor.BITSPERBYTE) > XCryptor.PLAIN_FILETYPE_MAX_SIZE))
			|| (params.type === XCryptor.TYPE_FILEDATA
				&& (typeof params.data !== "object"
					|| !(params.data instanceof ArrayBuffer)
					|| !Array.isArray(params.data = sjcl.codec.bytes.toBits(new Uint8Array(params.data)))
					|| (datalength = sjcl.bitArray.bitLength(params.data) / XCryptor.BITSPERBYTE) > XCryptor.PLAIN_FILEDATA_MAX_SIZE))
			|| datalength < XCryptor.PLAIN_DATA_MIN_SIZE)
		{
			throw new Error(XCryptor.ERR_BAD_INPUT_DATA);
		}

		let edata = sjcl.bitArray.concat([], sjcl.codec.hex.toBits(XCryptor.HEXTAG_DATA));
		let ivforcrypt = sjcl.random.randomWords((XCryptor.IV_SIZE / XCryptor.BYTESPERWORD), XCryptor.PARANOIA);
		edata = sjcl.bitArray.concat(edata, ivforcrypt);

		let aescrypt = new sjcl.cipher.aes(this._dekbits);
		sjcl.beware[XCryptor.WARN_CBC_USED]();
		
		edata = sjcl.bitArray.concat(edata, sjcl.mode.cbc.encrypt(aescrypt, params.data, ivforcrypt));

		let hmac = new sjcl.misc.hmac(this._dekbits, sjcl.hash.sha256).encrypt(edata);
		edata = sjcl.bitArray.concat(edata, hmac);

		params.data =  sjcl.codec.base64.fromBits(edata);
	}

	/**
	 * Decrypts data using the cached dek.
	 * 
	 * @param {Object} params The input/output. Object used so can pass large amount of data by ref instead of by value (e.g. for large file data). Should contain a data property and a type property. The type property should be one of XCryptor.TYPE_NOTE, XCryptor.TYPE_FILENAME, XCryptor.TYPE_FILETYPE, or XCryptor.TYPE_FILEDATA. The data property should be encrypted data in and will be plain data out. For anything but TYPE_FILEDATA, the data property should be passed as b64 string and will be returned as regular string. Specifically for TYPE_FILEDATA, the data property should be passed as b64 string and will be returned as ArrayBuffer.
	 * @throws {XCryptor.ERR_BAD_INPUT_PARAMS} If params is not passed.
	 * @throws {XCryptor.ERR_BAD_INPUT_DATA} If data input is not passed or is invalid.
	 * @throws {XCryptor.ERR_BAD_INPUT_TYPE} If type input is not passed or is invalid.
	 * @throws {XCryptor.ERR_BAD_TAG} If encrypted data is invalid - not recognized or wrong version.
	 * @throws {XCryptor.ERR_BAD_HMAC_CHECK} If wrong password or encrypted data is altered.
	 */
	decrypt (params) {
		if (!params) {
			throw new Error(XCryptor.ERR_BAD_INPUT_PARAMS);
		}

		if (!("type" in params)
			|| typeof params.type !== "number"
			|| (params.type !== XCryptor.TYPE_NOTE
				&& params.type !== XCryptor.TYPE_FILENAME
				&& params.type !== XCryptor.TYPE_FILETYPE
				&& params.type !== XCryptor.TYPE_FILEDATA))
		{
			throw new Error(XCryptor.ERR_BAD_INPUT_TYPE);
		}

		let datalength = -1;

		if (!("data" in params)
			|| typeof params.data !== "string"
			|| !Array.isArray(params.data = sjcl.codec.base64.toBits(params.data))
			|| (datalength = sjcl.bitArray.bitLength(params.data) / XCryptor.BITSPERBYTE) < XCryptor.ENCRYPTED_DATA_MIN_SIZE
			|| (params.type === XCryptor.TYPE_NOTE && datalength > XCryptor.ENCRYPTED_NOTE_MAX_SIZE)
			|| (params.type === XCryptor.TYPE_FILENAME && datalength > XCryptor.ENCRYPTED_FILENAME_MAX_SIZE)
			|| (params.type === XCryptor.TYPE_FILETYPE && datalength > XCryptor.ENCRYPTED_FILETYPE_MAX_SIZE)
			|| (params.type === XCryptor.TYPE_FILEDATA && datalength > XCryptor.ENCRYPTED_FILEDATA_MAX_SIZE))
		{
			throw new Error(XCryptor.ERR_BAD_INPUT_DATA);
		}

		let index = 0;

		if (sjcl.codec.hex.fromBits(sjcl.bitArray.bitSlice(params.data, index * XCryptor.BITSPERBYTE, (index + XCryptor.TAG_SIZE) * XCryptor.BITSPERBYTE)).toUpperCase() !== XCryptor.HEXTAG_DATA.toUpperCase()) {
			throw new Error(XCryptor.ERR_BAD_TAG);
		}
		index += XCryptor.TAG_SIZE;

		let ivforcrypt = sjcl.bitArray.bitSlice(params.data, index * XCryptor.BITSPERBYTE, (index + XCryptor.IV_SIZE) * XCryptor.BITSPERBYTE);
		index += XCryptor.IV_SIZE;

		let hmaclocation = sjcl.bitArray.bitLength(params.data) - (XCryptor.HMAC_SIZE * XCryptor.BITSPERBYTE);
		let hmacactual = sjcl.bitArray.bitSlice(params.data, hmaclocation);
		let hmacexpected = new sjcl.misc.hmac(this._dekbits, sjcl.hash.sha256)
			.encrypt(sjcl.bitArray.bitSlice(params.data, 0, hmaclocation));
		if (!sjcl.bitArray.equal(hmacactual, hmacexpected)) {
			throw new Error(XCryptor.ERR_BAD_HMAC_CHECK);
		}

		let aescrypt = new sjcl.cipher.aes(this._dekbits);
		sjcl.beware[XCryptor.WARN_CBC_USED]();

		params.data = sjcl.mode.cbc.decrypt(aescrypt, sjcl.bitArray.bitSlice(params.data, index * XCryptor.BITSPERBYTE, hmaclocation), ivforcrypt);

		if (params.type === XCryptor.TYPE_FILEDATA) {
			params.data = (new Uint8Array(sjcl.codec.bytes.fromBits(params.data))).buffer;
		} else {
			params.data = sjcl.codec.utf8String.fromBits(params.data);
		}
	}
}