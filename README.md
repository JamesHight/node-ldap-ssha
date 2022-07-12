LDAP SSHA
---------

LDAP salted password hashing library.  It supports all of the "sha" variants returned by `crypto.getHashes()`.


## Install
````bash
npm install -s ldap-ssha
````


## Usage

````javascript
const ldapSsha = require('ldap-ssha');

// LdapSssha.hash(algorithm, secret, salt)
let saltedHash = ldapSsha.hash('SSHA', 'foo');

// LdapSsha.verify(secret, saltedHash)
if (!ldapSsha.verify('bar', saltedHash)) {
	throw new Error('Invalid secret!');
}

let saltedHash512 = ldapSsha.hash('SSHA512', 'foo', 'optional salt');
if (ldapSsha.verify('foo', saltedHash512)) {
	console.log('Secret is valid!');
}
````
