/* global describe, before, it */

import { expect } from 'chai';
import ldapSsha from '../index.js';


const testData = {
	SSHA: {
		saltedHash: '{SSHA}jsk+Rnsm5Xy50uUOZ48scedXjgMrhj/LIPHvEg==',
		secret:'foo',
		valid: true
	},
	'SSHA-invalid': {
		saltedHash: '{SSHA}jsk+Rnsm5Xy50uUOZ48scedXjgMrhj/LIPHvEg==',
		secret:'foo1234',
		valid: false
	},
	SSHA256: {
		saltedHash: '{SSHA256}A6l9GxNPXvtT1R9C0qC1KyRdD2mLZiXPKKVKOz+W5a4Cx+oyEIlRvA==',
		secret: 'bar',
		valid: true
	},
	'SSHA256-invalid': {
		saltedHash: '{SSHA256}A6l9GxNPXvtT1R9C0qC1KyRdD2mLZiXPKKVKOz+W5a4Cx+oyEIlRvA==',
		secret: 'bar1234',
		valid: false
	},
	SSHA384: {
		saltedHash: '{SSHA384}crAsmQ7GasdQjctQs2VjVBm532rKR9ihpFYAhDpRP1E4L9hbGFik63hxNmGCDmVd2GTeyPn9UtM=',
		secret:'biz',
		valid: true
	},
	'SSHA384-invalid': {
		saltedHash: '{SSHA384}crAsmQ7GasdQjctQs2VjVBm532rKR9ihpFYAhDpRP1E4L9hbGFik63hxNmGCDmVd2GTeyPn9UtM=',
		secret:'biz1234',
		valid: false
	},
	SSHA512: {
		saltedHash: '{SSHA512}CGnLQnIBt+A3CC4AD9ASgRsexef99ra3ygBRqbnev+JU5iUpin2PwXbvHG6/q+aUGKYqe+Rg2laFrc1IS6dh9rZUWDP0+Vog',
		secret:'baz',
		valid: true
	},
	'SSHA512-invalid': {
		saltedHash: '{SSHA512}CGnLQnIBt+A3CC4AD9ASgRsexef99ra3ygBRqbnev+JU5iUpin2PwXbvHG6/q+aUGKYqe+Rg2laFrc1IS6dh9rZUWDP0+Vog',
		secret:'baz1234',
		valid: false
	}
};


describe('LdapSsha', function() {
	describe('verify', function () {
		for (let algorithm in testData) {
			it(algorithm, function() {
				let data = testData[algorithm];
				let result = ldapSsha.verify(data.secret, data.saltedHash);

				if (data.valid) {
					expect(result).to.be.true;
				}
				else {
					expect(result).to.be.false;
				}
			});
		}
	});
});
