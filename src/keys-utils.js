import { PGP_PATTERN, getPGPPublicKey } from './keys-helpers/pgp-helper.js';
import { RSA_PATTERN, getRSAPublicKey } from './keys-helpers/rsa-helper.js';
import { CERTIFICATE_PATTERN, getPEMFromCertificate } from './keys-helpers/certificate-helper.js';
import { getStarkbankKey } from './keys-helpers/ecdsa-helper.js';

const PUBLIC_KEY_PATTERN = '-----BEGIN PUBLIC KEY-----'

// Function to extract and parse public key from PEM format
export async function extractPublicKeyFromPEM(pemKey) {
    try {
        console.log('extractPublicKeyFromPEM');       
        // Try different key types based on headers
        if (pemKey.includes(PUBLIC_KEY_PATTERN)) {
            // For standard public keys
            try {
                console.log('Detected standard public key format, testing if this is RSA key');
                return getRSAPublicKey(pemKey);
            } catch (e) {
                console.error('Failed to parse standard public key as RSA key:', e);
                console.log('Trying to import key using starkbank-ecdsa');
                try{
                    return getStarkbankKey(pemKey);
                } catch (e) {
                    console.error('Failed to import key using starkbank-ecdsa:', e);
                    throw new Error('Failed to parse public key: ' + e.message);
                }
            }
        } else if (pemKey.includes(CERTIFICATE_PATTERN)) {
            return getPEMFromCertificate(pemKey);            
        } else if (pemKey.includes(RSA_PATTERN)) {
            return await getRSAPublicKey(pemKey);
        } else if (pemKey.includes(PGP_PATTERN)) {
            // For PGP public keys
            return getPGPPublicKey(pemKey);
        } else {
            throw new Error('Unsupported key format. Expected PUBLIC KEY, RSA PUBLIC KEY, PGP PUBLIC KEY, or CERTIFICATE.');
        }
    } catch (error) {
        console.error('Key extraction error:', error);
        throw new Error(`Failed to extract key: ${error.message}`);
    }
}