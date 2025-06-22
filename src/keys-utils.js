import { stripCertificateContent,
    arrayBufferToBase64,
    createPEMHeader,
    createPEMFooter,
    formatPEM,
    str2ab
 } from './utils.js';

import { PublicKey, Signature, Ecdsa} from 'starkbank-ecdsa';
import { X509Certificate } from '@peculiar/x509';
import * as openpgp from 'openpgp';
import forge from 'node-forge';

export function extractPEMFromCertificate(certKey) {
    console.info('extractPEMFromCertificate');
    // get buffer from pemKey    
    const cert = new X509Certificate(certKey);
    const publicKey = cert.publicKey;
    // Convert public key to PEM format
    const base64Key = arrayBufferToBase64(publicKey.rawData);
    const pemKeyContent = createPEMHeader('PUBLIC KEY') + 
                  formatPEM(base64Key) + 
                  createPEMFooter('PUBLIC KEY');
    return pemKeyContent;
}

// Function to extract and parse public key from PEM format
export async function extractPublicKeyFromPEM(pemKey) {
    try {
        console.log('extractPublicKeyFromPEM');       
        // Try different key types based on headers
        if (pemKey.includes('-----BEGIN PUBLIC KEY-----')) {
            // For standard public keys
            try {
                console.log('Detected standard public key format');
                const publicKey = forge.pki.publicKeyFromPem(pemKey);
                return { 
                    key: publicKey, 
                    format: 'publicKey' 
                };
            } catch (e) {
                console.error('Failed to parse standard public key using forge:', e);
                console.log('Trying to import key using starkbank-ecdsa');
                try{
                    const key = PublicKey.fromPem(pemKey);
                    console.log('Imported key using starkbank-ecdsa, will now return it');
                    return { 
                        key: key, 
                        format: 'starkbank-ecdsa',
                        pem: pemKey
                    };
                } catch (e) {
                    console.error('Failed to import key using starkbank-ecdsa:', e);
                    throw new Error('Failed to parse public key: ' + e.message);
                }
            }
        } else if (pemKey.includes('-----BEGIN CERTIFICATE-----')) {
            // For X.509 certificates
            try {
                console.log('Detected X.509 certificate');
                const cert = forge.pki.certificateFromPem(pemKey);
                const publicKey = cert.publicKey;
                return { 
                    key: publicKey, 
                    format: 'certificate',
                    pem: pemKey
                };
            } catch (e) {
                console.error('Forge Failed to parse certificate, trying Web Crypto API:', e);
                // Try to parse the certificate with Web Crypto API
                try {
                    // Strip the header, footer, and line breaks
                    const pemContents = stripCertificateContent(pemKey)
                    const binaryDerString = window.atob(pemContents);
                    const keyBuffer = str2ab(binaryDerString);

                    //const hex = arrayBufferToHexString(keyBuffer);
                    const key = await crypto.subtle.importKey(
                        'spki',
                        keyBuffer,
                        {
                            name: "ECDSA",
                            namedCurve: "P-384"
                        },
                        true,
                        ["verify"]
                    );
                    return { 
                        key: key, 
                        format: 'certificate',
                        pem: pemKey
                    };
                } catch (cryptoError) {
                    console.error('Web Crypto API failed, falling back to starkbank:', cryptoError, cryptoError.message);     
                    // try to parse with starkbank-ecdsa                    
                    try {                       
                        const key = PublicKey.fromPem(pemKey);
                        console.log('Imported key using starkbank-ecdsa, will now retirn it');
                        return { 
                            key: key, 
                            format: 'starkbank-ecdsa',
                            pem: pemKey
                        };
                    } catch (starkbankError) {
                        console.error('Starkbank-ECDSA import key failed:', starkbankError, starkbankError.message);
                        throw new Error('Failed to parse certificate: ' + starkbankError.message);
                    }
                }
            }
        } else if (pemKey.includes('-----BEGIN RSA PUBLIC KEY-----')) {
            // For RSA public keys
            try {
                console.log('Detected RSA public key format');
                const publicKey = forge.pki.publicKeyFromPem(pemKey);
                return { 
                    key: publicKey, 
                    format: 'rsaPublicKey' 
                };
            } catch (e) {
                console.error('Failed to parse RSA public key:', e);
                throw new Error('Failed to parse RSA public key: ' + e.message);
            }
        } else if (pemKey.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
            // For PGP public keys
            try {
                console.log('Detected PGP public key format');
                
                // Use OpenPGP.js to read the public key
                try {
                    // Read the PGP public key using OpenPGP.js
                    const pgpPublicKey = await openpgp.readKey({ armoredKey: pemKey });
                    console.log('Successfully parsed PGP public key');
                    
                    return {
                        key: pgpPublicKey,
                        format: 'pgpPublicKey'
                    };
                } catch (e) {
                    console.error('Failed to process PGP public key with OpenPGP.js:', e);
                    throw new Error('Failed to process PGP public key: ' + e.message);
                }
                
            } catch (e) {
                console.error('Failed to parse PGP public key:', e);
                throw new Error('Failed to parse PGP public key: ' + e.message);
            }
        } else {
            throw new Error('Unsupported key format. Expected PUBLIC KEY, RSA PUBLIC KEY, PGP PUBLIC KEY, or CERTIFICATE.');
        }
    } catch (error) {
        console.error('Key extraction error:', error);
        throw new Error(`Failed to extract key: ${error.message}`);
    }
}