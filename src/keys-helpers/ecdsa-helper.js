import { PublicKey, Signature, Ecdsa} from 'starkbank-ecdsa';
import { stripCertificateContent,str2ab } from '../utils.js';
import forge from 'node-forge';

export const STARBANK_KEY_FORMAT = 'starkbank-ecdsa'

export async function getPEMFromECDSACertificate(pemKey) {
    // Try to parse the certificate with Web Crypto API
    try {
        return await getPEMFromCertificateCrypto(pemKey);
        
    } catch (cryptoError) {
        console.error('Crypto API failed, falling back to starkbank:', cryptoError, cryptoError.message);     
        // try to parse with starkbank-ecdsa                    
        return getStarkbankKey(pemKey);
    }
}

export async function getPEMFromCertificateCrypto(pemKey) {
    // Strip the header, footer, and line breaks
    const pemContents = stripCertificateContent(pemKey)
    const binaryDerString = window.atob(pemContents);
    const keyBuffer = str2ab(binaryDerString);

    // testing if this is a ECDSA key, trying to import with curves P-256, P-384, P-521
    const curves = ['P-256', 'P-384', 'P-521'];
    for (const curve of curves) {
        const key = await crypto.subtle.importKey(
            'spki',
            keyBuffer,
            {
                name: "ECDSA",
                namedCurve: curve
            },
            true,
            ["verify"]
        );
        return { 
            key: key, 
            format: 'certificate',
            pem: pemKey
        };
 
    }
}
export function getStarkbankKey(pemKey) {
    try {                       
        const key = PublicKey.fromPem(pemKey);
        console.log('starkbank-ecdsa imported successfully, key.curve=', key.curve, 'returning the imported key');                        
        return { 
            key: key, 
            format: STARBANK_KEY_FORMAT,
            pem: pemKey
        };
    } catch (starkbankError) {
        console.error('Starkbank-ECDSA import key failed:', starkbankError, starkbankError.message);
        throw new Error('Failed to parse certificate: ' + starkbankError.message);
    }
}


// Function to verify signature using starkbank-ecdsa
export async function verifyStarkbankSignature(pae, signatures, publicKey) {
    let counter = 0;
    let signatureValid = false;
    for (const signature of signatures) {
        counter++;               
        console.log('Attempting starkbank-ecdsa verification for signature:', counter);                
        try {
            // Convert the PAE to a hash using SHA-256
            const signatureBase64 = signature.sig;
            const signatureBinary = forge.util.decode64(signatureBase64);
            
            // Create a starkbank signature object
            const starkbankSignature = Signature.fromDer(signatureBinary);            
            // Verify the signature
            signatureValid = Ecdsa.verify(pae, starkbankSignature, publicKey);            
        } catch (error) {
            console.error('Starkbank signature verification error:', error);
            throw new Error('Starkbank signature verification failed: ' + error.message);
        }

        if (signatureValid) {
            console.log('Starkbank-ECDSA signature verification succeeded');
            return true;
        }        
    }
    console.log('Starkbank-ECDSA none of the signatures verification succeeded');
    return false;
    
}