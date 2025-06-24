import forge from 'node-forge';

export const RSA_PATTERN = '-----BEGIN RSA PUBLIC KEY-----'
export const RSA_KEY_FORMAT = 'rsaPublicKey'
export const CERTIFICATE_KEY_FORMAT = 'certificate'

export function getPEMFromCertificateRSA(pemKey) {
    console.log('Use forge if RSA certificate');
        const cert = forge.pki.certificateFromPem(pemKey);
        const publicKey = cert.publicKey;
        return { 
            key: publicKey, 
            format: CERTIFICATE_KEY_FORMAT,
            pem: pemKey
        };
}
export function getRSAPublicKey(pemKey) {
     // For RSA public keys
     try {
        console.log('Detected RSA public key format');
        const publicKey = forge.pki.publicKeyFromPem(pemKey);
        return { 
            key: publicKey, 
            format: RSA_KEY_FORMAT 
        };

    } catch (e) {
        console.error('Failed to parse RSA public key:', e);
        throw new Error('Failed to parse RSA public key: ' + e.message);
    }
}

// Helper function for forge.js verification
export async function verifyRSASignature(pae, signatures, publicKey) {
    console.log('Verifying with Forge.js');
    let counter = 0;
    for (const signature of signatures) {
        counter++;
        // Get the signature algorithm                
        const sigAlg = signature.keyid || '';
        console.log('Checking signature, signature algorithm/key ID:', sigAlg, 'signature number=', counter);
        // Create message digest based on signature algorithm (default to SHA-256)
        let md = forge.md.sha256.create();
        // Check if we can detect the algorithm from keyid
        if (sigAlg.toLowerCase().includes('sha1')) {
            md = forge.md.sha1.create();
        } else if (sigAlg.toLowerCase().includes('sha384')) {
            md = forge.md.sha384.create();
        } else if (sigAlg.toLowerCase().includes('sha512')) {
            md = forge.md.sha512.create();
        }
        // Update message digest with the properly encoded PAE data
        md.update(pae);
        
        // Convert base64 signature to binary
        const signatureBase64 = signature.sig;
        const signatureBinary = forge.util.decode64(signatureBase64);
        
        // Use the appropriate verification method based on the key
        try {
            const isValid = publicKey.verify(md.digest().bytes(), signatureBinary);
            console.log('Signature verification result:', isValid);
            return isValid;
        } catch (verifyError) {
            console.error('Verification failed with error:', verifyError, 'signature number=', counter);
            
            // Try an alternative approach if the first one fails
            try {
                console.log('Attempting alternative verification approach...');
                // Create a verifier
                const verifier = forge.pki.createVerifier(md.algorithm);
                verifier.update(pae);
                const isValid = verifier.verify(publicKey, signatureBinary);
                console.log('Alternative verification result:', isValid);
                return isValid;
            } catch (altError) {
                console.error('Alternative verification failed:', altError, 'signature number=', counter);
                console.info('Continue to next signature');
            }
        }
    }
    return false;
}