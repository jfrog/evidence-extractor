import * as openpgp from 'openpgp';

import forge from 'node-forge';
export const PGP_PATTERN = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
export const PGP_KEY_FORMAT = 'pgpPublicKey'

export async function getPGPPublicKey(pemKey) {
    try {
        console.log('Detected PGP public key format');        
        // Use OpenPGP.js to read the public key
        try {
            // Read the PGP public key using OpenPGP.js
            const pgpPublicKey = await openpgp.readKey({ armoredKey: pemKey });
            console.log('Successfully parsed PGP public key');
            
            return {
                key: pgpPublicKey,
                format: PGP_KEY_FORMAT
            };
        } catch (e) {
            console.error('Failed to process PGP public key with OpenPGP.js:', e);
            throw new Error('Failed to process PGP public key: ' + e.message);
        }
        
    } catch (e) {
        console.error('Failed to parse PGP public key:', e);
        throw new Error('Failed to parse PGP public key: ' + e.message);
    }
}

//verifyOpenPGPSignature
export async function verifyPGPSignature(pae, signatures, publicKey) {
    try {                
        // Create a message from the PAE data for verification
        const message = await openpgp.createMessage({ text: pae });
        
        // loop over all signatures and verify each one
        let counter = 0;
        for (const signature of signatures) {
            counter++;   
            try {
                console.log('trying to verify signature number=', counter);
                // Convert signature to the right format for OpenPGP.js
                // OpenPGP.js expects an armored signature
                const signatureBase64 = signature.sig;
                const signatureBinary = forge.util.decode64(signatureBase64);
                // Create a detached signature object
                const detachedSignature = await openpgp.readSignature({
                    armoredSignature: signatureBinary
                });
                // Verify the signature using OpenPGP.js
                const verificationResult = await openpgp.verify({
                    message: message,
                    signature: detachedSignature,
                    verificationKeys: publicKey
                });
                // Check if the signature is valid
                const { verified, keyID } = verificationResult.signatures[0];
                try {
                    await verified; // This will throw if the signature is invalid
                    console.log('PGP signature verification succeeded');
                    return true;
                } catch (error) {
                    console.error('PGP signature verification failed:', error);
                }
            } catch (error) {
                console.error('Error during PGP verification of signature:', error, 'signature number=', counter);
                console.info('Continue to next signature');
            }
        }                           
    } catch (error) {
        console.error('Error during PGP verification:', error);
        throw new Error('PGP signature verification failed: ' + error.message);
    }
    console.log('OpenPGP none of the signatures verification succeeded');
    return false;
}

