import { Signature, Ecdsa} from 'starkbank-ecdsa';
import forge from 'node-forge';
import * as openpgp from 'openpgp';

export async function verifyOpenPGPSignature(pae, signatures, publicKey) {
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




// Helper function for forge.js verification
export async function verifyWithForge(pae, signatures, publicKey) {
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
