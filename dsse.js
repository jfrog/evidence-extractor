// Add event listener for file input
document.getElementById('fileInput').addEventListener('change', function(e) {
    const fileName = e.target.files[0]?.name || '';
    document.getElementById('fileName').textContent = fileName;
    
    if (fileName) {
        const file = e.target.files[0];
        const reader = new FileReader();
        
        reader.onload = function(e) {
            document.getElementById('dsseInput').value = e.target.result;
        };
        
        reader.readAsText(file);
    }
});

// Add event listener for certificate input
document.getElementById('certInput').addEventListener('change', function(e) {
    const fileName = e.target.files[0]?.name || '';
    document.getElementById('certFileName').textContent = fileName;

    if (fileName) {
        const file = e.target.files[0];
        const reader = new FileReader();
        
        reader.onload = function(e) {
            document.getElementById('pubKeyInput').value = e.target.result;
        };
        
        reader.readAsText(file);
    }
});

// Function to safely decode base64
function safeBase64Decode(base64String) {
    try {
        // Remove any non-base64 characters
        const cleanBase64 = base64String.replace(/[^A-Za-z0-9+/=]/g, '');
        
        // Add padding if needed
        let paddedBase64 = cleanBase64;
        const padding = cleanBase64.length % 4;
        if (padding) {
            paddedBase64 += '='.repeat(4 - padding);
        }
        
        // Use forge for base64 decoding
        return forge.util.decode64(paddedBase64);
    } catch (error) {
        console.error('Base64 decoding error:', error);
        throw new Error('Invalid base64 encoding in the key');
    }
}

// Helper function to replace literal \n with actual newlines
function replaceNewlines(text) {
    if (!text) return text;
    return text.replace(/\\n/g, '\n');
}

// Function to extract and parse public key from PEM format
async function extractPublicKeyFromPEM(pemKey) {
    try {
        console.log('Extracting public key from PEM...');
       
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
                console.error('Failed to parse standard public key:', e);
                throw new Error('Failed to parse public key: ' + e.message);
            }
        } else if (pemKey.includes('-----BEGIN CERTIFICATE-----')) {
            // For X.509 certificates
            try {
                console.log('Detected X.509 certificate');
                const cert = forge.pki.certificateFromPem(pemKey);
                const publicKey = cert.publicKey;
                return { 
                    key: publicKey, 
                    format: 'certificate' 
                };
            } catch (e) {
                console.error('Failed to parse certificate:', e);
                throw new Error('Failed to parse certificate: ' + e.message);
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

// Function to verify DSSE signature using forge.js
async function verifyDSSESignature(dsseEnvelope, publicKeyInfo) {
    try {
        console.log('Verifying signature with format:', publicKeyInfo.format);
        
        // Get the signature from the DSSE envelope
        if (!dsseEnvelope.signatures || dsseEnvelope.signatures.length === 0) {
            throw new Error('No signatures found in the DSSE envelope');
        }
        
        // Get the signature algorithm
        const sigAlg = dsseEnvelope.signatures[0].keyid || '';
        console.log('Signature algorithm/key ID:', sigAlg);
        
        // Convert base64 signature to binary
        const signatureBase64 = dsseEnvelope.signatures[0].sig;
        //console.log('signatureBase64', signatureBase64);
        const signatureBinary = forge.util.decode64(signatureBase64);
        console.log('signatureBinary', signatureBinary);
        
        // Get the encoded payload and payloadType
        const payload = dsseEnvelope.payload;
        const payloadDecoded = forge.util.decode64(payload);
        const payloadType = dsseEnvelope.payloadType;
        
        // Properly implement the DSSE PAE (Pre-Authentication Encoding) format
        // Format: "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
        const paePrefix = `DSSEv1 ${payloadType.length} ${payloadType} ${payloadDecoded.length} `;
        const pae = paePrefix + payloadDecoded;
        console.log('pae=', pae);
        const encodedPae = forge.util.encode64(pae);
        
        // Handle different key formats
        const publicKey = publicKeyInfo.key;
        console.log('publicKeyInfo.format=', publicKeyInfo.format);
        // Special handling for PGP keys
        if (publicKeyInfo.format === 'pgpPublicKey') {
            console.log('Verifying with PGP public key using OpenPGP.js');
            
            try {
                // Create a message from the PAE data for verification
                const message = await openpgp.createMessage({ text: pae });
                console.log('message=', message);

                // Convert signature to the right format for OpenPGP.js
                // OpenPGP.js expects an armored signature
                const armoredSignature = signatureBinary;
                
                // Create a detached signature object
                const detachedSignature = await openpgp.readSignature({
                    armoredSignature: armoredSignature
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
                    return false;
                }
            } catch (error) {
                console.error('Error during PGP verification:', error);
                throw new Error('PGP signature verification failed: ' + error.message);
            }
        }
        
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
        
        // Use the appropriate verification method based on the key
        try {
            const isValid = publicKey.verify(md.digest().bytes(), signatureBinary);
            console.log('Signature verification result:', isValid);
            return isValid;
        } catch (verifyError) {
            console.error('Verification failed with error:', verifyError);
            
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
                console.error('Alternative verification failed:', altError);
                throw new Error('Signature verification failed with both approaches');
            }
        }
    } catch (error) {
        console.error('Verification error:', error);
        throw new Error(`Signature verification failed: ${error.message}`);
    }
}

async function verifySignature(dsseEnvelope, verificationKey) {
    try {
        // Create a verification status element
        const statusDiv = document.getElementById('verificationStatus');
        statusDiv.style.display = 'block';
        statusDiv.className = 'verification-status unknown';
        statusDiv.textContent = 'Verifying signature...';
        
        // Make sure the right panel is visible
        const rightPanel = document.querySelector('.right-panel');
        rightPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        
        // Check if we have a certificate file or a pasted public key
        let keyText;
        
        if (verificationKey instanceof File) {
            // If it's a file, read it
            const reader = new FileReader();
            keyText = await new Promise((resolve, reject) => {
                reader.onload = e => resolve(e.target.result);
                reader.onerror = e => reject(new Error('Failed to read certificate file'));
                reader.readAsText(verificationKey);
            });
        } else {
            // If it's a string (pasted key), use it directly
            keyText = verificationKey;
        }
        
        // Basic key format validation
        if (!keyText.includes('-----BEGIN') || !keyText.includes('-----END')) {
            statusDiv.className = 'verification-status invalid';
            statusDiv.textContent = 'Error: Invalid key format. Expected PEM format.';
            return false;
        }
        
        console.log('keyText', keyText);
        
        // Extract the public key from PEM format
        const publicKeyInfo = await extractPublicKeyFromPEM(keyText);
        
        // Verify the DSSE signature
        const isValid = await verifyDSSESignature(dsseEnvelope, publicKeyInfo);
        
        if (isValid) {
            statusDiv.className = 'verification-status valid';
            statusDiv.textContent = 'Signature verification successful! The DSSE envelope is valid.';
            return true;
        } else {
            statusDiv.className = 'verification-status invalid';
            statusDiv.textContent = 'Signature verification failed. The DSSE envelope may have been tampered with.';
            return false;
        }
        
    } catch (error) {
        const statusDiv = document.getElementById('verificationStatus');
        statusDiv.style.display = 'block';
        statusDiv.className = 'verification-status invalid';
        statusDiv.textContent = `Error processing key: ${error.message}`;
        console.error('Full error:', error);
        
        // Provide more detailed help for common errors
        if (error.message.includes('format')) {
            const helpMessage = document.createElement('p');
            helpMessage.innerHTML = '<strong>Key format issue detected.</strong><br>' +
                'Make sure you\'re providing a valid PEM-formatted public key or certificate.';
            statusDiv.appendChild(helpMessage);
        }
        
        return false;
    }
}

// Properly export these functions to be accessible from HTML
async function processDSSE() {
    // Clear verification status
    const verificationStatus = document.getElementById('verificationStatus');
    verificationStatus.innerHTML = '';
    verificationStatus.style.display = 'none';
    verificationStatus.classList.remove('valid', 'invalid', 'unknown');
    
    const input = document.getElementById('dsseInput').value;
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('error');
    const pubKeyInput = document.getElementById('pubKeyInput');
    
    // Reset displays
    resultDiv.style.display = 'none';
    resultDiv.innerHTML = '';
    errorDiv.style.display = 'none';
    errorDiv.innerHTML = '';
    
    if (!input.trim()) {
        errorDiv.textContent = 'Error: Please provide input either by pasting JSON or uploading a file';
        errorDiv.style.display = 'block';
        return;
    }
    
    try {
        // Parse the input JSON
        const dsseEnvelope = JSON.parse(input);
        
        // Validate DSSE envelope structure
        if (!dsseEnvelope.payload || !dsseEnvelope.payloadType) {
            throw new Error('Invalid DSSE envelope: missing required fields');
        }
        
        // Check if we have a verification key (either from file or pasted)
        let verificationKey = pubKeyInput.value.trim();
        
     
        // If a verification key is provided, attempt verification
        if (verificationKey) {
            await verifySignature(dsseEnvelope, verificationKey);
        }
        
        // Decode the base64 payload
        let decodedPayload;
        try {
            decodedPayload = forge.util.decode64(dsseEnvelope.payload);
            console.log('Decoded payload as binary');
        } catch (decodeError) {
            console.error('Error decoding base64 payload:', decodeError);
            decodedPayload = dsseEnvelope.payload; // Fallback to showing the raw payload
        }
        
        // Try to parse the decoded payload as JSON if possible
        let formattedContent;
        try {
            // First try to interpret as UTF-8 text
            const textDecoder = new TextDecoder('utf-8');
            const payloadText = typeof decodedPayload === 'string' ? 
                decodedPayload : 
                textDecoder.decode(new Uint8Array(decodedPayload.length).map((_, i) => decodedPayload.charCodeAt(i)));
            
            console.log('Attempting to parse as JSON');
            const jsonContent = JSON.parse(payloadText);
            formattedContent = JSON.stringify(jsonContent, null, 2);
            console.log('Successfully parsed as JSON');
        } catch (jsonError) {
            console.warn('Not valid JSON, displaying as text:', jsonError);
            errorDiv.textContent = `Error: Not valid JSON, displaying as text, detailed error: ${jsonError}`;
            errorDiv.className = 'verification-status invalid';
            errorDiv.style.display = 'block';
            // If not JSON, display as text if it looks like text
            if (typeof decodedPayload === 'string') {
                formattedContent = decodedPayload;
            } else {
                // Try to convert binary to string
                try {
                    const textDecoder = new TextDecoder('utf-8');
                    formattedContent = textDecoder.decode(new Uint8Array(decodedPayload.length)
                        .map((_, i) => decodedPayload.charCodeAt(i)));
                } catch (textError) {
                    console.error('Error converting to text:', textError);
                    formattedContent = 'Binary content (unable to display as text)';
                }
            }
        }
        
        // Display the result
        resultDiv.textContent = formattedContent;
        resultDiv.style.display = 'block';
        
        // Ensure the right panel is visible on mobile
        if (window.innerWidth <= 768) {
            const rightPanel = document.querySelector('.right-panel');
            rightPanel.scrollIntoView({ behavior: 'smooth' });
        }
        
    } catch (error) {
        errorDiv.textContent = `Error: ${error.message}`;
        errorDiv.style.display = 'block';
    }
}
