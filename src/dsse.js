import forge from 'node-forge';
import * as openpgp from 'openpgp';
import { PublicKey, Signature, Ecdsa} from 'starkbank-ecdsa';
import { X509Certificate } from '@peculiar/x509';

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
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
    // Add event listener for file input
    document.getElementById('sigstoreFileInput').addEventListener('change', function(e) {
        console.log('sigstoreFileInput', e.target.files[0]);
        const fileName = e.target.files[0]?.name || '';
        document.getElementById('sigstoreFileName').textContent = fileName;
        
        if (fileName) {
            const file = e.target.files[0];
            const reader = new FileReader();
            
            reader.onload = function(e) {
                document.getElementById('sigstoreInput').value = e.target.result;
            };
            
            reader.readAsText(file);
        }
    });

});


function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

function arrayBufferToHexString(arrayBuffer) {
    if (typeof arrayBuffer !== 'object') {
        throw new TypeError('Expected input of arrayBuffer to be an ArrayBuffer Object');
    }

    const byteArray = new Uint8Array(arrayBuffer);
    let hexString = '';
    let nextHexByte;

    for (let i = 0; i < byteArray.byteLength; i++) {
        nextHexByte = byteArray[i].toString(16);
        if (nextHexByte.length < 2) {
            nextHexByte = '0' + nextHexByte;
        }
        hexString += nextHexByte;
    }

    return hexString;
}
function arrayBufferToBase64(buffer) {
    return Buffer.from(buffer).toString('base64');
}

function createPEMHeader(type) {
    return `-----BEGIN ${type}-----\n`;
}

function createPEMFooter(type) {
    return `\n-----END ${type}-----`;
}

function formatPEM(base64String) {
    // Split the base64 string into lines of 64 characters
    const lines = [];
    for (let i = 0; i < base64String.length; i += 64) {
        lines.push(base64String.slice(i, i + 64));
    }
    return lines.join('\n');
}

function extractPEMFromCertificate(certKey) {
    console.info('extractPEMFromCertificate');
    // get buffer from pemKey
    console.info('certKey=', certKey);
    const cert = new X509Certificate(certKey);
    console.info('cert=', cert);
    const publicKey = cert.publicKey;
    console.info('publicKey=', publicKey);
    // Convert public key to PEM format
    const base64Key = arrayBufferToBase64(publicKey.rawData);
    const pemKeyContent = createPEMHeader('PUBLIC KEY') + 
                  formatPEM(base64Key) + 
                  createPEMFooter('PUBLIC KEY');
    return pemKeyContent;
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
                    const pemHeader = "-----BEGIN CERTIFICATE-----";
                    const pemFooter = "-----END CERTIFICATE-----";
                    const pemContents = pemKey.replace(pemHeader, '').replace(pemFooter, '').replace(/\r?\n|\r/g, '').trim();
                    console.log('pemContents=', pemContents);
                    const binaryDerString = window.atob(pemContents);
                    console.log('binaryDerString=', binaryDerString);
                    const keyBuffer = str2ab(binaryDerString);
                    console.log('keyBuffer=', keyBuffer);

                    const hex = arrayBufferToHexString(keyBuffer);
                    console.log('hex=', hex);
                    
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

// Function to verify signature using starkbank-ecdsa
async function verifyStarkbankSignature(pae, signatures, publicKey) {
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

// Function to verify DSSE signature using forge.js
async function verifyDSSESignature(dsseEnvelope, publicKeyInfo) {
    try {
        console.log('Verifying signature with format:', publicKeyInfo.format);
        
        // Get the signature from the DSSE envelope
        if (!dsseEnvelope.signatures || dsseEnvelope.signatures.length === 0) {
            throw new Error('No signatures found in the DSSE envelope');
        }
        
        // Get the encoded payload and payloadType
        const payload = dsseEnvelope.payload;
        const payloadDecoded = forge.util.decode64(payload);
        const payloadType = dsseEnvelope.payloadType;
        
        // Properly implement the DSSE PAE (Pre-Authentication Encoding) format
        const paePrefix = `DSSEv1 ${payloadType.length} ${payloadType} ${payloadDecoded.length} `;
        const pae = paePrefix + payloadDecoded;
        
        // Handle different key formats
        const publicKey = publicKeyInfo.key;
        console.log('publicKeyInfo.format=', publicKeyInfo.format);
        
        // Special handling for PGP keys
        if (publicKeyInfo.format === 'pgpPublicKey') {
            console.log('Verifying with PGP public key using OpenPGP.js');            
            try {                
                // Create a message from the PAE data for verification
                const message = await openpgp.createMessage({ text: pae });
                
                // loop over all signatures and verify each one
                let counter = 0;
                for (const signature of dsseEnvelope.signatures) {
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
        } else if (publicKeyInfo.format === 'starkbank-ecdsa') {
            console.log('Verifying with Starkbank-ECDSA');
            // Try to verify using starkbank-ecdsa
            return await verifyStarkbankSignature(pae, dsseEnvelope.signatures, publicKey);
        } else {
            return await verifyWithForge(pae, dsseEnvelope.signatures, publicKey);
        }
        
    } catch (error) {
        console.error('Verification error:', error);
        throw new Error(`Signature verification failed: ${error.message}`);
    }
    return false;
}

// Helper function for forge.js verification
async function verifyWithForge(pae, signatures, publicKey) {
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

function extractPayload(dsseEnvelope) {
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
    return formattedContent;
}

// function for display reset
function resetDisplay(resultDiv,errorDiv, verificationStatus) {
    resultDiv.style.display = 'none';
    resultDiv.innerHTML = '';
    errorDiv.style.display = 'none';
    errorDiv.innerHTML = '';
    verificationStatus.innerHTML = '';
    verificationStatus.style.display = 'none';
    verificationStatus.classList.remove('valid', 'invalid', 'unknown');
}

// Properly export these functions to be accessible from HTML
window.processSigstore = async function() {
    const verificationStatus = document.getElementById('verificationStatus');
    const sigstoreInput = document.getElementById('sigstoreInput').value;
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('error');    
    // Reset displays
    resetDisplay(resultDiv,errorDiv, verificationStatus);
    // validate input
    if (!sigstoreInput.trim()) {
        errorDiv.textContent = 'Error: Please provide input either by pasting JSON or uploading a file';
        errorDiv.style.display = 'block';
        return;
    }
    let sigstoreBundle;
    try{
        // parse sigstore bundle
        sigstoreBundle = JSON.parse(sigstoreInput);
    } catch (error) {
        errorDiv.textContent = `Error parsing Sigstore bundle, please verify the input is a valid JSON format: ${error.message}`;
        errorDiv.style.display = 'block';
    }
    console.info('before sigstore verify');        
    // extract the dsse envelope from the sigstore bundle
    let dsseEnvelope;
    try{
        dsseEnvelope = sigstoreBundle.dsseEnvelope;
    } catch (error) {
        errorDiv.textContent = `Error parsing Sigstore bundle, please verify the input is a valid Sigstore bundle: ${error.message}`;
        errorDiv.style.display = 'block';
    }    
    // handling signature verification
    const derKey = sigstoreBundle.verificationMaterial.certificate.rawBytes;
    console.info('rawBytes=', derKey);
    
    let verificationKey = extractPEMFromCertificate(derKey);
    console.log('verificationKey=', verificationKey);
    // If a verification key is provided, attempt verification
    if (verificationKey) {
        await verifySignature(dsseEnvelope, verificationKey);
    }
    // handle the payload
    // handle the payload
    const formattedContent = extractPayload(dsseEnvelope);
    // Display the result
    resultDiv.textContent = formattedContent;
    resultDiv.style.display = 'block';
    
    // Ensure the right panel is visible on mobile
    if (window.innerWidth <= 768) {
        const rightPanel = document.querySelector('.right-panel');
        rightPanel.scrollIntoView({ behavior: 'smooth' });
    }
    
}

window.processDSSE = async function() {
    const verificationStatus = document.getElementById('verificationStatus');
    const input = document.getElementById('dsseInput').value;
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('error');
    const pubKeyInput = document.getElementById('pubKeyInput');
    
    // Reset displays
    resetDisplay(resultDiv,errorDiv, verificationStatus);
    
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
        // handle the payload
        const formattedContent = extractPayload(dsseEnvelope);
        
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
}; 