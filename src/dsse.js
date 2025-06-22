import forge from 'node-forge';
import { resetDisplay, stripCertificateContent , resetVerificationMessages} from './utils.js';
import {extractPEMFromCertificate, extractPublicKeyFromPEM} from './keys-utils.js';
import {verifyStarkbankSignature, verifyWithForge, verifyOpenPGPSignature} from './signature-verification.js';

const REKOR_HOST = 'https://rekor.sigstore.dev';

// Make resetDisplay available globally
window.resetDisplay = resetDisplay;
window.resetVerificationMessages = resetVerificationMessages;

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
            // reset display
            resetDisplay();
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
            resetVerificationMessages();
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
            // reset display
            resetDisplay();
        }
    });

});


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
            // Try to verify using openpgp.js
            console.log('Verifying with PGP public key using OpenPGP.js');     
            return await verifyOpenPGPSignature(pae, dsseEnvelope.signatures, publicKey);
        } else if (publicKeyInfo.format === 'starkbank-ecdsa') {
            console.log('Verifying with Starkbank-ECDSA');
            // Try to verify using starkbank-ecdsa
            return await verifyStarkbankSignature(pae, dsseEnvelope.signatures, publicKey);
        } else {
            // Try to verify using forge
            return await verifyWithForge(pae, dsseEnvelope.signatures, publicKey);
        }
        
    } catch (error) {
        console.error('Verification error:', error);
        throw new Error(`Signature verification failed: ${error.message}`);
    }
    return false;
}

async function verifySignature(statusDiv, dsseEnvelope, verificationKey) {
    try {
        // Create a verification status element        
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
    const errorDiv = document.getElementById('error');    
    // Decode the base64 payload
    let decodedPayload;
    try {
        decodedPayload = forge.util.decode64(dsseEnvelope.payload);
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

// function to verify a tlog entry
async function verifyTlogEntry(tlogEntry, dsseEnvelope, rawCertificate) {
       
    const statusDiv = document.getElementById('verificationStatus');

    console.info('verifying tlog entry=', tlogEntry);
    // call {REKOR_HOST}/api/v1/log/entries?logIndex={logIndex}
    const url = `${REKOR_HOST}/api/v1/log/entries?logIndex=${tlogEntry.logIndex}`;
    const response = await fetch(url);
    const data = await response.json();
    // verify the tlog entry
    // get integratedTime from data.{}.integratedTime
    for (const key in data) {
        if (data[key]) {            
            const integratedTime = data[key].integratedTime;
            // verify the integratedTime matches
            if (!(integratedTime == tlogEntry.integratedTime)) {
                statusDiv.textContent = 'Error: Rekor Tlog entry integratedTime mismatch';
                statusDiv.className = 'verification-status invalid';
                statusDiv.style.display = 'block';
                return false;
            } else {
                console.info('tlog entry integratedTime matches, continue to next tlog entry');
            }
            // verify the logIndex matches
            if (!(data[key].logIndex == tlogEntry.logIndex)) {
                statusDiv.textContent = 'Error: Rekor Tlog entry logIndex mismatch';
                statusDiv.className = 'verification-status invalid';
                statusDiv.style.display = 'block';
                return false;
            } else {
                console.info('tlog entry logIndex matches, continue to next tlog entry');
            }
            // verify the tlog entry signature matches
            // get entry body
            const entryBody = data[key].body;
            // base64 decode the body
            const entryBodyDecoded = forge.util.decode64(entryBody);
            // verify body kind is dsse
            const entryBodyJson = JSON.parse(entryBodyDecoded);
            const bodyKind = entryBodyJson.kind;
            if (bodyKind != 'dsse') {
                statusDiv.textContent = 'Error: Rekor Tlog entry body kind is not dsse';
                statusDiv.className = 'verification-status invalid';
                statusDiv.style.display = 'block';
                return false;
            } else {
                console.info('tlog entry body kind matches, continue to next tlog entry');
            }
            // verify the tlog entry signature matches
            const responseSignatures = entryBodyJson.spec.signatures;
            // for each signature, verify the signature is in tlogEntry signatures
            for (const responseSignature of responseSignatures) {
                const responseSig = responseSignature.signature;
                // itterate all dsse envelope signatures and check if responseSig is one of them
                let signatureFound = false;
                for (const dsseSignature of dsseEnvelope.signatures) {                   
                    if (dsseSignature.sig == responseSig) {
                        signatureFound = true;
                    }
                }
                if (!signatureFound) {
                    statusDiv.textContent = 'Error: Rekor Tlog entry signature not found';
                    statusDiv.className = 'verification-status invalid';
                    statusDiv.style.display = 'block';
                    return false;
                } else {
                    console.info('tlog entry signature matches, continue to next tlog entry');
                }
                console.info('All tlog entry signatures appear on dsse signatures list');
                 // check tlog entry verifier
                const responseVerifier = responseSignature.verifier;
                // base64 decode the verifier
                const responseVerifierDecoded = forge.util.decode64(responseVerifier);
                const responseVerifierStriped = stripCertificateContent(responseVerifierDecoded);
                

                // verify the verifier is the same as the raw certificate
                if (responseVerifierStriped != rawCertificate) {
                    statusDiv.textContent = 'Error: Rekor Tlog entry verifier mismatch';
                    statusDiv.className = 'verification-status invalid';
                    statusDiv.style.display = 'block';
                    return false;
                } else {
                    console.info('tlog entry verifier matches, continue to next tlog entry');
                }
            }
            
        }else{
            statusDiv.textContent = 'Error: Rekor Tlog entry not found';
            statusDiv.className = 'verification-status invalid';
            statusDiv.style.display = 'block';
            return false;
        }

    }
    // if we get here, all tlog entries were verified successfully
    return true;
}
// Properly export these functions to be accessible from HTML
window.processSigstore = async function() {
    const verificationStatus = document.getElementById('verificationStatus');
    const verificationWarning = document.getElementById('verificationWarning');
    const sigstoreInput = document.getElementById('sigstoreInput').value;
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('error');    
    // Reset displays
    resetDisplay(resultDiv,errorDiv, verificationStatus, verificationWarning);
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
    
    let verificationKey = extractPEMFromCertificate(derKey);
    //console.log('verificationKey=', verificationKey);
    // If a verification key is provided, attempt verification
    if (!verificationKey) {
        verificationStatus.className = 'verification-status invalid';
        verificationStatus.textContent = 'Error: Signature verification failed, could not locate certificate in the sigstore bundle';
        verificationStatus.style.display = 'block';
    }else{    
        const verified = await verifySignature(verificationStatus, dsseEnvelope, verificationKey);
        // if the dsse was not tampered with. lets check rekor, if we can
        if (!verified){
            verificationStatus.className = 'verification-status invalid';
            verificationStatus.textContent = 'Error: Signature verification failed, cerificate verification on dsse conten failed';
            verificationStatus.style.display = 'block';
            
        }else {
            // verify rekor index integrity
            const tlogEntries = sigstoreBundle.verificationMaterial.tlogEntries            
            if (tlogEntries) {
                let allTlogsVerified = true;
                // this is a public bundle, so we will check it against rekor data
                // verify each tlog entry - logIndex
                for (const tlogEntry of tlogEntries) {
                    const logIndex = tlogEntry.logIndex;
                    console.info('logIndex=', logIndex);
                    // verify the tlog entry
                    const tlogEntryVerified = await verifyTlogEntry(tlogEntry, dsseEnvelope, derKey);
                    console.info('tlogEntry with index=', logIndex, 'verification result is', tlogEntryVerified);        
                    if (!tlogEntryVerified) {
                        allTlogsVerified = false;
                        verificationStatus.textContent = 'Rekor transparency log verification failed for entry with index=' + logIndex;
                        verificationStatus.className = 'verification-status invalid';
                        verificationStatus.style.display = 'block';
                       
                    }
                }
                if (allTlogsVerified){
                    verificationStatus.className = 'verification-status valid';
                    verificationStatus.textContent = 'Signature verification successful! The DSSE envelope was not tampered with, Rekor transparency log verified successfully for all rekor log entries, matching: integratedTime, logIndex, body kind, signature, and certificate';
                    verificationStatus.style.display = 'block';
                }
            } else {
                // this is a private bundle, so we will not check it against rekor data
                console.info('tlogEntries not found, skipping tlog entry verification');
                // set result
                verificationStatus.className = 'verification-status valid';
                verificationStatus.textContent = 'Signature verification successful! The DSSE envelope was not tampered with, see validation warning for further details';
                verificationStatus.style.display = 'block';
                // set warning
                verificationWarning.textContent = 'The provided Sigstore bundle details were not added to rekor, therefore Rekor entries verification was skipped, it is recommended to farther verify the bundle certificate using sigstore cosign tool';
                verificationWarning.style.display = 'block';
                verificationWarning.className = 'verification-warning';    

                
            }
        }
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
    
}

window.processDSSE = async function() {
    const verificationStatus = document.getElementById('verificationStatus');
    const verificationWarning = document.getElementById('verificationWarning');
    const input = document.getElementById('dsseInput').value;
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('error');
    const pubKeyInput = document.getElementById('pubKeyInput');
    
    // Reset displays
    resetDisplay(resultDiv,errorDiv, verificationStatus, verificationWarning);
    
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
            const verified = await verifySignature(verificationStatus, dsseEnvelope, verificationKey);
            if (verified){
                verificationStatus.className = 'verification-status valid';
                verificationStatus.textContent = 'Signature verification successful! The DSSE envelope was not tampered with, ';
                verificationStatus.style.display = 'block';
            }
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

// Export functions for testing
export {    
    verifyDSSESignature,
    verifySignature,
    extractPayload,
    verifyTlogEntry
}; 