export function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}


export function stripCertificateContent(certificate) {
    // remove -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
    const pemHeader = "-----BEGIN CERTIFICATE-----";
    const pemFooter = "-----END CERTIFICATE-----";
    return certificate.replace(pemHeader, '').replace(pemFooter, '').replace(/\r?\n|\r/g, '').trim();
}

export function arrayBufferToBase64(buffer) {
    return Buffer.from(buffer).toString('base64');
}

export function createPEMHeader(type) {
    return `-----BEGIN ${type}-----\n`;
}

export function createPEMFooter(type) {
    return `\n-----END ${type}-----`;
}

export function formatPEM(base64String) {
    // Split the base64 string into lines of 64 characters
    const lines = [];
    for (let i = 0; i < base64String.length; i += 64) {
        lines.push(base64String.slice(i, i + 64));
    }
    return lines.join('\n');
}
export function resetVerificationMessages() {
    const errorDiv = document.getElementById('error');
    const verificationStatus = document.getElementById('verificationStatus');
    const verificationWarning = document.getElementById('verificationWarning');
    errorDiv.style.display = 'none';
    errorDiv.innerHTML = '';
    verificationStatus.innerHTML = '';
    verificationStatus.style.display = 'none';
    verificationStatus.classList.remove('valid', 'invalid', 'unknown');
    verificationWarning.innerHTML = '';
    verificationWarning.style.display = 'none';
}
export function resetDisplay() {
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('error');
    const verificationStatus = document.getElementById('verificationStatus');
    const verificationWarning = document.getElementById('verificationWarning');

    resultDiv.style.display = 'none';
    resultDiv.innerHTML = '';
    errorDiv.style.display = 'none';
    errorDiv.innerHTML = '';
    verificationStatus.innerHTML = '';
    verificationStatus.style.display = 'none';
    verificationStatus.classList.remove('valid', 'invalid', 'unknown');
    verificationWarning.innerHTML = '';
    verificationWarning.style.display = 'none';
}

