import { getPEMFromCertificateRSA } from './rsa-helper.js';
import { X509Certificate } from '@peculiar/x509';

export const CERTIFICATE_PATTERN = '-----BEGIN CERTIFICATE-----'
export const CERTIFICATE_KEY_FORMAT = 'certificate'

import {arrayBufferToBase64,
    createPEMHeader,
    createPEMFooter,
    formatPEM
 } from '../utils.js';
export function getPEMFromCertificate(certKey) {
    // For X.509 certificates    
    try{
        console.log('Detected X.509 certificate');
        return getPEMFromCertificateRSA(certKey);
    } catch (e) {
        console.error('Forge Failed to parse certificate, trying Web Crypto API, for ECDSA certificate:', e);
        return getPEMFromECDSACertificate(certKey);
    }
}
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
