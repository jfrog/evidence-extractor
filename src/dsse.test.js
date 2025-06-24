import './test-setup.js';
import { expect } from 'chai';
import './utils.js';
import {extractPublicKeyFromPEM} from './keys-utils.js';
import {RSA_KEY_FORMAT} from './keys-helpers/rsa-helper.js';

// Import the functions we want to test
import {
    verifyDSSESignature,
    verifySignature,
    extractPayload,
    verifyTlogEntry
} from './dsse.js';


describe('DSSE Verification Tests', () => {
    // Test data
    const validDSSEEnvelope = {
        payload: 'eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJkaWdlc3QiOnsic2hhMjU2IjoiZWRkZDgzOWJjOTg3NjM4NDA1ODI1YmI2YzU5MTM3ZDM3ZmQ1YmE3MDBjN2UxNjBiY2VmYjg2NjI5MGFhOWEyOCJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2pmcm9nLmNvbS9ldmlkZW5jZS9idWlsZC1zaWduYXR1cmUvdjEiLCJwcmVkaWNhdGUiOnsiYWN0b3IiOiJjYXJtaXRoZXJzaCIsImRhdGUiOiIyMDI1LTAzLTI1VDE0OjUwOjQyWiJ9LCJjcmVhdGVkQXQiOiIyMDI1LTAzLTI1VDE0OjUwOjQyLjI4OVoiLCJjcmVhdGVkQnkiOiJhZG1pbiJ9',
        payloadType: 'application/vnd.in-toto+json',
        signatures: [{
            sig: 'dfObGJFeNLKRmPQ2V/8DMnJ/2uq2kHftzGJ8YHlBNhTNc/o5ArfYuoifxIyoXMb19t0uKpUOxEvL6Hc33z/iEbSzgQ7A9G3YKJle7jkW/VclAfdJFFy8rLi52FYrNHdrQ1HU8fxAaapccCsGtTCRvvjEEBA0dZt5lzMirAA1j1tbeMhX4HzxmSofDjrT+OLM7Pb8Kt+DXP5sZ1mCh8zF8hyMjR+7YjeegpGkXD4wnBW4tshwOxwKXcCDimusDOuW9bHQqnUQDt5ybx4kceUcXsWUASXq4KETI5pt30GmUS0igDMhYP0KYyyfJrfzOfvUahXNmpoDhtOObR1V+2u2Pw==',
            keyid: 'KEY-ALIAS'
        }]
    };
    const validPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA07f3tJM90t9tuhN4pTnA
a/YjRKeFWOahu8VvZ1BqyDsDaSmMHB3NNpxhfYtByK3k8OQh0I16RPQEpTABb5NV
XfpAoc8xja0Ol5Y/IKi4zIsL/fD5RWY+EclIyUG6r0qd+68MjwSbHvZeLFkbmBtV
+4qGzh0MGClcLFzhcg2+R7uKHDpsHxsjuBv+qbwwzaLtrKpXL5bqCnr5veORCxTD
Pp752cOnpHESRpL86bpVM9uoVoruXsajOKMXfTxjDvD9KWkpy9wDWuQoMbC0A6a3
2lZw/MW6Gp2Mi7nmo7l3XvSd5PwhCIpxnCbL9ag680+Bht//bajqUwHQfarN8Kko
nwIDAQAB
-----END PUBLIC KEY-----`;

    describe('extractPublicKeyFromPEM', () => {
        it('should successfully extract a public key from PEM format', async () => {
            const validPublicKeyTrimmed = validPublicKey.trim();
            const result = await extractPublicKeyFromPEM(validPublicKeyTrimmed);
            expect(result).to.have.property('key');
            expect(result).to.have.property('format');
            expect(result.format).to.equal(RSA_KEY_FORMAT);
        });

        it('should throw error for invalid PEM format', async () => {
            try {
                await extractPublicKeyFromPEM('invalid-pem');
                expect.fail('Should have thrown an error');
            } catch (error) {
                expect(error.message).to.include('Failed to extract key');
            }
        });
    });

    describe('verifyDSSESignature', () => {
        it('should successfully verify a valid DSSE signature', async () => {
            const publicKeyInfo = await extractPublicKeyFromPEM(validPublicKey);
            const result = await verifyDSSESignature(validDSSEEnvelope, publicKeyInfo);
            expect(result).to.be.true;
        });

        it('should fail to verify an invalid DSSE signature', async () => {
            const invalidEnvelope = {
                ...validDSSEEnvelope,
                signatures: [{
                    ...validDSSEEnvelope.signatures[0],
                    sig: 'invalid-signature'
                }]
            };
            const publicKeyInfo = await extractPublicKeyFromPEM(validPublicKey);
            const result = await verifyDSSESignature(invalidEnvelope, publicKeyInfo);
            expect(result).to.be.false;
        });
    });

    describe('extractPayload', () => {
        const errorDiv = document.getElementById('error');

        it('should successfully extract and decode JSON payload', () => {
            const result = extractPayload(validDSSEEnvelope);
            expect(result).to.include('"createdBy": "admin"');
        });

        it('should fail non-JSON payload', () => {
            const nonJsonEnvelope = {
                ...validDSSEEnvelope,
                payload: 'dGVzdCBzdHJpbmc=' // base64 encoded "test string"
            };
            extractPayload(nonJsonEnvelope);
            expect(errorDiv.style.display).to.equal('block');
            expect(errorDiv.textContent).to.include('Error');
            expect(errorDiv.className).to.include('invalid');
        });

        it('should update errorDiv when payload is invalid', () => {
            const invalidEnvelope = {
                ...validDSSEEnvelope,
                payload: 'invalid-base64' // invalid base64
            };
            extractPayload(invalidEnvelope);
            expect(errorDiv.style.display).to.equal('block');
            expect(errorDiv.textContent).to.include('Error');
            expect(errorDiv.className).to.include('invalid');
        });
    });

    describe('verifyTlogEntry', () => {
        const mockTlogEntry = {
            logIndex: 163873779,
            integratedTime: 1737376057
        };
   
        it('should verify a valid tlog entry', async () => {
            // Mock fetch response
            global.fetch = async () => ({
                json: async () => ({
                    [mockTlogEntry.logIndex]: {
                        integratedTime: mockTlogEntry.integratedTime,
                        logIndex: mockTlogEntry.logIndex,
                        body: 'eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiOTUxMDZmMzMwYmM5ODU1MDEyNzg2Y2ViOThkOGRkNWE4ZmM0Mjg3ODA5Y2IyN2I3ODFhZjI3MzA0YmZlNjI5NCJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6IjA3MmM4MzY3NGVjNzUzMWRiYTIyZjliMjE2ZmI4NzQwZjBlMTYwNjk0YTgwYmMyMmIzOTRlYmY0MjhlMjEyNzUifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVVQ0lGVkhjcXFOK2I4RU0wZkh0c1JmN0xiT3B5RXJsSnZ2ZktmL1lCSnl4SWJNQWlFQXRWbjdIdjVWelBwKzBwamlEZHFMcE9CeEtWOXZmNjVvZytBeXpEaFF3WE09IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VoQmVrTkRRbTl0WjBGM1NVSkJaMGxWWmpSa1QxRkxjRzByU25Cc1dqZFBNVFZMTmtseFRVOUJhUzlOZDBObldVbExiMXBKZW1vd1JVRjNUWGNLVG5wRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5ValIzU0VGWlJGWlJVVVJGZUZaNllWZGtlbVJIT1hsYVV6RndZbTVTYkFwamJURnNXa2RzYUdSSFZYZElhR05PVFdwVmQwMVVTWGROVkVsNVRucE5NMWRvWTA1TmFsVjNUVlJKZDAxVVNYcE9lazB6VjJwQlFVMUdhM2RGZDFsSUNrdHZXa2w2YWpCRFFWRlpTVXR2V2tsNmFqQkVRVkZqUkZGblFVVndjRUpXYUdScUszUnlVMEl6YkdsUk4wRkhTR2xVWTJ0Sk5GaEhWRk54Vm1wVVJIRUtWVUZGYTBoQmRtMDFTRkphUkRWWVJYQldOM2RIUm5jd01YaEtWMmhRYzNwcVVsUXdTblZSZG1aeWFtOXVUeXRTZVRaUFEwSmhaM2RuWjFkclRVRTBSd3BCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVdSQ1owNVdTRkUwUlVablVWVk5jRkpOQ2t4Q1NXODVRMEpFUkdWV2JGUlFla1JHVDNnekswTk5kMGgzV1VSV1VqQnFRa0puZDBadlFWVXpPVkJ3ZWpGWmEwVmFZalZ4VG1wd1MwWlhhWGhwTkZrS1drUTRkMk5uV1VSV1VqQlNRVkZJTDBKSFozZGFiMXByWVVoU01HTklUVFpNZVRsdVlWaFNiMlJYU1hWWk1qbDBUREpPYUdOdE1YQmtSMmhzWTI1T2J3cE1NazVvWTIweGNHUkRNVEJhV0U0d1lWYzFia3g1Tlc1aFdGSnZaRmRKZG1ReU9YbGhNbHB6WWpOa2Vrd3lTakZoVjNoclRGaENNVmx0ZUhCak1tZDBDbVJxU1hWbFZ6RnpVVWhLYkZwdVRYWmhSMVpvV2toTmRtSlhSbkJpYWtFMVFtZHZja0puUlVWQldVOHZUVUZGUWtKRGRHOWtTRkozWTNwdmRrd3pVbllLWVRKV2RVeHRSbXBrUjJ4MlltNU5kVm95YkRCaFNGWnBaRmhPYkdOdFRuWmlibEpzWW01UmRWa3lPWFJOUWtsSFEybHpSMEZSVVVKbk56aDNRVkZKUlFwQ1NFSXhZekpuZDA1bldVdExkMWxDUWtGSFJIWjZRVUpCZDFGdlRrUlZNMWxxVVRGWmVsRXpUVlJLYUU1WFRURlpWRUV6V20xRmVVMUhXVEZaTWxGNkNrOVVaR3BhVkVVMVdXMVpNRTVVUlRCYVJFRm5RbWR2Y2tKblJVVkJXVTh2VFVGRlJVSkNTbWxrVjJ4eldrTXhkMlJYU25OaFdFNXZURmhPYWxsWE5IY0tTMEZaUzB0M1dVSkNRVWRFZG5wQlFrSlJVV0ZaTWtaNVlsZHNNR0ZIVm5sak1tZDJXVEpHZVdKWGJEQk1XRkpzWXpOU2NHSnRZM2RJVVZsTFMzZFpRZ3BDUVVkRWRucEJRa0puVVZCamJWWnRZM2s1YjFwWFJtdGplVGwwV1Zkc2RVMUVjMGREYVhOSFFWRlJRbWMzT0hkQlVXZEZURkYzY21GSVVqQmpTRTAyQ2t4NU9UQmlNblJzWW1rMWFGa3pVbkJpTWpWNlRHMWtjR1JIYURGWmJsWjZXbGhLYW1JeU5UQmFWelV3VEcxT2RtSlVRakJDWjI5eVFtZEZSVUZaVHk4S1RVRkZTa0pIV1UxYVIyZ3daRWhDZWs5cE9IWmFNbXd3WVVoV2FVeHRUblppVXpscVdWaEtkR0ZZVW05YVdFcDZZVU01YWxsWVNuUmhXRkYwWkVkV2VncGtSMngxV25rNGRWb3liREJoU0ZacFRETmtkbU50ZEcxaVJ6a3pZM2s1YVdSWGJITmFRekYzWkZkS2MyRllUbTlNV0ZsNVRHNXNkR0pGUW5sYVYxcDZDa3d5YUd4WlYxSjZUREl4YUdGWE5IZFBRVmxMUzNkWlFrSkJSMFIyZWtGQ1EyZFJjVVJEWnpCT1ZHUnBUa1JXYWs1RVkzaE5iVVV4V1hwV2FFMUVaRzBLV1ZSSmQxcHFWbXBhUkUwMVRqSk9iRTFVYkdsYWFsRXhUVlJTYTAxQ01FZERhWE5IUVZGUlFtYzNPSGRCVVhORlJIZDNUbG95YkRCaFNGWnBURmRvZGdwak0xSnNXa1JCT1VKbmIzSkNaMFZGUVZsUEwwMUJSVTFDUXpoTlRGZG9NR1JJUW5wUGFUaDJXakpzTUdGSVZtbE1iVTUyWWxNNWFsbFlTblJoV0ZKdkNscFlTbnBoUXpscVdWaEtkR0ZZVVhSa1IxWjZaRWRzZFZwNlFUUkNaMjl5UW1kRlJVRlpUeTlOUVVWT1FrTnZUVXRFVVRGT01ra3dUbGROTUU1NlJYa0tXVlJXYWs1WFJYZE9NbHBvVFdwQ2JVNVhUbXROZW1zeldUSlZlRTlYU20xT1JGVjRUa2RSZDBoM1dVdExkMWxDUWtGSFJIWjZRVUpFWjFGU1JFRTVlUXBhVjFwNlRESm9iRmxYVW5wTU1qRm9ZVmMwZDBkUldVdExkMWxDUWtGSFJIWjZRVUpFZDFGTVJFRnJNMDlVUlRKT2VrMDFUbFJSZDB4bldVdExkMWxDQ2tKQlIwUjJla0ZDUlVGUlowUkNOVzlrU0ZKM1kzcHZka3d5WkhCa1IyZ3hXV2sxYW1JeU1IWlpNa1o1WWxkc01HRkhWbmxqTW1kM1IwRlpTMHQzV1VJS1FrRkhSSFo2UVVKRlVWRkxSRUZuTTA5RVkzbE5hazB4VDBSQ01FSm5iM0pDWjBWRlFWbFBMMDFCUlZOQ1IxbE5Xa2RvTUdSSVFucFBhVGgyV2pKc01BcGhTRlpwVEcxT2RtSlRPV3BaV0VwMFlWaFNiMXBZU25waFF6bHFXVmhLZEdGWVVYUmtSMVo2WkVkc2RWcDVPSFZhTW13d1lVaFdhVXd6WkhaamJYUnRDbUpIT1ROamVUbHBaRmRzYzFwRE1YZGtWMHB6WVZoT2IweFlXWGxNYm14MFlrVkNlVnBYV25wTU1taHNXVmRTZWt3eU1XaGhWelIzVDBGWlMwdDNXVUlLUWtGSFJIWjZRVUpGZDFGeFJFTm5NRTVVWkdsT1JGWnFUa1JqZUUxdFJURlplbFpvVFVSa2JWbFVTWGRhYWxacVdrUk5OVTR5VG14TlZHeHBXbXBSTVFwTlZGSnJUVUpSUjBOcGMwZEJVVkZDWnpjNGQwRlNVVVZDWjNkRlkwaFdlbUZFUW1oQ1oyOXlRbWRGUlVGWlR5OU5RVVZXUWtaTlRWVlhhREJrU0VKNkNrOXBPSFphTW13d1lVaFdhVXh0VG5aaVV6bHFXVmhLZEdGWVVtOWFXRXA2WVVNNWFsbFlTblJoV0ZGMFpFZFdlbVJIYkhWYWVUbG9XVE5TY0dJeU5Yb0tURE5LTVdKdVRYWk5WRWswVG1wak5VOUVZekJOVkZsMldWaFNNRnBYTVhka1NFMTJUVlJCVjBKbmIzSkNaMFZGUVZsUEwwMUJSVmRDUVdkTlFtNUNNUXBaYlhod1dYcERRbWxuV1V0TGQxbENRa0ZJVjJWUlNVVkJaMUk0UWtodlFXVkJRakpCVGpBNVRVZHlSM2g0UlhsWmVHdGxTRXBzYms1M1MybFRiRFkwQ2pOcWVYUXZOR1ZMWTI5QmRrdGxOazlCUVVGQ2JFbFBkWGg0U1VGQlFWRkVRVVZqZDFKUlNXaEJVRkp4ZUROMmRHSnRVMlJZY1N0VFZrcGhkVFpwT1VJS2RtNVliazFOUnk4MGNFWjRWRzFGTVVWemIyTkJhVUV5VWxWbGJVaGxNblZpTmtKMlFtc3pTamhCWVZab1lYRmFiVGh2Uld4MlMxcFNOMHB2WlZaUk53cHdla0ZMUW1kbmNXaHJhazlRVVZGRVFYZE9iMEZFUW14QmFrSTJWV2RpV2pCUlpVNVdNVVJqZWpaRVdWSlZUREEzTjNSak9HaEZXRmd4VTBkSFJHOUJDbXRMTTJOUWNWSlZLMVozY0ZvemEyeEZPWGQzYlZvM2JrWmhiME5OVVVOWVpUWjVlbW81WVVWbk4wRTBkREYwYUZwemVVOXdMMW8zVFd0bVJHSTVSMWtLYTBoNkt6ZHZRVVZEYlV0WldGVkNVM3BzZGpSeVRsUk1iREF5YUc4NVJUMEtMUzB0TFMxRlRrUWdRMFZTVkVsR1NVTkJWRVV0TFMwdExRbz0ifV19fQ=='
                    }
                })
            });
            const certificate = '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'
            const sigstoreDsse = {
                payload: 'eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoiZXZpZGVuY2V0cmlhbC5qZnJvZy5pby90ZXN0LWRvY2tlci1sb2NhbC9teS12ZXJ5LWNvb2wtaW1hZ2UiLCJkaWdlc3QiOnsic2hhMjU2IjoiNDI4MjQ5MDc1M2Q4Mjc1ZTc1MWU0YjdmZTIzZWM5ZjEzYTkxZDMzNjFiNzRiYmVlYjgxYzJmMGJjMzMxYTZjNSJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjEiLCJwcmVkaWNhdGUiOnsiYnVpbGREZWZpbml0aW9uIjp7ImJ1aWxkVHlwZSI6Imh0dHBzOi8vYWN0aW9ucy5naXRodWIuaW8vYnVpbGR0eXBlcy93b3JrZmxvdy92MSIsImV4dGVybmFsUGFyYW1ldGVycyI6eyJ3b3JrZmxvdyI6eyJyZWYiOiJyZWZzL2hlYWRzL21haW4iLCJyZXBvc2l0b3J5IjoiaHR0cHM6Ly9naXRodWIuY29tL2Nhcm1pdGhlcnNoL2Nhcm1pdC10ZXN0aW5nIiwicGF0aCI6Ii5naXRodWIvd29ya2Zsb3dzL2J1aWxkLXB1Ymxpc2gtdjIueW1sIn19LCJpbnRlcm5hbFBhcmFtZXRlcnMiOnsiZ2l0aHViIjp7ImV2ZW50X25hbWUiOiJwdXNoIiwicmVwb3NpdG9yeV9pZCI6Ijc5MTY3Mzk1NCIsInJlcG9zaXRvcnlfb3duZXJfaWQiOiI3ODcyMjM1OCIsInJ1bm5lcl9lbnZpcm9ubWVudCI6ImdpdGh1Yi1ob3N0ZWQifX0sInJlc29sdmVkRGVwZW5kZW5jaWVzIjpbeyJ1cmkiOiJnaXQraHR0cHM6Ly9naXRodWIuY29tL2Nhcm1pdGhlcnNoL2Nhcm1pdC10ZXN0aW5nQHJlZnMvaGVhZHMvbWFpbiIsImRpZ2VzdCI6eyJnaXRDb21taXQiOiI0NTdiNDVjNDcxMmE1YzVhMDdmYTIwZjVjZDM5N2NlMTliZjQ1MTRkIn19XX0sInJ1bkRldGFpbHMiOnsiYnVpbGRlciI6eyJpZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9jYXJtaXRoZXJzaC9jYXJtaXQtdGVzdGluZy8uZ2l0aHViL3dvcmtmbG93cy9idWlsZC1wdWJsaXNoLXYyLnltbEByZWZzL2hlYWRzL21haW4ifSwibWV0YWRhdGEiOnsiaW52b2NhdGlvbklkIjoiaHR0cHM6Ly9naXRodWIuY29tL2Nhcm1pdGhlcnNoL2Nhcm1pdC10ZXN0aW5nL2FjdGlvbnMvcnVucy8xMjg2Nzk4NzQxNi9hdHRlbXB0cy8xIn19fX0=',
                payloadType: 'application/vnd.in-toto+json',
                signatures: [{
                    sig: 'MEUCIFVHcqqN+b8EM0fHtsRf7LbOpyErlJvvfKf/YBJyxIbMAiEAtVn7Hv5VzPp+0pjiDdqLpOBxKV9vf65og+AyzDhQwXM='                    
                }]
            };
            const result = await verifyTlogEntry(mockTlogEntry, sigstoreDsse, certificate);
            expect(result).to.be.true;
        });

        it('should fail verification for mismatched integratedTime', async () => {
            // Mock fetch response with mismatched time
            global.fetch = async () => ({
                json: async () => ({
                    [mockTlogEntry.logIndex]: {
                        integratedTime: 9999999999, // Different time
                        logIndex: mockTlogEntry.logIndex,
                        body: 'eyJraW5kIjoiZHNzZSJ9'
                    }
                })
            });

            const result = await verifyTlogEntry(mockTlogEntry, validDSSEEnvelope, 'test-certificate');
            expect(result).to.be.false;
        });
    });
}); 