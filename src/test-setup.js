import { JSDOM } from 'jsdom';

// Set up JSDOM environment
const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
global.document = dom.window.document;
global.window = dom.window;


// Create mock elements that the code expects
const mockElements = {
    'fileInput': { addEventListener: () => {} },
    'fileName': { textContent: '' },
    'dsseInput': { value: '' },
    'certInput': { addEventListener: () => {} },
    'certFileName': { textContent: '' },
    'pubKeyInput': { value: '' },
    'sigstoreFileInput': { addEventListener: () => {} },
    'sigstoreFileName': { textContent: '' },
    'sigstoreInput': { value: '' },
    'error': { 
        textContent: '',
        style: { display: 'none' },
        className: '',
        innerHTML: ''
    },
    'verificationStatus': {
        textContent: '',
        style: { display: 'none' },
        className: '',
        innerHTML: ''
    },
    'verificationWarning': {
        textContent: '',
        style: { display: 'none' },
        innerHTML: ''
    },
    'result': {
        textContent: '',
        style: { display: 'none' },
        innerHTML: ''
    }
};

// Add mock elements to document
Object.entries(mockElements).forEach(([id, element]) => {
    const mockElement = document.createElement('div');
    mockElement.id = id;
    Object.assign(mockElement, element);
    document.body.appendChild(mockElement);
}); 