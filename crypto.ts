/*
* Welcome to Crypto.ts!
* This is a small collection of helper functions that we use for our encryption.
* It is all implemented using the Window.Crypto API that is baseline in most if not all modern browsers.
* This "library" is used ONLY as an example of how a client-based encryption service could be built.
* WE DO NOT RECOMMEND USING THIS IN A PRODUCTION ENVOIRMENT
* T
*
* This uses RSA Public / Private key encryption as well as AES encryption.
*
* Written by André Högberg & Oscar Karlsson
*/


import type {AesEncryptInterface} from "./models/AesEncryptInterface";
// We start with hashing a password and using that key to create an AES key.
export const createKeyFromMaster = async (password: string): Promise<CryptoKey> => {
    let key = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(password));
    return await window.crypto.subtle.importKey("raw", key, {name: "AES-GCM"}, false,["encrypt", "decrypt"]);
}

export const combineArrayBuffers = (bufferOne: ArrayBuffer, bufferTwo: ArrayBuffer): ArrayBuffer => {
    let bufferOneB64 = arrayBufferToBase64(bufferOne);
    let bufferTwoB64 = arrayBufferToBase64(bufferTwo);
    let combinedBuffer = bufferTwoB64.concat(bufferOneB64);
    return _base64ToArrayBuffer(combinedBuffer);
}

export const createPasswordForAuthentication = async (combinedBuffer: ArrayBuffer): Promise<ArrayBuffer> => {
    return await crypto.subtle.digest("SHA-256", combinedBuffer);
}

export const retrievePublicKeyFromJwk = async (publicKey: JsonWebKey): Promise<CryptoKey> => {
    return await window.crypto.subtle.importKey(
        "jwk",
        publicKey,
        "RSA-OAEP",
        true,
        ["encrypt"]
    );
}

/*
* These two functions are used to export the keys from CryptoKey object to an ArrayBuffer.
* We can take this ArrayBuffer and turn them into base64 strings and store in the database.
* We have to remember to encrypt the private key before converting to base64 with the help of aesEncrypt function.
*/
export const privateRSAKeyToArrayBuffer = async (privateKey: CryptoKey): Promise<ArrayBuffer> => {
   return await window.crypto.subtle.exportKey("pkcs8", privateKey);
}
export const publicRSAKeyToArrayBuffer = async (publicKey: CryptoKey): Promise<ArrayBuffer> => {
    return await window.crypto.subtle.exportKey("spki", publicKey);
}

//This function is used whenever we want to encrypt something with a public key.
//This function will return the secret as a base64 string.
export const rsaPublicEncrypt = async (key: CryptoKey, message: string): Promise<string> => {
    let messageBuffer = new TextEncoder().encode(message);
    let cipher = await window.crypto.subtle.encrypt({name: "RSA-OAEP"}, key, messageBuffer) as ArrayBuffer;
    return btoa(String.fromCharCode.apply(null, cipher));
}

// This will only be called once, when first creating the account.
// We will use this to encrypt our private key to store in the database.
export const aesEncrypt = async (key: CryptoKey, privateKey: ArrayBuffer): Promise<AesEncryptInterface> => {
    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    let privateKeyBuffer = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        privateKey) as ArrayBuffer;
    return {
        iv: arrayBufferToBase64(iv),
        data: arrayBufferToBase64(privateKeyBuffer)
    }
}
// We use this function only when deciphering the encrypted privateKey.
export const aesDecrypt = async (key: CryptoKey, iv: ArrayBuffer, cipher: ArrayBuffer): Promise<ArrayBuffer> => {
    return await window.crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: iv
    },
        key,
        cipher) as ArrayBuffer;
}

//This function should only be called when registering a new user.
//We create a public/private key pair, where the public key is used for encryption
//And the private key is used for decrypting.
export const createCryptoKeyValuePair = async () => {
    return await window.crypto.subtle.generateKey({
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1,0,1]),
            hash: 'SHA-256'
        },
        true,
        ["encrypt", "decrypt"]) as CryptoKeyPair;
}


export const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    return btoa(String.fromCharCode.apply(null, buffer));
}

// This function takes a base64 string and returns a ArrayBuffer. Obviously.
function _base64ToArrayBuffer(base64: string) {
    let binary_string = window.atob(base64);
    let len = binary_string.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}