(async () => {

const prefixHex = '302e020100300506032b656e04220420' 
const size = 256
const kdfHash = 'SHA-256'
const kdfIterations = 100000

async function genDetX25519KeyPair(passphrase, salt) {    
    const textEncoder = new TextEncoder()
    const passphraseAB = textEncoder.encode(passphrase) 
    const saltAB = textEncoder.encode(salt) 
    // derive raw private key via PBKDF2
    const passphraseCK = await crypto.subtle.importKey('raw', passphraseAB, { name: 'PBKDF2' }, false, ['deriveBits'])
    const rawPrivateEcKeyAB = await deriveRawPrivate(saltAB, passphraseCK, size)
    // convert to PKCS#8
    const pkcs8AB = new Uint8Array([ ...hex2ab(prefixHex), ...new Uint8Array(rawPrivateEcKeyAB)]) 
    const privateKeyCK = await crypto.subtle.importKey('pkcs8', pkcs8AB, { name: 'X25519' }, true, ['deriveBits'] )
    // get public key 
    const publicKeyCK = await getPublic(privateKeyCK)
    const spkiAB = await crypto.subtle.exportKey('spki', publicKeyCK)
    return { pkcs8AB, spkiAB };
}

async function deriveRawPrivate(saltAB, passphraseCK, nHex){
    return await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltAB, iterations: kdfIterations, hash: kdfHash }, passphraseCK, size)    
}

async function getPublic(privateKeyCK){
    const privatKeyJWK = await crypto.subtle.exportKey('jwk', privateKeyCK)    
    delete privatKeyJWK.d
    privatKeyJWK.key_ops = []
    return crypto.subtle.importKey('jwk', privatKeyJWK, { name: 'X25519' }, true, [])
}

function ab2hex(ab) { 
    return Array.prototype.map.call(new Uint8Array(ab), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function hex2ab(hex){
    return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(function (h) { return parseInt(h, 16) }));
}

// Use case: Calculate shared secrets for X25519 -----------------------------------------------------------

// 1a. Determinstic key generation, A side
var keysA =  await genDetX25519KeyPair('a passphrase for A side', 'some salt for A')
console.log('PKCS#8, A:', ab2hex(keysA.pkcs8AB))
console.log('SPKI, A:', ab2hex(keysA.spkiAB))
// 1b. Determinstic key generation, B side
var keysB =  await genDetX25519KeyPair('a passphrase for B side', 'some salt for B')
console.log('PKCS#8, B:', ab2hex(keysB.pkcs8AB))
console.log('SPKI, B:', ab2hex(keysB.spkiAB))

// 2. exchange public keys

// 3a. key import, A side
var privateKeyA = await crypto.subtle.importKey('pkcs8', keysA.pkcs8AB, { name: 'X25519' }, true,  ['deriveBits'])
var publicKeyB = await crypto.subtle.importKey('spki', keysB.spkiAB, { name: 'X25519' }, true,  [])
// 3b. key import, B side
var privateKeyB = await crypto.subtle.importKey('pkcs8', keysB.pkcs8AB, { name: 'X25519' }, true,  ['deriveBits'])
var publicKeyA = await crypto.subtle.importKey('spki', keysA.spkiAB, { name: 'X25519' }, true,  [])

// 4a. calculate shared secret, A side
var sharedSecretA = await window.crypto.subtle.deriveBits({ name: 'X25519', public: publicKeyB }, privateKeyA, size)
// 4b. calculate shared secret, B side
var sharedSecretB = await window.crypto.subtle.deriveBits({ name: 'X25519', public: publicKeyA }, privateKeyB, size)

console.log('Shared secret, A:', ab2hex(sharedSecretA))
console.log('Shared secret, B:', ab2hex(sharedSecretB))

})();
