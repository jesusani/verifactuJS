const forge = require("node-forge");

// Generar claves RSA (Ejecuta esto solo una vez y guarda las claves en un archivo seguro)
const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair(2048);
const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
const publicKeyPem = forge.pki.publicKeyToPem(publicKey);

// Función para firmar una factura
function signInvoice(invoiceData) {
    const md = forge.md.sha256.create();
    md.update(JSON.stringify(invoiceData), "utf8");
    return forge.util.encode64(privateKey.sign(md));
}

// Función para verificar la firma
function verifySignature(invoiceData, signature) {
    const md = forge.md.sha256.create();
    md.update(JSON.stringify(invoiceData), "utf8");
    return publicKey.verify(md.digest().bytes(), forge.util.decode64(signature));
}

// Exportamos las funciones
module.exports = { signInvoice, verifySignature, publicKeyPem };
