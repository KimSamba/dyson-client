import { createDecipheriv } from 'crypto';

interface PasswordDecryptParams {
    encryptedPassword: string;
    decryptKey: Buffer;
    initialVector: Buffer;
    decipherAlgorithm: string;
}

interface DecryptedPassword {
    serial: string;
    apPasswordHash: string;
}

function b64dec(data: string) {
    return Buffer.from(data, 'base64').toString('binary');
}

export function decryptPassword(params: PasswordDecryptParams): DecryptedPassword {
    const { decryptKey, encryptedPassword, initialVector, decipherAlgorithm } = params;
    const decipher = createDecipheriv(decipherAlgorithm, decryptKey, initialVector);
    const data = b64dec(encryptedPassword);

    return JSON.parse(`${decipher.update(data, 'binary', 'utf8')}${decipher.final('utf8')}`);
}
