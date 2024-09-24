
import express, { Request, Response } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { Encrypt } from '../services/encrypt.service';
import { get } from 'http';


const encrypt = new Encrypt(); // Crear una instancia de Encrypt
// Endpoint para encriptar y guardar datos
const encryptionRouter = express.Router();

encryptionRouter.post('/encrypt', (req: Request, res: Response) => {
    const { text } = req.body;
      
    if (!text ) {
      return res.status(400).json({ message: 'You have to enter text and password' });
    }
  
    try {
      const algorithm = 'aes-256-cbc';
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
  
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
  
      const filePath = path.join(__dirname, `encrypted_${Date.now()}.txt`);
      fs.writeFile(filePath, JSON.stringify({ iv: iv.toString('hex'), key: key.toString('hex'), data: encrypted }), (err) => {
        if (err) {
          return res.status(500).json({ message: 'Failed to save the file' });
        }
  
        res.json({ message: 'Text encrypted and saved successfully', filePath });
      });
    } catch (error) {
      res.status(500).json({ message: 'Encryption failed', error: error});
    }
  });
  
  encryptionRouter.post('/encrypt-body', (req: Request, res: Response) => {
    const { id, data } = req.body;

  if (!id || !data) {
    return res.status(400).json({ message: 'ID and data are required' });
  }

  try {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32); // Generar clave aleatoria
    const iv = crypto.randomBytes(16);  // Generar vector de inicialización aleatorio

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const dataString = JSON.stringify(data); // Convertir datos a string
    let encrypted = cipher.update(dataString, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Guardar iv, key y datos en el archivo
    const filePath = path.join(__dirname, `encryptedBody_${id}.txt`);
    fs.writeFileSync(filePath, JSON.stringify({
      iv: iv.toString('hex'),
      key: key.toString('hex'),
      data: encrypted
    }));

    res.json({ message: 'Body encrypted and saved successfully', filePath });
  } catch (error) {
    res.status(500).json({ message: 'Encryption failed', error: error });
  }
  })
  
  // Endpoint para obtener información encriptada
  encryptionRouter.get('/decrypt/:id', (req: Request, res: Response) => {
    const { id } = req.params;
    const filePath = path.join(__dirname, `../controllers/encryptedBody_${id}.txt`);
    // Revisa si el archivo existe
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'Encrypted file not found' });
    }
  
    try {
      // Lee el contenido del archivo
      const encryptedData = Encrypt.readFromFile(filePath);
      
      const { iv, key, data: encrypted } = encryptedData;
  
      // Verifica que el archivo contenga iv, key y data
      if (!iv || !key || !encrypted) {
        return res.status(400).json({ message: 'Invalid encrypted file structure' });
      }
  
      const decryptor = new Encrypt();
      decryptor.key = Buffer.from(key, 'hex');
      decryptor.iv = Buffer.from(iv, 'hex');
      
      // Desencriptar el texto
      const decrypted = decryptor.decrypt(encrypted);
      
      res.json({ data: JSON.parse(decrypted) });
    } catch (error) {
      console.error('Decryption failed:', error); // Para loguear el error exacto
      res.status(500).json({ message: 'Decryption failed', error: error });
    }
  });


  encryptionRouter.get("/user-files", async (req: Request, res: Response) => {
    const userId = req.body.userId;

    if (!userId) {
        return res.status(403).json({ message: 'You have to be logged in' });
    }

    try {
        const filePath = path.join(__dirname, `../controllers/encryptedBody_${userId}`);
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ message: 'No files found for this user' });
        }

        const files = fs.readdirSync(filePath); // Lista todos los archivos
        const fileNames = files.map(file => path.basename(file)); // Extrae solo los nombres de archivos

        res.json({ files: fileNames });
    } catch (error) {
        res.status(500).json({ message: 'Failed to get files', error });
    }
});

  encryptionRouter.post("/decrypt-file", async (req: Request, res: Response) => {
    const {password, fileName } = req.body;
    const userId=req.body?.userId;


    if(!userId || !password || !fileName){
      return res.status(403).json({ message: 'You have to be logged in' });
    }
    const filePath= path.join(__dirname, `../controllers/encryptedBody_${userId}/${fileName}`);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'File not found' });
    }

    try {
      const encryptedData = Encrypt.readFromFile(filePath);// Lee el contenido del archivo

      const decryptor=new Encrypt();
      decryptor.key=crypto.scryptSync(password, 'salt', 32);// Genera clave de encriptación
      decryptor.iv=Buffer.from(encryptedData.iv, 'hex');// Genera vector de inicialización


      const decrypted = decryptor.decrypt(encryptedData.data);// Desencripta el texto
      res.json({ data: JSON.parse(decrypted) });
    } catch (error) {
      res.status(500).json({ message: 'Decryption failed', error: error });
    }
  })

  encryptionRouter.post("/encrypt-file", async (req: Request, res: Response) => {
    const { password, text, userId } = req.body;

    if (!userId) {
        return res.status(403).json({ message: 'You have to be logged in' });
    }

    if (!text || !password) {
        return res.status(400).json({ message: 'Text and password are required' });
    }

    try {
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync(password, 'salt', 32); // Utiliza la contraseña para generar la clave de encriptación
        const iv = crypto.randomBytes(16);

        const cipher = crypto.createCipheriv(algorithm, key, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // Guardar el archivo encriptado en el servidor
        const fileName = `encryptedText_${Date.now()}.txt`;
        const filePath = path.join(__dirname, `../controllers/encryptedBody_${userId}/${fileName}`);

        // Asegurarse de que el directorio existe
        fs.mkdirSync(path.dirname(filePath), { recursive: true });

        fs.writeFileSync(filePath, JSON.stringify({
            iv: iv.toString('hex'),
            data: encrypted
        }));

        res.json({ message: 'Text encrypted and saved successfully', fileName });
    } catch (error) {
        res.status(500).json({ message: 'Text encryption failed', error });
    }
});


  



  
  export { encryptionRouter };
