import express, { Request, Response, NextFunction } from 'express';



// Middleware para verificar headers
function headerValidator(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization']; 

  if (!authHeader || authHeader !== 'Bearer valid-token') { // Aquí puedes hacer la validación que quieras
    return res.status(403).json({ message: 'Forbidden: Invalid or missing headers' });
  }

  // Si todo está bien, permite que la solicitud continúe al siguiente middleware/controlador
  next();
}

export { headerValidator };