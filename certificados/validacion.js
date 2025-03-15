const { body, validationResult } = require("express-validator");

// Middleware de validación de factura
const validateInvoice = [
    body("cliente").isString().notEmpty().withMessage("El cliente es obligatorio"),
    body("nif").matches(/^[0-9]{8}[A-Z]$/).withMessage("NIF no válido"),
    body("fecha").isISO8601().withMessage("Fecha inválida"),
    body("concepto").isString().notEmpty().withMessage("El concepto es obligatorio"),
    body("importe").isFloat({ gt: 0 }).withMessage("El importe debe ser mayor a 0"),
    body("iva").isFloat({ min: 0, max: 21 }).withMessage("El IVA debe estar entre 0% y 21%"),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errores: errors.array() });
        }
        next();
    },
];

// Exportamos el middleware
module.exports = validateInvoice;
