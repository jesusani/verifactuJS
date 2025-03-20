const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const forge = require("node-forge");
const fs = require("fs");
const axios = require("axios");
require('dotenv').config();

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;


const app = express();
app.use(express.json());

app.use(cors({
    origin: ['http://localhost:3002', 'https://127.0.1:81'],
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// 📌 Configuración de MySQL
const db = mysql.createConnection({
    host: "localhost",
    user: CLIENT_ID,
    password: CLIENT_SECRET,
    database: "verifactu"
});

db.connect(err => {
    if (err) {
        console.error("Error conectando a MySQL:", err);
        return;
    }
    console.log("✅ Conectado a MySQL");
});

// 📌 Función para generar un hash SHA-256 de la factura
function generarHash(factura) {
    return crypto.createHash("sha256").update(JSON.stringify(factura)).digest("hex");
}

// 📌 Función para firmar una factura con OpenSSL
function firmarFactura(factura) {
    try {
        const privateKeyPem = fs.readFileSync("./certificados/clave_privada.pem", "utf8");
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

        const facturaString = JSON.stringify(factura, Object.keys(factura).sort());
        const md = forge.md.sha256.create();
        md.update(facturaString, "utf8");

        const firma = privateKey.sign(md);
        return forge.util.encode64(firma);
    } catch (error) {
        console.error("❌ Error al firmar la factura:", error);
        return null;
    }
}

// 📌 Obtener token de la AEAT (OAuth2)
async function obtenerTokenAEAT() {
    try {
        const response = await axios.post("https://api.aeat.es/oauth/token", {
            grant_type: "client_credentials",
            client_id: "TU_CLIENT_ID",
            client_secret: "TU_CLIENT_SECRET"
        });
        return response.data.access_token;
    } catch (error) {
        console.error("❌ Error al obtener token AEAT:", error.response?.data || error.message);
        return null;
    }
}

// 📌 Enviar factura a la AEAT
async function enviarFacturaAEAT(factura, firma) {
    try {
        const token = await obtenerTokenAEAT();
        if (!token) throw new Error("No se pudo obtener el token AEAT");

        const response = await axios.post("https://api.aeat.es/verifactu/enviar", { factura, firma }, {
            headers: { Authorization: `Bearer ${token}` }
        });
 
        
        if (response.data.error) {
            return res.status(400).json({ error: `Error de la AEAT: ${response.data.error}` });
        }
        

        console.log("✅ Factura enviada a la AEAT:", response.data);
        return response.data;
    } catch (error) {
        console.error("❌ Error al enviar factura a la AEAT:", error.response?.data || error.message);
        return null;
    }
}

app.post('/api/auth/register', (req, res) => {
    const { username, password, nif, email, rol} = req.body;
    if (!username || !nif || !email || !password || !rol)  {
        return res.status(400).json({ error: "Faltan campos obligatorios" });
    }

    // Hash de la contraseña (por ejemplo, usando bcrypt)
   // const hashedPassword = bcrypt.hashSync(password, 10);

    // Consulta a la base de datos para registrar al usuario
    const query = 'INSERT INTO users (username, nif, email, password, rol) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [username, nif, email, password, rol], (err, result) => {
        if (err) {
            console.error("Error al registrar el usuario:", err);
            return res.status(500).json({ error: "Error al registrar el usuario", details: err });
        }
        res.status(200).json({ success: true, message: "Usuario registrado exitosamente",username,password, nif, email, rol });
    });
});


// 📌 Endpoint para registrar una nueva factura
app.post("/generar_factura", async (req, res) => {
    const { cliente, nif, fecha, concepto, importe, iva } = req.body;
    if (isNaN(importe) || isNaN(iva)) {
        return res.status(400).json({ error: "El importe o IVA no son números válidos" });
    }
    const total = parseFloat(importe) + parseFloat(importe) * (parseFloat(iva) / 100);

    const factura = { cliente, nif, fecha, concepto, importe, iva, total };
    const hashFactura = generarHash(factura);
    const firmaFactura = firmarFactura(factura);

    if (!firmaFactura) {
        return res.status(500).json({ error: "Error al firmar la factura" });
    }

    const query = "INSERT INTO facturas (cliente, nif, fecha, concepto, importe, iva, total, hash, firma) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    db.query(query, [cliente, nif, fecha, concepto, importe, iva, total, hashFactura, firmaFactura], async (err, result) => {
    
 
        if (err) {
            console.error("❌ Error al insertar la factura:", err);
            return res.status(500).json({ error: "Error al insertar la factura", detalle: err });
        }else{
            

            // Puedes usar la información de la factura para generar una respuesta personalizada
            const response = {
              message: `La factura con nif **${nif}** ha sido generada.`,
              factura_id: nif,
            };
            res.json(response);
        }

        // Enviar factura a la AEAT
        const respuestaAEAT = await enviarFacturaAEAT(factura, firmaFactura);
        if (!respuestaAEAT) {
            return res.status(500).json({ error: "Error al enviar la factura a la AEAT" });
        }

        res.json({ mensaje: "✅ Factura registrada y enviada a la AEAT", factura_id: result.insertId });
    });
});

// 📌 Endpoint para listar todas las facturas
app.get("/listar_facturas", (req, res) => {
    const query = "SELECT id, cliente, nif, fecha, concepto, importe, iva, total, firma FROM facturas ORDER BY fecha DESC";

    db.query(query, (err, results) => {
        if (err) {
            console.error("❌ Error al obtener las facturas:", err);
            return res.status(500).json({ error: "Error al obtener las facturas", detalle: err });
        }

        res.json(results);
    });
});

// 📌 Bloqueo de modificación de facturas ya emitidas
app.put("/editar_factura/:id", (req, res) => {
    res.status(403).json({ error: "⛔ No se permite modificar facturas ya emitidas" });
});

// 📌 Bloqueo de eliminación de facturas
app.delete("/borrar_factura/:id", (req, res) => {
    res.status(403).json({ error: "⛔ No se permite eliminar facturas" });
});



app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Please provide username and password.' });
    }

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Error querying database.' });
        }

        if (results.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid username .' });
        }

        const user = results[0];

        // Compare the provided password with the hashed password
        if (bcrypt.compare(password, user.password)) {
               // Crear JWT
            const token = jwt.sign({ userId: user.id, username: user.username }, "secreto", { expiresIn: "1h" });

            return res.json({ 
                success: true,
                'rol': user.rol,
                'user': user.username,
                'token': token
             });
        } else {
            return res.status(401).json({ success: false, message: 'Invalid  or password.' });
        }
    });
});

// 📌 Servidor en puerto 3000
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
