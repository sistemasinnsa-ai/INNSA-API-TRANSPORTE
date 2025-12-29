require('dotenv').config();
const express = require('express');
const http = require('http');
const {execFile } = require('child_process');
const fs = require('fs');
const {Server} = require('socket.io')
const sql = require('mssql');
const cors = require('cors');
const path = require('path');
const { DateTime } = require('luxon');
const jwt = require('jsonwebtoken')
const app = express();
const port = process.env.PORT || 3000;
const WPF_SERVICE_TOKEN= process.env.WPF_SERVICE_TOKEN



// Obtener origen permitido de las variables de entorno, sin fallback '*'
const allowedOrigin = process.env.ALLOWED_ORIGIN || 'https://inn.lat';
// 1. EL MIDDLEWARE DE CORS VA PRIMERO
//    Manejará las solicitudes OPTIONS automáticamente y las terminará.
const corsOptions = {
  origin: allowedOrigin,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: 'https://inn.lat',
    methods: ['GET', 'POST'],
    allowedHeaders: 'Content-Type, Authorization'
  }
});

//Validacion de token WPF al conectar
io.use((socket, next)=>{
    const token = socket.handshake.auth.token
    if(token !== WPF_SERVICE_TOKEN){
        return next (new Error('Token invalido para wpf'));
    }
    next();
})
io.on('connection',(socket)=>{
    console.log('WPF conectada:', socket.id);
})

if (!allowedOrigin) {
  console.error('ERROR: ALLOWED_ORIGIN no está definido en variables de entorno');
  process.exit(1);
}






app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  console.log(`${req.method} ${req.url} - Origin: ${req.headers.origin} - IP: ${ip}`);
  next();
});



// Middleware para parsear JSON
app.use(express.json());


const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  options: {
    encrypt: process.env.DB_ENCRYPT === 'true',
    trustServerCertificate: process.env.DB_TRUST_CERT === 'true'
  }
};

//Middleware para verificar JWT
function verificarToken(req, res, next) {
    const ip = req.ip;
    let token = req.headers['authorization'];

    if (!token) {
        console.log(`Intento de acceso sin token desde IP: ${ip}`);
        return res.end(); // Solo código HTTP, sin texto

    }

    // Si viene con "Bearer ", lo separamos
    if (token.startsWith('Bearer ')) {
        token = token.slice(7, token.length).trim();
    }

    console.log('Token recibido en la petición:');

    jwt.verify(token, process.env.JWT_SECRET, (err, usuario) => {
        if (err) {
            return res.end(); // Solo código

        }
        req.usuario = usuario;
        next();
    });
}

function bloquearIPWindows(ip) {
    const ipValida = ip.replace("::ffff:", "");
    const ipRegex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    if (!ipRegex.test(ipValida)) return;

    execFile("netsh", [
        "advfirewall", "firewall", "add", "rule",
        `name=Bloqueo IP ${ipValida}`,
        "dir=in",
        "action=block",
        `remoteip=${ipValida}`
    ], (error, stdout, stderr) => {
        if (error) {
            console.error(`Error al bloquear IP ${ipValida}:`, error);
            return;
        }
        console.log(`IP bloqueada en firewall: ${ipValida}`);
    });
}

//manejo de rutas no definidas para seguridad, redireccion a estado 403
const logFile = 'C:\\Users\\Admin\\Downloads\\INNSA-API\\api.log';
const rateLimit = {};
const MAX_ATTEMPTS = 1;        // Número máximo de intentos permitidos
const BLOCK_TIME = 15 * 60 * 1000; // Tiempo de bloqueo en ms (15 min)

app.use((req, res, next) => {
  const ip = req.ip;

  // Inicializar registro si no existe
  if (!rateLimit[ip]) {
    rateLimit[ip] = { count: 0, blockedUntil: null };
  }

  const now = Date.now();

  // Si la IP está bloqueada y aún sigue bloqueada
  if (rateLimit[ip].blockedUntil && rateLimit[ip].blockedUntil > now) {
    console.log(`IP bloqueada temporalmente: ${ip}`);
   return res.end();
  }

  // Si el bloqueo ya expiró
  if (rateLimit[ip].blockedUntil && rateLimit[ip].blockedUntil <= now) {
    rateLimit[ip].blockedUntil = null;
    rateLimit[ip].count = 0;
  }

  // Verificar rutas prohibidas
const blockedPaths = [
  // Administración y login
  '/admin',
  '/administrator',
  '/login',
  '/wp-login.php',
  '/wp-login',
  '/wp-admin',
  '/user/login',
  '/cpanel',
  '/admin.php',
  '/manager',
  
  // Archivos sensibles y configuración
  '/.env',
  '/.git',
  '/.gitignore',
  '/.htaccess',
  '/config.php',
  '/config',
  '/config.json',
  
  // Backups o dumps
  '/backup',
  '/backups',
  '/db.sql',
  '/dump.sql',
  
  // Robots y sitemap
  '/robots.txt',
  '/sitemap.xml',
  
  // Scripts CGI y exploits comunes
  '/cgi-bin',
  '/cgi-sys',
  '/phpmyadmin',
  '/pma',
  '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
  
  // CMS específicos
  '/joomla',
  '/drupal',
  '/typo3',
  '/magento',
  '/shop',
  
  // Rutas comunes de prueba
  '/test',
  '/testing',
  '/demo',
  '/staging'
];
   if (blockedPaths.some(path => req.url.startsWith(path))) {
    rateLimit[ip].count++;
    const logMsg = `Intento acceso prohibido desde IP: ${ip} - Intento #${rateLimit[ip].count}\n`;
    console.log(logMsg.trim());
    fs.appendFile(logFile, logMsg, err => {
      if (err) console.error('Error escribiendo log:', err);
    });

    if (rateLimit[ip].count >= MAX_ATTEMPTS) {
      rateLimit[ip].blockedUntil = now + BLOCK_TIME;
      console.log(`IP bloqueada por superar límite de intentos: ${ip}`);

      bloquearIPWindows(ip);
      return res.end();
    }

    return res.end();
  }

  next();
});




app.get('/comprobar', (req, res) => {
  res.send('API INNSA activa y ejecutándose v1.7.0');
});


httpServer.listen(port, '::', () => {
  console.log(`API HTTPS escuchando en puerto ${port}`);
});




let pool;

sql.connect(config).then(p => {
    pool = p;
    if(pool.connected) {
        console.log('Connected to SQL Server');
    }
}).catch(err => {
    console.error('Error conectando a SQL Server:', err);
});
//funcion auxiliar para extrar solo hora y minutos del string ISO
function extraerHoraMinutosDeISO(isoString)
{
    try {
        const date =  new Date(isoString);
        const h = date.getHours().toString().padStart(2,'0');
        const m = date.getMinutes().toString().padStart(2,'0');
        return `${h}:${m}`;
    }catch{
        return null;
    }
        
    
}

// Function to calculate retardo (delay) without inserting into DB
async function calcularRetardo(horaDeLlegada, horario, horaInicioFromClient) {
    // Validaciones iniciales
    if (!horaDeLlegada || !horario) {
        console.error('Parámetros requeridos faltantes:', { horaDeLlegada, horario });
        return { retardo: false, diffMin: 0 };
    }

    // Normaliza la hora en formato "HH:mm" o "h:mm A"
    const normalizarHora = (hora) => {
        if (!hora) return null;
        const str = String(hora).trim();

        const regex = /^(?<h>\d{1,2}):(?<m>\d{1,2})(?::\d{1,2})?\s?(?<ampm>[APap][Mm])?$/;
        const match = str.match(regex);
        if (!match) {
            console.warn(`Formato de hora no válido: ${hora}`);
            return null;
        }

        let h = parseInt(match.groups.h);
        const m = match.groups.m.padStart(2, '0');
        const ampm = match.groups.ampm?.toUpperCase();

        if (ampm === 'PM' && h !== 12) h += 12;
        if (ampm === 'AM' && h === 12) h = 0;

        return `${h.toString().padStart(2, '0')}:${m}`;
    };

    const horaAMinutos = (horaStr) => {
        const [h, m] = horaStr.split(':').map(Number);
        return h * 60 + m;
    };

    // Normaliza las horas que se recibieron
    const horaDeLlegadaNorm = normalizarHora(horaDeLlegada);
    const horaInicioNorm = horaInicioFromClient ? normalizarHora(horaInicioFromClient) : null;

    if (!horaDeLlegadaNorm) {
        console.error('Hora de llegada inválida:', horaDeLlegada);
        return { retardo: false, diffMin: 0 };
    }

    let retardo = false;
    let diffMin = 0;
    let limiteMinutos = 15;

    try {
        const result = await pool.request()
            .input('ContratoHorarioID', sql.Int, parseInt(horario))
            .query(`
                SELECT 
                    CONVERT(VARCHAR(8), h.HoraInicio, 108) AS HoraInicio,
                    COALESCE(c.LimiteDeTiempo, 15) AS LimiteDeTiempo
                FROM Horarios h
                INNER JOIN Contrato_Horario ch ON h.HorarioID = ch.HorarioID
                INNER JOIN Contratos c ON ch.ContratoID = c.ContratoID
                WHERE ch.ContratoHorarioID = @ContratoHorarioID
            `);

        if (result.recordset.length === 0) {
            console.error(`ContratoHorarioID no encontrado: ${horario}`);
            return { retardo: false, diffMin: 0 };
        }

        const { HoraInicio, LimiteDeTiempo } = result.recordset[0];
        const horaProgramada = horaInicioNorm || normalizarHora(HoraInicio);
        limiteMinutos = Math.max(parseInt(LimiteDeTiempo) || 15, 0);

        if (!horaProgramada) {
            console.error('Hora programada inválida:', HoraInicio);
            return { retardo: false, diffMin: 0 };
        }

        const programadaMin = horaAMinutos(horaProgramada);
        const llegadaMin = horaAMinutos(horaDeLlegadaNorm);
        const maxPermitidoMin = programadaMin - limiteMinutos;

        // Manejar cruce de medianoche
        let diff = ((llegadaMin - maxPermitidoMin + 1440) % 1440);
        if (diff > 720) diff -= 1440;

        retardo = diff > 0;
        diffMin = diff;

        console.log('Cálculo de retardo final:', {
            horarioID: horario,
            horaProgramada,
            horaDeLlegada: horaDeLlegadaNorm,
            limiteMinutos,
            horaMaximaPermitida: `${Math.floor(maxPermitidoMin / 60)}:${(maxPermitidoMin % 60).toString().padStart(2, '0')}`,
            diferenciaMinutos: diffMin,
            retardo,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error en calcularRetardo:', error);
        return { retardo: false, diffMin: 0 };
    }

    return { retardo, diffMin };
}


// POST endpoint to calculate retardo without inserting
app.post('/calculate-retardo', verificarToken, async (req, res) => {
    const { tipoMovimientoID, horario, horaInicio, horaDeLlegada: horaDeLlegadaCliente } = req.body;

    if (!horario) {
        return res.status(400).json({ success: false, message: 'El campo "Horario" es requerido' });
    }

    try {
        // Determinar hora de llegada: cliente o actual
        const horaDeLlegada = horaDeLlegadaCliente 
            ? DateTime.fromISO(horaDeLlegadaCliente, { zone: 'utc' }).setZone('America/Matamoros').toFormat('HH:mm')
            : DateTime.now().setZone('America/Matamoros').toFormat('HH:mm');

        console.log('Hora generada antes de calcularRetardo:', horaDeLlegada);

        let retardo = null;
        let diffMin = null;

        // Solo calcular si tipoMovimientoID != 6
        if (tipoMovimientoID !== 6) {
            const result = await calcularRetardo(horaDeLlegada, horario, horaInicio);
            retardo = result.retardo;
            diffMin = result.diffMin;
        }

        // Siempre retornar la hora y el resultado (si lo hay)
        res.json({
            success: true,
            horaDeLlegada,
            retardo,
            diffMin
        });

    } catch (err) {
        console.error('Error en /calculate-retardo:', err);
        res.status(500).json({
            success: false,
            message: 'Error calculando retardo',
            detalle: err.message
        });
    }
});



       
    


// POST endpoint to register route
app.post('/register-route', verificarToken,async (req, res) => {
    const registros = Array.isArray(req.body.registros) ? req.body.registros : [req.body];

    // Función normalizarHora igual que antes
    const normalizarHora = (hora) => {
        if (!hora) return null;
        try {
            if (hora.includes('T')) {
                const dt = DateTime.fromISO(hora);
                return dt.isValid ? dt.toFormat('HH:mm:ss') : null;
            }
            const [hh, mm, ss] = hora.trim().split(':');
            const horas = hh.padStart(2, '0');
            const minutos = (mm || '00').padStart(2, '0');
            const segundos = (ss || '00').padStart(2, '0');
            return `${horas}:${minutos}:${segundos}`;
        } catch (error) {
            console.error("Error normalizando hora:", hora, error);
            return null;
        }
    };

    const resultados = [];

    for (const registro of registros) {
        const {
            unidad,
            rutas,
            coordinador,
            falla,
            fecha,
            personalABordo,
            requiereApoyo,
            registrarLlegada,
            horario,
            tipoMovimientoID,
            horaInicio: horaInicioFromClient,
            horaCalculoPreliminar,
            horaDeLlegada: horaDeLlegadaFromClient,
            retardo: retardoFromClient
        } = registro;
      
      if(!Array.isArray(rutas) || rutas.length === 0 ){
        resultados.push({registro, succes: false, message: "Debe incluir al menos una ruta"});
        continue;
      }

        // Normalizar hora
        const horaDeLlegadaFinal = registrarLlegada
            ? normalizarHora(horaCalculoPreliminar || horaDeLlegadaFromClient)
            : null;

        // Validación básica
        if (registrarLlegada && !horaDeLlegadaFinal) {
            resultados.push({
                registro,
                success: false,
                message: "Se requiere hora de llegada (horaCalculoPreliminar o horaDeLlegada)"
            });
            continue;
        }

        try {

           // agregar aqui condicional para solo hacer el calculo del retardo en los horarios de entrada o los tipomiviento 5
            // Cálculo de retardo
            const tipoMOvimiento = parseInt(tipoMovimientoID, 10);
            let retardo = false;
            let diffMin = 0;
            
            if(tipoMOvimiento !==6){
                if (retardoFromClient !== undefined) {
                retardo = retardoFromClient;
            } else if (horaDeLlegadaFinal && horario) {
                const resultado = await calcularRetardo(
                    horaDeLlegadaFinal.substring(0, 5),
                    horario,
                    horaInicioFromClient
                );
                retardo = resultado.retardo;
                diffMin = resultado.diffMin;
            }

                
            }
            
            // Insertar registro
            const insertRequest = pool.request()
                .input('UnidadID', sql.Int, parseInt(unidad))
                .input('CoordinadorID', sql.Int, parseInt(coordinador))
                .input('FallaID', sql.VarChar(50), falla ? falla.toString() : null)
                .input('Fecha', sql.Date, fecha)
                .input('PersonalABordo', sql.VarChar(50), personalABordo ? personalABordo.toString() : '')
                .input('Apoyo', sql.Bit, requiereApoyo ? 1 : 0)
                .input('HoraDeLlegada', sql.VarChar(8), horaDeLlegadaFinal)
                .input('ContratoHorarioID', sql.Int, parseInt(horario))
                .input('Retardo', sql.Bit, retardo ? 1 : 0)
                .input('TipoMovimientoID', sql.Int, parseInt(tipoMovimientoID));

           const insertResult = await insertRequest.query(`
                INSERT INTO Registros_Rutas
                (UnidadID, CoordinadorID, FallaID, Fecha, PersonalABordo, Apoyo, HoraDeLlegada, ContratoHorarioID, Retardo, TipoMovimientoID)
                OUTPUT INSERTED.RegistroID
                VALUES
                (@UnidadID, @CoordinadorID, @FallaID, @Fecha, @PersonalABordo, @Apoyo, @HoraDeLlegada, @ContratoHorarioID, @Retardo, @TipoMovimientoID)
            `);
          const registroID = insertResult.recordset[0].RegistroID;

          //insertar rutas en la tabla intermedia para rutas empalmadas
          for(let i = 0; i< rutas.length; i++){
            await pool.request()
            .input('RegistroID', sql.Int, registroID)
            .input('RutaID', sql.Int, parseInt(rutas[i]))
            .input('Orden', sql.Int, i+1)
            .query(` INSERT INTO REGISTRO_RUTAS_MULTIPLES (RegistroID, RutaID, Orden)
                   VALUES (@RegistroID, @RutaID, @Orden)`);
          }
          // Emitir notificacion en tiempo real para wpf
          io.emit('nuevoRegistro',{
            registroID,
            unidad,
            rutas,
            coordinador,
            fecha,
            horaDeLlegada: horaDeLlegadaFinal,
            retardo,
            fuenteHora: horaCalculoPreliminar ? 'horaCalculoPreliminar' : 'horaDeLlegada'
          });

            resultados.push({
                registro,
                success: true,
                message: "Registro insertado correctamente.",
                horaRegistrada: horaDeLlegadaFinal,
                retardo,
                minutosRetraso: diffMin,
                fuenteHora: horaCalculoPreliminar ? 'horaCalculoPreliminar' : 'horaDeLlegada'
            });

        } catch (error) {
            resultados.push({
                registro,
                success: false,
                message: "Error interno al insertar.",
                error: error.message
            });
        }
    }

    res.json({ success: true, resultados });
  console.log("Resultados de inserción:", resultados);

});




    // Endpoint to get Unidades
    app.get('/unidades', verificarToken,async (req, res) => {
        try {
            const result = await pool.request().query('SELECT UnidadID, Unidad FROM Unidades');
            res.json(result.recordset);
        } catch (err) {
            console.error('Error fetching Unidades:', err);
            res.status(500).json({ error: 'Error fetching Unidades' });
        }
    });

  app.get('/rutas', verificarToken, async (req, res) => {
    try {
        const contratoHorarioID = req.query.contratoHorarioID;
        const coordinadorID = req.query.coordinadorID;

        let query = `
            SELECT DISTINCT r.RutaID, r.DescripcionRuta
            FROM CONTRATO_HORARIO_RUTA chr
            INNER JOIN Rutas r ON chr.RutaID = r.RutaID
            INNER JOIN Contrato_Horario ch ON chr.ContratoHorarioID = ch.ContratoHorarioID
        `;

        const request = pool.request();

        // Condiciones dinámicas
        const condiciones = [];

        if (contratoHorarioID) {
            condiciones.push(`chr.ContratoHorarioID = @ContratoHorarioID`);
            request.input('ContratoHorarioID', sql.Int, parseInt(contratoHorarioID));
        }

        if (coordinadorID) {
            query += `
                INNER JOIN coordinador_contrato cc ON ch.ContratoID = cc.ContratoID
            `;
            condiciones.push(`cc.CoordinadorID = @CoordinadorID`);
            request.input('CoordinadorID', sql.Int, parseInt(coordinadorID));
        }

        if (condiciones.length > 0) {
            query += ' WHERE ' + condiciones.join(' AND ');
        }

        query += ' ORDER BY r.DescripcionRuta';

        const result = await request.query(query);
        res.json(result.recordset);
    } catch (err) {
        console.error('Error fetching Rutas:', err);
        res.status(500).json({ error: 'Error fetching Rutas', detalle: err.message });
    }
});


    // Endpoint to get Coordinadores
    app.get('/coordinadores', verificarToken,async (req, res) => {
        try {
            const result = await pool.request().query('SELECT CoordinadorID, Nombre FROM Coordinadores');
            res.json(result.recordset);
        } catch (err) {
            console.error('Error fetching Coordinadores:', err);
            res.status(500).json({ error: 'Error fetching Coordinadores' });
        }
    });

app.get('/horarios',verificarToken, async (req, res) => {
        try {
            const coordinadorID = req.query.coordinadorID;
            const contratoID = req.query.contratoID;
            const tipoMovimientoID = req.query.tipoMovimientoID;
            let query = `
                SELECT 
                    ch.ContratoHorarioID,
                    ISNULL(c.Cliente, '') AS Cliente,
                    ISNULL(h.Descripcion, '') AS HorarioNombre,
                    CONVERT(varchar(8), h.HoraInicio, 108) AS HoraInicio,
                    CONVERT(varchar(8), h.HoraFin, 108) AS HoraFin
                FROM 
                    Contrato_Horario ch
                INNER JOIN 
                    Contratos c ON ch.ContratoID = c.ContratoID
                INNER JOIN 
                    Horarios h ON ch.HorarioID = h.HorarioID
            `;
            const request = pool.request();

            if (coordinadorID && contratoID && tipoMovimientoID) {
                query += `
                    INNER JOIN coordinador_contrato cc ON c.ContratoID = cc.ContratoID
                    WHERE cc.CoordinadorID = @CoordinadorID AND c.ContratoID = @ContratoID AND h.TipoMovimientoID = @TipoMovimientoID
                `;
                request.input('CoordinadorID', sql.Int, parseInt(coordinadorID));
                request.input('ContratoID', sql.Int, parseInt(contratoID));
                request.input('TipoMovimientoID', sql.Int, parseInt(tipoMovimientoID));
            } else if (contratoID && tipoMovimientoID) {
                query += ` WHERE c.ContratoID = @ContratoID AND h.TipoMovimientoID = @TipoMovimientoID`;
                request.input('ContratoID', sql.Int, parseInt(contratoID));
                request.input('TipoMovimientoID', sql.Int, parseInt(tipoMovimientoID));
            } else if (coordinadorID && contratoID) {
                query += `
                    INNER JOIN coordinador_contrato cc ON c.ContratoID = cc.ContratoID
                    WHERE cc.CoordinadorID = @CoordinadorID AND c.ContratoID = @ContratoID
                `;
                request.input('CoordinadorID', sql.Int, parseInt(coordinadorID));
                request.input('ContratoID', sql.Int, parseInt(contratoID));
            } else if (contratoID) {
                query += ` WHERE c.ContratoID = @ContratoID`;
                request.input('ContratoID', sql.Int, parseInt(contratoID));
            }

            const result = await request.query(query);
            res.json(result.recordset);
        } catch (err) {
            console.error('Error fetching Horarios:', err);
            res.status(500).json({ error: 'Error fetching Horarios' });
        }
    });

    // Endpoint to get Fallas
    app.get('/fallas',verificarToken, async (req, res) => {
        try {
            const result = await pool.request().query('SELECT FallaID, Descripcion FROM Fallas');
            res.json(result.recordset);
        } catch (err) {
            console.error('Error fetching Fallas:', err);
            res.status(500).json({ error: 'Error fetching Fallas' });
        }
    });

    // Endpoint to get Contratos
    app.get('/contratos', verificarToken,async (req, res) => {
        try {
            const coordinadorID = req.query.coordinadorID;
            let query = 'SELECT ContratoID, Cliente FROM Contratos';
            const request = pool.request();
            let mensaje = ''; // Variable para el mensaje

            if (coordinadorID) {
                query = `
                    SELECT DISTINCT c.ContratoID, c.Cliente
                    FROM Contratos c
                    INNER JOIN coordinador_contrato cc ON c.ContratoID = cc.ContratoID
                    WHERE cc.CoordinadorID = @CoordinadorID
                `;
                request.input('CoordinadorID', sql.Int, parseInt(coordinadorID));
                mensaje = `Filtrando contratos por coordinadorID: ${coordinadorID}`;
            } else {
                mensaje = 'Mostrando todos los contratos (no se especificó coordinadorID)';
            }

            console.log('Ejecutando consulta contratos:', query, 'con coordinadorID:', coordinadorID);

            const result = await request.query(query);
            
            // Devolver tanto los datos como el mensaje
            res.json({
                mensaje: mensaje,
                data: result.recordset
            });
            
        } catch (err) {
            console.error('Error fetching Contratos:', err);
            console.error('Stack trace:', err.stack);
            res.status(500).json({ 
                error: 'Error fetching Contratos',
                detalle: err.message 
            });
        }
    });

    // Endpoint to get Horario and LimiteDeTiempo by ContratoHorarioID
    app.get('/horario-info/:contratoHorarioID', verificarToken,async (req, res) => {
        const contratoHorarioID = parseInt(req.params.contratoHorarioID);
        try {
            const query = `
                SELECT 
                    h.HoraInicio,
                    c.LimiteDeTiempo
                FROM 
                    Horarios h
                INNER JOIN 
                    Contrato_Horario ch ON h.HorarioID = ch.HorarioID
                INNER JOIN 
                    Contratos c ON ch.ContratoID = c.ContratoID
                WHERE 
                    ch.ContratoHorarioID = @ContratoHorarioID
            `;
            const request = pool.request();
            request.input('ContratoHorarioID', sql.Int, contratoHorarioID);
            const result = await request.query(query);
            if (result.recordset.length > 0) {
                res.json(result.recordset[0]);
            } else {
                res.status(404).json({ error: 'Horario no encontrado' });
            }
        } catch (err) {
            console.error('Error fetching horario info:', err);
            res.status(500).json({ error: 'Error fetching horario info' });
        }
    });



app.post('/sesion',express.json(), async (req, res) => {
    if (!pool || !pool.connected) {
        try {
            pool = await sql.connect(config);
        } catch (err) {
            console.error('Error conectando a SQL Server en login:', err);
            return res.status(500).json({ success: false, message: 'DB connection error' });
        }
    }
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    try {
        const request = pool.request();
        request.input('NombreUsuario', username);
        request.input('Contraseña', password);

        const result = await request.execute('sp_AutenticarUsuario');

        if (result.recordset && result.recordset.length > 0) {
            const authResult = result.recordset[0];
            if (authResult.Autenticado === 1) {
                // Obtener CoordinadorID del usuario autenticado
                const userRequest = pool.request();
                userRequest.input('NombreUsuario', username);
                const userResult = await userRequest.query(`
                    SELECT u.CoordinadorID, c.Nombre AS CoordinadorNombre
                    FROM Usuarios u
                    LEFT JOIN Coordinadores c ON u.CoordinadorID = c.CoordinadorID
                    WHERE u.NombreUsuario = @NombreUsuario
                `);
                const coordinadorID = userResult.recordset.length > 0 ? userResult.recordset[0].CoordinadorID : null;
                const coordinadorNombre = userResult.recordset.length > 0 ? userResult.recordset[0].CoordinadorNombre : null;

                //Generar token JWT
                const token = jwt.sign(
                    {username, coordinadorID},
                    process.env.JWT_SECRET,
                    {expiresIn: '8h'}
                );
                return res.json({
                    success: true,
                    message: authResult.Mensaje,
                    coordinadorID,
                    coordinadorNombre,
                    token
                });

            } else {
                res.status(401).json({ success: false, message: authResult.Mensaje });
            }
        } else {
            res.status(401).json({ success: false, message: 'Authentication failed' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// funcion con api para obtener la hora local y usarla para evitar inconsistencia en las horas de registro en la web
app.get('/hora-servidor', verificarToken,(req,res )=> {
    const horaNuevoLaredo = DateTime.now().setZone('America/Matamoros');
    res.json({
        hora:horaNuevoLaredo.toISO(),
        hora_legible: horaNuevoLaredo.toLocaleString(DateTime.DATETIME_MED_WITH_SECONDS),
        zona: horaNuevoLaredo.zoneName
    
    });
});

// Obtener la capacidad por unidad
app.get('/Capacidad-unidad', verificarToken,async (req, res) => {
    try {
        const unidadID = parseInt(req.query.unidadID);
        if (isNaN(unidadID)) {
            return res.status(400).json({ error: 'unidadID inválido' });
        }

        const result = await pool
            .request()
            .input('unidadID', unidadID)
            .query('SELECT Capacidad FROM Unidades WHERE UnidadID = @unidadID');

        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'Unidad no encontrada' });
        }

        res.json(result.recordset[0]);
    } catch (err) {
        console.error('Error al obtener capacidad:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});


// bloquear y desbloquear filas 
app.get('/estado-bloqueo', verificarToken,async (req, res) => {
  const coordinadorId = parseInt(req.query.coordinadorId, 10);
  if (isNaN(coordinadorId) || coordinadorId <= 0) {
    return res.status(400).json({ error: 'coordinadorId inválido' });
  }

  try {
    await sql.connect(config);

    const result = await sql.query`
      SELECT 
        CH.ContratoHorarioID,
        H.HoraInicio
      FROM Contrato_Horario AS CH
      JOIN Horarios AS H ON CH.HorarioID = H.HorarioID
      JOIN Coordinador_Contrato AS CC ON CH.ContratoID = CC.ContratoID
      WHERE CC.CoordinadorID = ${coordinadorId}
    `;

    const zona = 'America/Matamoros';
    const now = DateTime.now().setZone(zona);

    const horariosProcesados = result.recordset.map(({ ContratoHorarioID, HoraInicio }) => {
      // Convertir HoraInicio (Date) a hora en zona correcta, pero con la fecha de hoy
      const horaLuxon = DateTime.fromJSDate(HoraInicio).setZone(zona);
      const horaProgramadaReal = now.set({
        hour: horaLuxon.hour,
        minute: horaLuxon.minute,
        second: horaLuxon.second
      });

      let horaFinal = horaProgramadaReal;
      if (horaFinal < now) {
        horaFinal = horaFinal.plus({ days: 1 });
      }

      const minutosParaHorario = Math.round(horaFinal.diff(now, 'minutes').minutes);
      const bloqueado = minutosParaHorario >= -15 && minutosParaHorario <= 60 ? 0 : 1;

      return {
        ContratoHorarioID,
        HoraServidor: now.toFormat('hh:mm a'),
        HoraProgramada: horaFinal.toFormat('hh:mm a'),
        HoraProgramadaReal: horaFinal.toISO(),
        MinutosParaHorario: minutosParaHorario,
        Bloqueado: bloqueado
      };
    });

    res.json(horariosProcesados);

  } catch (err) {
    console.error('[ERROR SQL]', err);
    res.status(500).json({ error: err.message || 'Error en la consulta' });
  }
});


app.get('/reporte-usuario', verificarToken,async(req, res) => {
  const coordinadorId = parseInt(req.query.coordinadorId,10)
  if(isNaN(coordinadorId) || coordinadorId <=0){
  return res.status(400).json({error: 'Error el coordinadorId es invalido'});
  }
        try{
                const contratoID = req.query.contratoAsignado || null;
                const fechaInicio = req.query.fechaInicio || null;
                const fechaFin = req.query.fechaFin || null;
                const contratoHorarioID = req.query.contratoHorario || null;
                const result = await pool.request()
                    .input('CoordinadorID', coordinadorId)
                    .input('FechaInicio', fechaInicio)
                    .input('FechaFin', fechaFin)
                    .input('ContratoID', contratoID)
                    .input('ContratoHorarioID', contratoHorarioID)
                    .query(`
                    SELECT
                    rr.RegistroID,
                    u.Unidad as Unidad,
                    STRING_AGG(r.DescripcionRuta, ', ') WITHIN GROUP (ORDER BY rrm.Orden) as Rutas,
                    co.Nombre as Coordinador,
                    FORMAT(rr.Fecha, 'yyyy-MM-dd') as Fecha,
                    rr.PersonalAbordo,
                    CASE WHEN rr.Retardo = 1 THEN 'Si' ELSE 'No' END as Retardo,
                    ISNULL(FORMAT(CAST(rr.HoraDeLlegada as DATETIME), 'hh:mm:tt'), '') as HoraLlegada,
                    c.Cliente + ' - ' + ISNULL(FORMAT(CAST(h.HoraInicio as DATETIME), 'hh:mm:tt'), '') as HorarioContrato,
                    tm.Nombre as Tipo
                  FROM REGISTROS_RUTAS rr
                  LEFT JOIN UNIDADES u ON rr.UnidadID = u.UnidadID
                  LEFT JOIN REGISTRO_RUTAS_MULTIPLES rrm ON rr.RegistroID = rrm.RegistroID
                  LEFT JOIN RUTAS r ON rrm.RutaID = r.RutaID
                  LEFT JOIN COORDINADORES co ON rr.CoordinadorID = co.CoordinadorID
                  LEFT JOIN FALLAS f ON rr.FallaID = f.FallaID
                  LEFT JOIN CONTRATO_HORARIO ch ON rr.ContratoHorarioID = ch.ContratoHorarioID
                  LEFT JOIN CONTRATOS c ON ch.ContratoID = c.ContratoID
                  LEFT JOIN HORARIOS h ON ch.HorarioID = h.HorarioID
                  LEFT JOIN TIPO_MOVIMIENTO tm ON h.TipoMovimientoID = tm.TipoMovimientoID
                  WHERE
                    co.CoordinadorID = @CoordinadorID
                    AND (
                      (@FechaInicio IS NULL AND @FechaFin IS NULL)
                      OR (
                        rr.Fecha >= COALESCE(@FechaInicio, '1900-01-01')
                        AND rr.Fecha <= COALESCE(@FechaFin, '9999-12-31')
                      )
                    )
                    AND (@ContratoID IS NULL OR c.ContratoID = @ContratoID)
                    AND (@ContratoHorarioID IS NULL OR ch.ContratoHorarioID = @ContratoHorarioID)
                  
                  GROUP BY
                    rr.RegistroID,
                    u.Unidad,
                    co.Nombre,
                    rr.Fecha,
                    rr.PersonalAbordo,
                    rr.Retardo,
                    rr.HoraDeLlegada,
                    c.Cliente,
                    h.HoraInicio,
                    tm.Nombre
                  ORDER BY rr.Fecha DESC;`
                  );
              return res.json(result.recordset);
        }catch(error){
            console.error('Error fetching reporte usuario:', error);
            res.status(500).json({error: 'Error fetching reporte usuario'});
}
});

        



app.get('/tipos-movimiento',verificarToken, async (req, res) => {
    try {
        const result = await pool.request().query(`
            SELECT TOP (1000) TipoMovimientoID, Nombre, Descripcion
            FROM TIPO_MOVIMIENTO
        `);
        res.json(result.recordset);
    } catch (error) {
        console.error('Error fetching tipos de movimiento:', error);
        res.status(500).json({ error: 'Error fetching tipos de movimiento' });
    }
});

// Middleware para manejar rutas no definidas
app.use((req, res) => {
  console.log(`Ruta no encontrada: ${req.method} ${req.url}`);
  res.end();
});


