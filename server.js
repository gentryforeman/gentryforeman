// server.js - Backend API Server for Foreman System

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const fs = require('fs').promises;
const path = require('path');
const OAuthClient = require('intuit-oauth');
const axios = require('axios');
require('dotenv').config();

// QuickBooks OAuth Client
const qbOAuthClient = new OAuthClient({
    clientId: process.env.QB_CLIENT_ID,
    clientSecret: process.env.QB_CLIENT_SECRET,
    environment: process.env.QB_ENVIRONMENT || 'sandbox',
    redirectUri: process.env.QB_REDIRECT_URI || 'http://localhost:3000/api/quickbooks/callback',
    logging: false
});

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Serve home.html as the default landing page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// Database connection - use Neon cloud DATABASE_URL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Database connected successfully');
    }
});

// File upload configuration
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = './uploads';
        try {
            await fs.mkdir(uploadDir, { recursive: true });
            cb(null, uploadDir);
        } catch (error) {
            cb(error, null);
        }
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + file.originalname;
        cb(null, uniqueName);
    }
});

const upload = multer({ storage });

// Photo upload configuration (for daily record photos)
const photoStorage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = './uploads/photos';
        try {
            await fs.mkdir(uploadDir, { recursive: true });
            cb(null, uploadDir);
        } catch (error) {
            cb(error, null);
        }
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const photoUpload = multer({ 
    storage: photoStorage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|heic|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Only image files are allowed'));
    }
});

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// ========== AUTHENTICATION ROUTES ==========

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.full_name,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Register new user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, full_name, role } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            'INSERT INTO users (email, password_hash, full_name, role) VALUES ($1, $2, $3, $4) RETURNING id, email, full_name, role',
            [email, hashedPassword, full_name, role || 'office']
        );

        res.status(201).json({ user: result.rows[0] });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// ========== JOBS ROUTES ==========

// Get all jobs
app.get('/api/jobs', async (req, res) => {
    try {
        const { status, crew_lead_id } = req.query;
        let query = 'SELECT j.*, cl.name as crew_lead_name, cl.color FROM jobs j LEFT JOIN crew_leads cl ON j.crew_lead_id = cl.id';
        const params = [];

        if (status || crew_lead_id) {
            query += ' WHERE';
            if (status) {
                params.push(status);
                query += ` j.status = $${params.length}`;
            }
            if (crew_lead_id) {
                if (status) query += ' AND';
                params.push(crew_lead_id);
                query += ` j.crew_lead_id = $${params.length}`;
            }
        }

        query += ' ORDER BY j.created_at DESC';

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching jobs:', error);
        res.status(500).json({ error: 'Failed to fetch jobs' });
    }
});

// Get single job
app.get('/api/jobs/:id', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT j.*, cl.name as crew_lead_name, cl.color FROM jobs j LEFT JOIN crew_leads cl ON j.crew_lead_id = cl.id WHERE j.id = $1',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Job not found' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching job:', error);
        res.status(500).json({ error: 'Failed to fetch job' });
    }
});

// Create job
app.post('/api/jobs', async (req, res) => {
    try {
        const { job_number, job_name, location, contractor_name, crew_lead_id, start_date, end_date, notes } = req.body;

        const result = await pool.query(
            'INSERT INTO jobs (job_number, job_name, location, contractor_name, crew_lead_id, start_date, end_date, notes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
            [job_number, job_name, location, contractor_name, crew_lead_id, start_date, end_date, notes]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error creating job:', error);
        res.status(500).json({ error: 'Failed to create job' });
    }
});

// Update job
app.put('/api/jobs/:id', async (req, res) => {
    try {
        const { job_name, location, contractor_name, customer_name, crew_lead_id, status, start_date, end_date, notes, contract_value, income } = req.body;

        // Build dynamic update query based on what fields are provided
        const updates = [];
        const values = [];
        let paramIndex = 1;

        if (job_name !== undefined) { updates.push(`job_name = $${paramIndex++}`); values.push(job_name); }
        if (location !== undefined) { updates.push(`location = $${paramIndex++}`); values.push(location); }
        if (contractor_name !== undefined) { updates.push(`contractor_name = $${paramIndex++}`); values.push(contractor_name); }
        if (customer_name !== undefined) { updates.push(`contractor_name = $${paramIndex++}`); values.push(customer_name); }
        if (crew_lead_id !== undefined) { updates.push(`crew_lead_id = $${paramIndex++}`); values.push(crew_lead_id); }
        if (status !== undefined) { updates.push(`status = $${paramIndex++}`); values.push(status); }
        if (start_date !== undefined) { updates.push(`start_date = $${paramIndex++}`); values.push(start_date); }
        if (end_date !== undefined) { updates.push(`end_date = $${paramIndex++}`); values.push(end_date); }
        if (notes !== undefined) { updates.push(`notes = $${paramIndex++}`); values.push(notes); }
        if (contract_value !== undefined) { updates.push(`income = $${paramIndex++}`); values.push(contract_value); }
        if (income !== undefined) { updates.push(`income = $${paramIndex++}`); values.push(income); }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(req.params.id);

        const result = await pool.query(
            `UPDATE jobs SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
            values
        );

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating job:', error);
        res.status(500).json({ error: 'Failed to update job' });
    }
});

// ========== CREW LEADS ROUTES ==========

// Get all crew leads
app.get('/api/crew-leads', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM crew_leads ORDER BY name');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching crew leads:', error);
        res.status(500).json({ error: 'Failed to fetch crew leads' });
    }
});

// Create crew lead
app.post('/api/crew-leads', async (req, res) => {
    try {
        const { name, color } = req.body;

        const result = await pool.query(
            'INSERT INTO crew_leads (name, color) VALUES ($1, $2) RETURNING *',
            [name, color]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error creating crew lead:', error);
        res.status(500).json({ error: 'Failed to create crew lead' });
    }
});

// ========== WORKERS ROUTES ==========

// Get all workers
app.get('/api/workers', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM workers ORDER BY full_name');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching workers:', error);
        res.status(500).json({ error: 'Failed to fetch workers' });
    }
});

// Create worker
app.post('/api/workers', async (req, res) => {
    try {
        const { full_name, role, contact_info, hire_date } = req.body;

        const result = await pool.query(
            'INSERT INTO workers (full_name, role, contact_info, hire_date) VALUES ($1, $2, $3, $4) RETURNING *',
            [full_name, role, contact_info, hire_date]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error creating worker:', error);
        res.status(500).json({ error: 'Failed to create worker' });
    }
});

// Assign worker to foreman
app.put('/api/workers/:id/foreman', async (req, res) => {
    try {
        const { foreman_id } = req.body;
        const result = await pool.query(
            'UPDATE workers SET foreman_id = $1 WHERE id = $2 RETURNING *',
            [foreman_id, req.params.id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error assigning foreman:', error);
        res.status(500).json({ error: 'Failed to assign foreman' });
    }
});

// Get workers by foreman
app.get('/api/workers/by-foreman/:foremanId', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM workers WHERE foreman_id = $1 AND active = true ORDER BY full_name',
            [req.params.foremanId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching workers by foreman:', error);
        res.status(500).json({ error: 'Failed to fetch workers' });
    }
});

// ========== ITEMS ROUTES ==========

// Get all items
app.get('/api/items', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM items ORDER BY name');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching items:', error);
        res.status(500).json({ error: 'Failed to fetch items' });
    }
});

// Public items endpoint
app.get('/api/public/items', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM items ORDER BY name');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching items:', error);
        res.status(500).json({ error: 'Failed to fetch items' });
    }
});

// Get work items for a daily record
app.get('/api/daily-records/:id/work-items', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT wi.*, i.name as item_name, i.unit_of_measure FROM work_items wi JOIN items i ON wi.item_id = i.id WHERE wi.daily_record_id = $1 ORDER BY wi.created_at',
            [req.params.id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching work items:', error);
        res.status(500).json({ error: 'Failed to fetch work items' });
    }
});

// Get worker hours for a daily record
app.get('/api/daily-records/:id/worker-hours', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT wh.*, w.full_name, w.role
             FROM worker_hours wh
             JOIN workers w ON wh.worker_id = w.id
             WHERE wh.daily_record_id = $1
             ORDER BY w.full_name`,
            [req.params.id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching worker hours:', error);
        res.status(500).json({ error: 'Failed to fetch worker hours' });
    }
});

// ========== DAILY RECORDS ROUTES ==========

// Get daily records for a job
app.get('/api/jobs/:jobId/daily-records', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT dr.*, w.full_name as foreman_name FROM daily_records dr LEFT JOIN workers w ON dr.foreman_id = w.id WHERE dr.job_id = $1 ORDER BY dr.record_date DESC',
            [req.params.jobId]
        );

        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching daily records:', error);
        res.status(500).json({ error: 'Failed to fetch daily records' });
    }
});

// Create daily record
app.post('/api/daily-records', async (req, res) => {
    try {
        const { job_id, foreman_id, record_date, notes, work_items, worker_hours, takeoff_entries, yards_poured } = req.body;

        // Start transaction
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // Create daily record with yards_poured
            const recordResult = await client.query(
                'INSERT INTO daily_records (job_id, foreman_id, record_date, notes, yards_poured) VALUES ($1, $2, $3, $4, $5) RETURNING *',
                [job_id, foreman_id, record_date, notes, yards_poured || 0]
            );

            const dailyRecordId = recordResult.rows[0].id;

            // Add work items (legacy)
            if (work_items && work_items.length > 0) {
                for (const item of work_items) {
                    await client.query(
                        'INSERT INTO work_items (daily_record_id, item_id, quantity) VALUES ($1, $2, $3)',
                        [dailyRecordId, item.item_id, item.quantity]
                    );
                }
            }

            // Add worker hours with labor_rate snapshot from workers table
            if (worker_hours && worker_hours.length > 0) {
                for (const wh of worker_hours) {
                    // Get worker's current labor rate
                    const workerResult = await client.query(
                        'SELECT labor_rate FROM workers WHERE id = $1',
                        [wh.worker_id]
                    );
                    const laborRate = workerResult.rows[0]?.labor_rate || 25.00; // Default $25/hr

                    await client.query(
                        'INSERT INTO worker_hours (daily_record_id, worker_id, hours_worked, labor_rate) VALUES ($1, $2, $3, $4)',
                        [dailyRecordId, wh.worker_id, wh.hours_worked, laborRate]
                    );
                }
            }

            // Add takeoff entries and update job_takeoffs progress
            if (takeoff_entries && takeoff_entries.length > 0) {
                for (const entry of takeoff_entries) {
                    // Save to daily_record_production
                    await client.query(
                        `INSERT INTO daily_record_production (daily_record_id, job_id, item_name, quantity, unit)
                         VALUES ($1, $2, $3, $4, $5)`,
                        [dailyRecordId, job_id, entry.item_name, entry.quantity, entry.unit]
                    );

                    // Update job_takeoffs quantity_completed
                    if (entry.takeoff_id) {
                        await client.query(
                            `UPDATE job_takeoffs
                             SET quantity_completed = COALESCE(quantity_completed, 0) + $1,
                                 status = CASE
                                     WHEN COALESCE(quantity_completed, 0) + $1 >= quantity THEN 'complete'
                                     WHEN COALESCE(quantity_completed, 0) + $1 > 0 THEN 'in_progress'
                                     ELSE 'pending'
                                 END
                             WHERE id = $2`,
                            [entry.quantity, entry.takeoff_id]
                        );
                    }
                }
            }

            await client.query('COMMIT');
            res.status(201).json(recordResult.rows[0]);
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error creating daily record:', error);
        res.status(500).json({ error: 'Failed to create daily record' });
    }
});

// ========== PHOTO UPLOAD ROUTES ==========

// Upload photos for a daily record
app.post('/api/daily-records/:id/photos', photoUpload.array('photos', 10), async (req, res) => {
    try {
        const dailyRecordId = req.params.id;
        
        // Verify daily record exists
        const recordCheck = await pool.query('SELECT id FROM daily_records WHERE id = $1', [dailyRecordId]);
        if (recordCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Daily record not found' });
        }

        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: 'No files uploaded' });
        }

        const uploadedFiles = [];
        for (const file of req.files) {
            const result = await pool.query(
                'INSERT INTO files (daily_record_id, file_path, file_type) VALUES ($1, $2, $3) RETURNING *',
                [dailyRecordId, '/uploads/photos/' + file.filename, file.mimetype]
            );
            uploadedFiles.push(result.rows[0]);
        }

        res.status(201).json({ files: uploadedFiles });
    } catch (error) {
        console.error('Error uploading photos:', error);
        res.status(500).json({ error: 'Failed to upload photos' });
    }
});

// Get photos for a daily record
app.get('/api/daily-records/:id/photos', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM files WHERE daily_record_id = $1 ORDER BY created_at DESC',
            [req.params.id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching photos:', error);
        res.status(500).json({ error: 'Failed to fetch photos' });
    }
});

// Delete a photo
app.delete('/api/photos/:id', async (req, res) => {
    try {
        // Get file path first
        const fileResult = await pool.query('SELECT file_path FROM files WHERE id = $1', [req.params.id]);
        if (fileResult.rows.length === 0) {
            return res.status(404).json({ error: 'Photo not found' });
        }

        const filePath = '.' + fileResult.rows[0].file_path;
        
        // Delete from database
        await pool.query('DELETE FROM files WHERE id = $1', [req.params.id]);
        
        // Try to delete file from disk (don't fail if file doesn't exist)
        try {
            await fs.unlink(filePath);
        } catch (e) {
            console.log('File not found on disk, continuing...');
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting photo:', error);
        res.status(500).json({ error: 'Failed to delete photo' });
    }
});

// ========== CONCRETE DELIVERIES ROUTES ==========

// Get all concrete deliveries
app.get('/api/concrete-deliveries', async (req, res) => {
    try {
        const { status, job_id } = req.query;
        let query = `
            SELECT cd.*, cs.name as supplier_name, j.job_name, j.job_number 
            FROM concrete_deliveries cd 
            LEFT JOIN concrete_suppliers cs ON cd.supplier_id = cs.id 
            LEFT JOIN jobs j ON cd.job_id = j.id
        `;
        const params = [];

        if (status || job_id) {
            query += ' WHERE';
            if (status) {
                params.push(status);
                query += ` cd.status = $${params.length}`;
            }
            if (job_id) {
                if (status) query += ' AND';
                params.push(job_id);
                query += ` cd.job_id = $${params.length}`;
            }
        }

        query += ' ORDER BY cd.delivery_date DESC';

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching concrete deliveries:', error);
        res.status(500).json({ error: 'Failed to fetch concrete deliveries' });
    }
});

// Upload and parse concrete invoice
app.post('/api/concrete-deliveries/upload', authenticateToken, upload.single('invoice'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Read and parse PDF
        const dataBuffer = await fs.readFile(req.file.path);
        const pdfData = await pdfParse(dataBuffer);
        const text = pdfData.text;

        // Extract data from PDF (this is a basic parser - you'll refine based on actual invoice format)
        const invoiceData = {
            invoice_number: extractInvoiceNumber(text),
            delivery_date: extractDeliveryDate(text),
            cubic_yards: extractCubicYards(text),
            total_cost: extractTotalCost(text),
            job_info: extractJobInfo(text),
            invoice_pdf_path: req.file.path
        };

        // Try to match to existing job
        let matchedJobId = null;
        if (invoiceData.job_info) {
            const jobResult = await pool.query(
                'SELECT id FROM jobs WHERE job_name ILIKE $1 OR job_number ILIKE $2 OR location ILIKE $3 LIMIT 1',
                [`%${invoiceData.job_info}%`, `%${invoiceData.job_info}%`, `%${invoiceData.job_info}%`]
            );
            if (jobResult.rows.length > 0) {
                matchedJobId = jobResult.rows[0].id;
            }
        }

        res.json({
            parsed_data: invoiceData,
            matched_job_id: matchedJobId,
            file_path: req.file.path
        });
    } catch (error) {
        console.error('Error parsing invoice:', error);
        res.status(500).json({ error: 'Failed to parse invoice' });
    }
});

// Create concrete delivery
app.post('/api/concrete-deliveries', async (req, res) => {
    try {
        const {
            invoice_number,
            supplier_id,
            job_id,
            delivery_date,
            cubic_yards,
            cost_per_yard,
            total_cost,
            invoice_pdf_path,
            notes
        } = req.body;

        const result = await pool.query(
            `INSERT INTO concrete_deliveries 
            (invoice_number, supplier_id, job_id, delivery_date, cubic_yards, cost_per_yard, total_cost, invoice_pdf_path, status, matched_by_user_id, matched_at, notes) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP, $11) 
            RETURNING *`,
            [invoice_number, supplier_id, job_id, delivery_date, cubic_yards, cost_per_yard, total_cost, invoice_pdf_path, job_id ? 'matched' : 'unmatched', req.user.id, notes]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error creating concrete delivery:', error);
        res.status(500).json({ error: 'Failed to create concrete delivery' });
    }
});

// ========== HELPER FUNCTIONS FOR PDF PARSING ==========

function extractInvoiceNumber(text) {
    const match = text.match(/Invoice\s*(?:No|Number|#)?:?\s*(\d+)/i);
    return match ? match[1] : null;
}

function extractDeliveryDate(text) {
    const match = text.match(/(?:Inv\s*Date|Date|Delivered):\s*(\d{1,2}\/\d{1,2}\/\d{2,4})/i);
    return match ? match[1] : null;
}

function extractCubicYards(text) {
    const match = text.match(/(\d+\.?\d*)\s*(?:CY|Cubic\s*Yards?|cy)/i);
    return match ? parseFloat(match[1]) : null;
}

function extractTotalCost(text) {
    const match = text.match(/(?:Total|Amount\s*Due)[\s:$]*(\d+\.?\d*)/i);
    return match ? parseFloat(match[1]) : null;
}

function extractJobInfo(text) {
    // Look for address or job number
    const addressMatch = text.match(/(?:Delivered\s*To|Job|Address):\s*([^\n]+)/i);
    return addressMatch ? addressMatch[1].trim() : null;
}

// ========== QB IMPORT ROUTES ==========

const XLSX = require('xlsx');

// QB Import upload configuration
const qbStorage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = './uploads/qb-imports';
        try {
            await fs.mkdir(uploadDir, { recursive: true });
            cb(null, uploadDir);
        } catch (error) {
            cb(error, null);
        }
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + file.originalname;
        cb(null, uniqueName);
    }
});

const qbUpload = multer({
    storage: qbStorage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = /csv|xlsx|xls|pdf/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        if (extname) {
            return cb(null, true);
        }
        cb(new Error('Only CSV, Excel, and PDF files are allowed'));
    }
});

// Parse QB PDF (proposals/estimates)
app.post('/api/qb-import/parse-pdf', (req, res, next) => {
    qbUpload.single('file')(req, res, (err) => {
        if (err) {
            return res.status(400).json({ error: err.message || 'File upload failed' });
        }
        next();
    });
}, async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const filePath = req.file.path;
        const ext = path.extname(req.file.originalname).toLowerCase();

        if (ext !== '.pdf') {
            return res.status(400).json({ error: 'File must be a PDF' });
        }

        // Read and parse PDF
        const dataBuffer = await fs.readFile(filePath);
        const pdfData = await pdfParse(dataBuffer);
        const text = pdfData.text;

        // Extract header info
        const headerInfo = extractQBHeaderInfo(text);

        // Extract line items table
        const lineItems = extractQBLineItems(text);

        // Get existing jobs for matching
        const existingJobs = await pool.query('SELECT id, job_number, job_name FROM jobs');

        // Try to match job
        let matchedJob = null;
        if (headerInfo.job_name || headerInfo.customer) {
            const searchTerm = headerInfo.job_name || headerInfo.customer;
            const jobMatch = existingJobs.rows.find(j =>
                j.job_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                searchTerm.toLowerCase().includes(j.job_name.toLowerCase()) ||
                j.job_number === searchTerm
            );
            if (jobMatch) {
                matchedJob = jobMatch;
            }
        }

        res.json({
            file_name: req.file.originalname,
            file_path: filePath,
            header: headerInfo,
            line_items: lineItems,
            matched_job: matchedJob,
            existing_jobs: existingJobs.rows,
            raw_text: text.substring(0, 2000) // First 2000 chars for debugging
        });
    } catch (error) {
        console.error('QB PDF parse error:', error);
        res.status(500).json({ error: 'Failed to parse PDF: ' + error.message });
    }
});

// Helper function to extract header info from QB proposal/estimate
function extractQBHeaderInfo(text) {
    const info = {
        proposal_number: null,
        estimate_number: null,
        invoice_number: null,
        date: null,
        customer: null,
        job_name: null,
        job_address: null,
        total: null
    };

    // Proposal/Estimate/Invoice number patterns
    const proposalMatch = text.match(/Proposal\s*#?\s*:?\s*(\d+)/i) ||
                          text.match(/Proposal\s+(\d+)/i);
    if (proposalMatch) info.proposal_number = proposalMatch[1];

    const estimateMatch = text.match(/Estimate\s*#?\s*:?\s*(\d+)/i) ||
                          text.match(/Estimate\s+(\d+)/i);
    if (estimateMatch) info.estimate_number = estimateMatch[1];

    const invoiceMatch = text.match(/Invoice\s*#?\s*:?\s*(\d+)/i);
    if (invoiceMatch) info.invoice_number = invoiceMatch[1];

    // Date patterns
    const dateMatch = text.match(/Date[:\s]+(\d{1,2}\/\d{1,2}\/\d{2,4})/i) ||
                      text.match(/(\d{1,2}\/\d{1,2}\/\d{4})/);
    if (dateMatch) info.date = dateMatch[1];

    // Customer/Job name - look for common patterns
    const customerMatch = text.match(/(?:Bill To|Customer|Sold To)[:\s]*\n?([^\n]+)/i);
    if (customerMatch) info.customer = customerMatch[1].trim();

    // Job name/address patterns
    const jobMatch = text.match(/(?:Job|Project|Ship To|Service Address)[:\s]*\n?([^\n]+)/i);
    if (jobMatch) info.job_name = jobMatch[1].trim();

    // Look for address pattern after job/customer
    const addressMatch = text.match(/(?:Job|Project|Service Address|Ship To)[:\s]*\n?[^\n]*\n([^\n]+(?:Dr|St|Ave|Rd|Way|Blvd|Lane|Ln|Circle|Cir|Court|Ct)[^\n]*)/i);
    if (addressMatch) info.job_address = addressMatch[1].trim();

    // Total amount
    const totalMatch = text.match(/(?:Total|Grand Total|Amount Due)[:\s]*\$?([\d,]+\.?\d*)/i);
    if (totalMatch) info.total = parseFloat(totalMatch[1].replace(/,/g, ''));

    return info;
}

// Helper function to extract line items from QB proposal/estimate
function extractQBLineItems(text) {
    const items = [];
    const lines = text.split('\n');

    // Common QB line item patterns
    // Format 1: Product/Service | Description | Qty | Rate | Amount
    // Format 2: Item | Qty | Rate | Amount
    // Format 3: Description | Qty | Price | Total

    let inItemsSection = false;
    let headerFound = false;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        const lowerLine = line.toLowerCase();

        // Detect start of items section
        if (lowerLine.includes('product/service') ||
            lowerLine.includes('description') && (lowerLine.includes('qty') || lowerLine.includes('quantity')) ||
            lowerLine.includes('item') && lowerLine.includes('rate') ||
            lowerLine.includes('activity') && lowerLine.includes('qty')) {
            inItemsSection = true;
            headerFound = true;
            continue;
        }

        // Detect end of items section
        if (inItemsSection && (
            lowerLine.includes('subtotal') ||
            lowerLine.includes('total') && !lowerLine.includes('product') ||
            lowerLine.includes('thank you') ||
            lowerLine.includes('terms') ||
            lowerLine.includes('notes') ||
            line === ''
        )) {
            // Check if this is just an empty line, continue if so
            if (line === '' && i < lines.length - 1) continue;
            if (lowerLine.startsWith('total') || lowerLine.startsWith('subtotal')) {
                inItemsSection = false;
                continue;
            }
        }

        if (inItemsSection && line.length > 0) {
            // Try to parse line item
            const item = parseQBLineItem(line, lines, i);
            if (item) {
                items.push(item);
            }
        }
    }

    // If no items found with section detection, try pattern matching on all lines
    if (items.length === 0) {
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            // Look for lines with dollar amounts that might be line items
            const dollarMatch = line.match(/\$?([\d,]+\.\d{2})\s*$/);
            if (dollarMatch && line.length > 10) {
                const item = parseQBLineItem(line, lines, i);
                if (item && item.product) {
                    items.push(item);
                }
            }
        }
    }

    return items;
}

// Parse a single line item
function parseQBLineItem(line, allLines, lineIndex) {
    // Pattern 1: "Product   Description   Qty   Rate   Amount"
    // Pattern 2: "Description   Qty   Rate   Amount"
    // Pattern 3: Numbers separated by spaces/tabs at end of line

    const item = {
        product: '',
        description: '',
        qty: 0,
        rate: 0,
        total: 0
    };

    // Try to extract numbers from end of line
    // Look for pattern like: 1.00 150.00 150.00 or 1 $150.00 $150.00
    const numbersMatch = line.match(/(\d+(?:\.\d+)?)\s+\$?([\d,]+(?:\.\d{2})?)\s+\$?([\d,]+(?:\.\d{2})?)\s*$/);

    if (numbersMatch) {
        item.qty = parseFloat(numbersMatch[1]);
        item.rate = parseFloat(numbersMatch[2].replace(/,/g, ''));
        item.total = parseFloat(numbersMatch[3].replace(/,/g, ''));

        // Everything before the numbers is product/description
        const textPart = line.substring(0, line.indexOf(numbersMatch[0])).trim();

        // Split text into product and description (if tab or multiple spaces)
        const textParts = textPart.split(/\t+|\s{2,}/);
        if (textParts.length >= 2) {
            item.product = textParts[0].trim();
            item.description = textParts.slice(1).join(' ').trim();
        } else {
            item.product = textPart;
            item.description = '';
        }

        return item;
    }

    // Pattern 2: Just two numbers at end (qty and amount)
    const twoNumbersMatch = line.match(/(\d+(?:\.\d+)?)\s+\$?([\d,]+(?:\.\d{2})?)\s*$/);
    if (twoNumbersMatch) {
        item.qty = parseFloat(twoNumbersMatch[1]);
        item.total = parseFloat(twoNumbersMatch[2].replace(/,/g, ''));
        item.rate = item.qty > 0 ? item.total / item.qty : 0;

        const textPart = line.substring(0, line.indexOf(twoNumbersMatch[0])).trim();
        item.product = textPart;

        return item;
    }

    // Pattern 3: Single amount at end
    const singleAmountMatch = line.match(/^(.+?)\s+\$?([\d,]+\.\d{2})\s*$/);
    if (singleAmountMatch && singleAmountMatch[1].length > 3) {
        item.product = singleAmountMatch[1].trim();
        item.total = parseFloat(singleAmountMatch[2].replace(/,/g, ''));
        item.qty = 1;
        item.rate = item.total;

        return item;
    }

    return null;
}

// Import QB PDF - auto-create job, save takeoffs, set income
app.post('/api/qb-import/import-pdf', async (req, res) => {
    const client = await pool.connect();
    try {
        const { header, line_items, selected_job_id } = req.body;

        if (!line_items || !Array.isArray(line_items)) {
            return res.status(400).json({ error: 'line_items array required' });
        }

        await client.query('BEGIN');
        const results = {
            imported: 0,
            errors: [],
            job_created: false,
            job_matched: false,
            job_id: null,
            job_name: null,
            job_number: null,
            income_set: 0
        };

        const proposalNum = header?.proposal_number || header?.estimate_number || '';
        const jobName = header?.job_name || header?.customer || '';
        const proposalTotal = header?.total || 0;

        // Step 1: Find or create job
        let jobId = selected_job_id;

        if (!jobId && jobName) {
            // Try to find existing job by name
            const existingJob = await client.query(
                `SELECT id, job_number, job_name FROM jobs
                 WHERE LOWER(job_name) = LOWER($1)
                    OR LOWER(job_name) LIKE LOWER($2)
                    OR LOWER($1) LIKE '%' || LOWER(job_name) || '%'
                 LIMIT 1`,
                [jobName.trim(), jobName.trim() + '%']
            );

            if (existingJob.rows.length > 0) {
                jobId = existingJob.rows[0].id;
                results.job_matched = true;
                results.job_name = existingJob.rows[0].job_name;
                results.job_number = existingJob.rows[0].job_number;
            }
        }

        if (!jobId) {
            // Create new job
            const finalJobName = jobName || 'Proposal ' + (proposalNum || Date.now());
            const jobNumber = proposalNum ? 'P-' + proposalNum : 'QB-' + Date.now();
            const newJob = await client.query(
                `INSERT INTO jobs (job_number, job_name, location, status, income)
                 VALUES ($1, $2, $3, 'active', $4)
                 RETURNING id, job_number, job_name`,
                [jobNumber, finalJobName, header?.job_address || null, proposalTotal]
            );
            jobId = newJob.rows[0].id;
            results.job_created = true;
            results.job_name = newJob.rows[0].job_name;
            results.job_number = newJob.rows[0].job_number;
            results.income_set = proposalTotal;
        } else {
            // Update existing job income if proposal total is higher
            if (proposalTotal > 0) {
                await client.query(
                    'UPDATE jobs SET income = GREATEST(COALESCE(income, 0), $1) WHERE id = $2',
                    [proposalTotal, jobId]
                );
                results.income_set = proposalTotal;
            }
        }

        results.job_id = jobId;

        // Step 2: Import line items as takeoffs with prices
        for (const item of line_items) {
            try {
                if (!item.product || item.product.trim() === '') continue;

                // Find or create item in items table (exact match)
                let itemResult = await client.query(
                    'SELECT id FROM items WHERE LOWER(name) = LOWER($1)',
                    [item.product.trim()]
                );

                let itemId;
                if (itemResult.rows.length > 0) {
                    itemId = itemResult.rows[0].id;
                } else {
                    const newItem = await client.query(
                        'INSERT INTO items (name, unit_of_measure) VALUES ($1, $2) RETURNING id',
                        [item.product.trim(), 'EA']
                    );
                    itemId = newItem.rows[0].id;
                }

                // Build notes with description, rate, and proposal reference
                const noteParts = [];
                if (item.description) noteParts.push(item.description);
                if (item.rate) noteParts.push('Rate: $' + parseFloat(item.rate).toFixed(2));
                if (proposalNum) noteParts.push('Proposal #' + proposalNum);
                const notes = noteParts.join(' | ');

                // Insert or update takeoff - store total price in area_sqft field for now
                await client.query(
                    `INSERT INTO job_takeoffs (job_id, item_id, quantity, unit, area_sqft, notes, source)
                     VALUES ($1, $2, $3, 'EA', $4, $5, 'qb_proposal')
                     ON CONFLICT (job_id, item_id)
                     DO UPDATE SET
                        quantity = EXCLUDED.quantity,
                        area_sqft = EXCLUDED.area_sqft,
                        notes = EXCLUDED.notes,
                        source = 'qb_proposal',
                        updated_at = CURRENT_TIMESTAMP`,
                    [jobId, itemId, item.qty || 1, item.total || 0, notes]
                );
                results.imported++;
            } catch (e) {
                results.errors.push({ item: item.product, error: e.message });
            }
        }

        await client.query('COMMIT');
        res.json(results);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('QB PDF import error:', error);
        res.status(500).json({ error: 'Import failed: ' + error.message });
    } finally {
        client.release();
    }
});

// Preview QB import data (parse without saving)
app.post('/api/qb-import/preview', (req, res, next) => {
    qbUpload.single('file')(req, res, (err) => {
        if (err) {
            return res.status(400).json({ error: err.message || 'File upload failed' });
        }
        next();
    });
}, async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const filePath = req.file.path;
        const importType = req.body.type || 'auto'; // jobs, invoices, time, costs, auto

        // Parse the file
        const workbook = XLSX.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });

        if (data.length < 2) {
            return res.json({ error: 'File is empty or has no data rows', rows: [] });
        }

        const headers = data[0].map(h => String(h || '').toLowerCase().trim());
        const rows = data.slice(1).filter(row => row.some(cell => cell !== null && cell !== ''));

        // Auto-detect import type based on headers
        let detectedType = importType;
        if (importType === 'auto') {
            if (headers.some(h => h.includes('customer') || h.includes('job name') || h.includes('project'))) {
                detectedType = 'jobs';
            } else if (headers.some(h => h.includes('invoice') || h.includes('bill') || h.includes('vendor'))) {
                detectedType = 'costs';
            } else if (headers.some(h => h.includes('hours') || h.includes('time') || h.includes('employee'))) {
                detectedType = 'time';
            } else {
                detectedType = 'jobs';
            }
        }

        // Map columns based on type
        const mappedData = rows.map((row, idx) => {
            const obj = { _row: idx + 2 };
            headers.forEach((header, i) => {
                obj[header] = row[i];
            });
            return obj;
        });

        // Get existing jobs for matching
        const existingJobs = await pool.query('SELECT id, job_number, job_name FROM jobs');

        res.json({
            file_name: req.file.originalname,
            file_path: filePath,
            detected_type: detectedType,
            headers: headers,
            row_count: rows.length,
            preview: mappedData.slice(0, 10),
            all_data: mappedData,
            existing_jobs: existingJobs.rows
        });
    } catch (error) {
        console.error('QB Import preview error:', error);
        res.status(500).json({ error: 'Failed to parse file: ' + error.message });
    }
});

// Execute QB import
app.post('/api/qb-import/execute', async (req, res) => {
    const client = await pool.connect();
    try {
        const { type, mappings, data } = req.body;
        // mappings: { job_number: 'col_name', job_name: 'col_name', ... }
        // data: array of row objects

        await client.query('BEGIN');
        const results = { imported: 0, skipped: 0, errors: [] };

        if (type === 'jobs') {
            for (const row of data) {
                try {
                    const jobNumber = row[mappings.job_number] || '';
                    const jobName = row[mappings.job_name] || '';
                    const location = row[mappings.location] || '';
                    const contractor = row[mappings.contractor] || '';

                    if (!jobNumber && !jobName) {
                        results.skipped++;
                        continue;
                    }

                    // Check if job exists
                    const existing = await client.query(
                        'SELECT id FROM jobs WHERE job_number = $1 OR job_name = $2',
                        [jobNumber, jobName]
                    );

                    if (existing.rows.length > 0) {
                        // Update existing
                        await client.query(
                            'UPDATE jobs SET location = COALESCE($1, location), contractor_name = COALESCE($2, contractor_name) WHERE id = $3',
                            [location || null, contractor || null, existing.rows[0].id]
                        );
                    } else {
                        // Insert new
                        await client.query(
                            'INSERT INTO jobs (job_number, job_name, location, contractor_name, status) VALUES ($1, $2, $3, $4, $5)',
                            [jobNumber || 'QB-' + Date.now(), jobName, location || null, contractor || null, 'active']
                        );
                    }
                    results.imported++;
                } catch (e) {
                    results.errors.push({ row: row._row, error: e.message });
                }
            }
        } else if (type === 'costs') {
            for (const row of data) {
                try {
                    const invoiceNumber = row[mappings.invoice_number] || '';
                    const vendor = row[mappings.vendor] || '';
                    const date = row[mappings.date] || new Date().toISOString().split('T')[0];
                    const amount = parseFloat(row[mappings.amount]) || 0;
                    const description = row[mappings.description] || '';
                    const jobRef = row[mappings.job] || '';
                    const category = row[mappings.category] || 'materials';

                    if (!amount) {
                        results.skipped++;
                        continue;
                    }

                    // Try to match job
                    let jobId = null;
                    if (jobRef) {
                        const jobMatch = await client.query(
                            'SELECT id FROM jobs WHERE job_number ILIKE $1 OR job_name ILIKE $1 LIMIT 1',
                            ['%' + jobRef + '%']
                        );
                        if (jobMatch.rows.length > 0) {
                            jobId = jobMatch.rows[0].id;
                        }
                    }

                    // Insert into job_costs table
                    await client.query(
                        'INSERT INTO job_costs (job_id, invoice_number, vendor, cost_date, amount, description, category, source) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
                        [jobId, invoiceNumber, vendor, date, amount, description, category, 'qb_import']
                    );
                    results.imported++;
                } catch (e) {
                    results.errors.push({ row: row._row, error: e.message });
                }
            }
        } else if (type === 'time') {
            for (const row of data) {
                try {
                    const workerName = row[mappings.worker] || '';
                    const date = row[mappings.date] || new Date().toISOString().split('T')[0];
                    const hours = parseFloat(row[mappings.hours]) || 0;
                    const jobRef = row[mappings.job] || '';
                    const rate = parseFloat(row[mappings.rate]) || 0;

                    if (!hours || !workerName) {
                        results.skipped++;
                        continue;
                    }

                    // Find or create worker
                    let workerResult = await client.query('SELECT id FROM workers WHERE full_name ILIKE $1', ['%' + workerName + '%']);
                    let workerId;
                    if (workerResult.rows.length > 0) {
                        workerId = workerResult.rows[0].id;
                    } else {
                        const newWorker = await client.query(
                            'INSERT INTO workers (full_name, role, hire_date) VALUES ($1, $2, CURRENT_DATE) RETURNING id',
                            [workerName, 'Laborer']
                        );
                        workerId = newWorker.rows[0].id;
                    }

                    // Try to match job and find/create daily record
                    let jobId = null;
                    if (jobRef) {
                        const jobMatch = await client.query(
                            'SELECT id FROM jobs WHERE job_number ILIKE $1 OR job_name ILIKE $1 LIMIT 1',
                            ['%' + jobRef + '%']
                        );
                        if (jobMatch.rows.length > 0) {
                            jobId = jobMatch.rows[0].id;
                        }
                    }

                    if (jobId) {
                        // Find or create daily record
                        let recordResult = await client.query(
                            'SELECT id FROM daily_records WHERE job_id = $1 AND record_date = $2',
                            [jobId, date]
                        );
                        let recordId;
                        if (recordResult.rows.length > 0) {
                            recordId = recordResult.rows[0].id;
                        } else {
                            const newRecord = await client.query(
                                'INSERT INTO daily_records (job_id, record_date, notes) VALUES ($1, $2, $3) RETURNING id',
                                [jobId, date, 'Created from QB Import']
                            );
                            recordId = newRecord.rows[0].id;
                        }

                        // Add worker hours
                        await client.query(
                            'INSERT INTO worker_hours (daily_record_id, worker_id, hours_worked, labor_rate) VALUES ($1, $2, $3, $4)',
                            [recordId, workerId, hours, rate || 25]
                        );
                    }
                    results.imported++;
                } catch (e) {
                    results.errors.push({ row: row._row, error: e.message });
                }
            }
        }

        await client.query('COMMIT');
        res.json(results);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('QB Import execute error:', error);
        res.status(500).json({ error: 'Import failed: ' + error.message });
    } finally {
        client.release();
    }
});

// ========== STACK INTEGRATION ROUTES ==========

// STACK API Configuration
const STACK_API_BASE = 'https://go.stackct.com/api/v2';
const STACK_AUTH_URL = 'https://go.stackct.com/OAuth/Token';

// Helper: Get valid STACK access token
async function getStackAccessToken() {
    try {
        const tokenResult = await pool.query('SELECT * FROM stack_tokens ORDER BY updated_at DESC LIMIT 1');
        if (tokenResult.rows.length === 0) {
            return null;
        }

        const tokenData = tokenResult.rows[0];
        const now = new Date();
        const expiresAt = new Date(tokenData.expires_at);

        // If token expires in less than 5 minutes, refresh it
        if (expiresAt.getTime() - now.getTime() < 5 * 60 * 1000) {
            return await refreshStackToken(tokenData);
        }

        return tokenData.access_token;
    } catch (e) {
        console.error('Error getting STACK token:', e);
        return null;
    }
}

// Helper: Refresh STACK token
async function refreshStackToken(tokenData) {
    try {
        const credentials = Buffer.from(`${tokenData.client_id}:${tokenData.client_secret}`).toString('base64');

        const response = await axios.post(STACK_AUTH_URL,
            `grant_type=refresh_token&refresh_token=${tokenData.refresh_token}`,
            {
                headers: {
                    'Authorization': `Basic ${credentials}`,
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const expiresAt = new Date(Date.now() + (response.data.expires_in * 1000));

        await pool.query(
            `UPDATE stack_tokens SET
                access_token = $1,
                refresh_token = $2,
                expires_at = $3,
                updated_at = CURRENT_TIMESTAMP
             WHERE id = $4`,
            [response.data.access_token, response.data.refresh_token, expiresAt, tokenData.id]
        );

        return response.data.access_token;
    } catch (e) {
        console.error('Failed to refresh STACK token:', e);
        return null;
    }
}

// STACK connection status
app.get('/api/stack/status', async (req, res) => {
    try {
        const tokenResult = await pool.query('SELECT client_id, expires_at, updated_at FROM stack_tokens ORDER BY updated_at DESC LIMIT 1');

        if (tokenResult.rows.length === 0) {
            return res.json({ connected: false });
        }

        const tokenData = tokenResult.rows[0];
        const isExpired = new Date(tokenData.expires_at) < new Date();

        res.json({
            connected: !isExpired,
            client_id: tokenData.client_id,
            expires_at: tokenData.expires_at,
            last_updated: tokenData.updated_at
        });
    } catch (e) {
        res.json({ connected: false, error: e.message });
    }
});

// Connect to STACK (save credentials and get initial token)
app.post('/api/stack/connect', async (req, res) => {
    try {
        const { client_id, client_secret } = req.body;

        if (!client_id || !client_secret) {
            return res.status(400).json({ error: 'client_id and client_secret required' });
        }

        // Get access token from STACK
        const credentials = Buffer.from(`${client_id}:${client_secret}`).toString('base64');

        const response = await axios.post(STACK_AUTH_URL,
            'grant_type=client_credentials',
            {
                headers: {
                    'Authorization': `Basic ${credentials}`,
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const expiresAt = new Date(Date.now() + (response.data.expires_in * 1000));

        // Create table if not exists
        await pool.query(`
            CREATE TABLE IF NOT EXISTS stack_tokens (
                id SERIAL PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL,
                client_secret VARCHAR(255) NOT NULL,
                access_token TEXT NOT NULL,
                refresh_token TEXT,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Clear existing tokens and save new one
        await pool.query('DELETE FROM stack_tokens');
        await pool.query(
            `INSERT INTO stack_tokens (client_id, client_secret, access_token, refresh_token, expires_at)
             VALUES ($1, $2, $3, $4, $5)`,
            [client_id, client_secret, response.data.access_token, response.data.refresh_token || '', expiresAt]
        );

        res.json({ success: true, message: 'Connected to STACK successfully' });
    } catch (error) {
        console.error('STACK connect error:', error.response?.data || error.message);
        res.status(400).json({
            error: error.response?.data?.error_description || error.message || 'Failed to connect to STACK'
        });
    }
});

// Disconnect from STACK
app.post('/api/stack/disconnect', async (req, res) => {
    try {
        await pool.query('DELETE FROM stack_tokens');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get projects from STACK
app.get('/api/stack/projects', async (req, res) => {
    try {
        const accessToken = await getStackAccessToken();
        if (!accessToken) {
            return res.status(401).json({ error: 'Not connected to STACK. Please configure your API credentials.' });
        }

        const response = await axios.get(`${STACK_API_BASE}/Projects`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            },
            params: {
                pageSize: 50,
                sortBy: 'ModifiedDate',
                sortDirection: 'desc'
            }
        });

        const projects = response.data.data || response.data || [];

        res.json({
            projects: projects.map(p => ({
                id: p.id || p.Id,
                name: p.name || p.Name,
                bid_date: p.bidDate || p.BidDate,
                created_date: p.createdDate || p.CreatedDate,
                modified_date: p.modifiedDate || p.ModifiedDate,
                status: p.status || p.Status
            }))
        });
    } catch (error) {
        console.error('STACK projects error:', error.response?.data || error.message);
        res.status(500).json({
            error: error.response?.data?.message || 'Failed to fetch projects from STACK'
        });
    }
});

// Get takeoffs for a STACK project
app.get('/api/stack/projects/:projectId/takeoffs', async (req, res) => {
    try {
        const accessToken = await getStackAccessToken();
        if (!accessToken) {
            return res.status(401).json({ error: 'Not connected to STACK' });
        }

        const response = await axios.get(`${STACK_API_BASE}/Projects/${req.params.projectId}/Takeoffs`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        });

        const takeoffs = response.data.data || response.data || [];

        res.json({
            takeoffs: takeoffs.map(t => ({
                id: t.id || t.Id,
                name: t.name || t.Name,
                description: t.description || t.Description,
                type: t.type || t.Type,
                created_date: t.createdDate || t.CreatedDate,
                modified_date: t.modifiedDate || t.ModifiedDate
            }))
        });
    } catch (error) {
        console.error('STACK takeoffs error:', error.response?.data || error.message);
        res.status(500).json({ error: 'Failed to fetch takeoffs from STACK' });
    }
});

// Get estimates for a STACK takeoff
app.get('/api/stack/takeoffs/:takeoffId/estimates', async (req, res) => {
    try {
        const accessToken = await getStackAccessToken();
        if (!accessToken) {
            return res.status(401).json({ error: 'Not connected to STACK' });
        }

        const response = await axios.get(`${STACK_API_BASE}/Takeoffs/${req.params.takeoffId}/Estimates`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        });

        const estimates = response.data.data || response.data || [];

        res.json({
            estimates: estimates.map(e => ({
                id: e.id || e.Id,
                name: e.name || e.Name || e.itemName || e.ItemName,
                description: e.description || e.Description,
                quantity: e.quantity || e.Quantity || e.takeoffQuantity || 0,
                unit: e.unit || e.Unit || e.unitOfMeasure || 'EA',
                unit_cost: e.unitCost || e.UnitCost || 0,
                total_cost: e.totalCost || e.TotalCost || 0,
                area: e.area || e.Area || 0,
                length: e.length || e.Length || e.perimeter || 0,
                item_type: e.itemType || e.ItemType || 'material'
            }))
        });
    } catch (error) {
        console.error('STACK estimates error:', error.response?.data || error.message);
        res.status(500).json({ error: 'Failed to fetch estimates from STACK' });
    }
});

// Import STACK estimates to a job
app.post('/api/stack/import-to-job', async (req, res) => {
    const client = await pool.connect();
    try {
        const { job_id, project_id, takeoff_id, estimates } = req.body;

        if (!job_id || !estimates || !Array.isArray(estimates)) {
            return res.status(400).json({ error: 'job_id and estimates array required' });
        }

        await client.query('BEGIN');

        const results = { imported: 0, errors: [] };

        for (const est of estimates) {
            try {
                // Check if item exists
                let itemResult = await client.query(
                    'SELECT id FROM items WHERE name ILIKE $1',
                    ['%' + est.name + '%']
                );

                let itemId;
                if (itemResult.rows.length > 0) {
                    itemId = itemResult.rows[0].id;
                } else {
                    // Create new item with price from STACK
                    const newItem = await client.query(
                        'INSERT INTO items (name, unit_of_measure, price) VALUES ($1, $2, $3) RETURNING id',
                        [est.name, est.unit || 'EA', est.unit_cost || 0]
                    );
                    itemId = newItem.rows[0].id;
                }

                // Store takeoff data
                await client.query(
                    `INSERT INTO job_takeoffs (job_id, item_id, quantity, unit, area_sqft, linear_ft, notes, source)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, 'stack')
                     ON CONFLICT (job_id, item_id)
                     DO UPDATE SET quantity = $3, area_sqft = $5, linear_ft = $6, notes = $7, source = 'stack', updated_at = CURRENT_TIMESTAMP`,
                    [
                        job_id,
                        itemId,
                        est.quantity || 0,
                        est.unit || 'EA',
                        est.area || 0,
                        est.length || 0,
                        `STACK: ${est.description || est.name} | Cost: $${est.total_cost || 0}`
                    ]
                );
                results.imported++;
            } catch (e) {
                results.errors.push({ item: est.name, error: e.message });
            }
        }

        // Log the import
        await client.query(
            `INSERT INTO stack_import_log (job_id, project_id, takeoff_id, items_imported, created_at)
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
             ON CONFLICT DO NOTHING`,
            [job_id, project_id || null, takeoff_id || null, results.imported]
        ).catch(() => {
            // Table might not exist, create it
            return client.query(`
                CREATE TABLE IF NOT EXISTS stack_import_log (
                    id SERIAL PRIMARY KEY,
                    job_id INTEGER REFERENCES jobs(id),
                    project_id VARCHAR(255),
                    takeoff_id VARCHAR(255),
                    items_imported INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
        });

        await client.query('COMMIT');
        res.json(results);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('STACK import error:', error);
        res.status(500).json({ error: 'Import failed: ' + error.message });
    } finally {
        client.release();
    }
});

// Import STACK takeoff data
app.post('/api/stack/import', async (req, res) => {
    const client = await pool.connect();
    try {
        const { job_id, takeoff_data } = req.body;
        // takeoff_data: array of { item_name, quantity, unit, area_sqft, linear_ft, notes }

        if (!job_id || !takeoff_data || !Array.isArray(takeoff_data)) {
            return res.status(400).json({ error: 'job_id and takeoff_data array required' });
        }

        await client.query('BEGIN');

        const results = { imported: 0, errors: [] };

        for (const item of takeoff_data) {
            try {
                // Check if item exists
                let itemResult = await client.query(
                    'SELECT id FROM items WHERE name ILIKE $1',
                    ['%' + item.item_name + '%']
                );

                let itemId;
                if (itemResult.rows.length > 0) {
                    itemId = itemResult.rows[0].id;
                } else {
                    // Create new item
                    const newItem = await client.query(
                        'INSERT INTO items (name, unit_of_measure) VALUES ($1, $2) RETURNING id',
                        [item.item_name, item.unit || 'EA']
                    );
                    itemId = newItem.rows[0].id;
                }

                // Store takeoff data in job_takeoffs table
                await client.query(
                    `INSERT INTO job_takeoffs (job_id, item_id, quantity, unit, area_sqft, linear_ft, notes, source)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, 'stack')
                     ON CONFLICT (job_id, item_id)
                     DO UPDATE SET quantity = $3, area_sqft = $5, linear_ft = $6, notes = $7, updated_at = CURRENT_TIMESTAMP`,
                    [job_id, itemId, item.quantity || 0, item.unit || 'EA', item.area_sqft || 0, item.linear_ft || 0, item.notes || '']
                );
                results.imported++;
            } catch (e) {
                results.errors.push({ item: item.item_name, error: e.message });
            }
        }

        await client.query('COMMIT');
        res.json(results);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('STACK import error:', error);
        res.status(500).json({ error: 'Import failed: ' + error.message });
    } finally {
        client.release();
    }
});

// Get takeoffs for a job (with progress)
app.get('/api/jobs/:id/takeoffs', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT jt.*,
                    COALESCE(i.name, jt.source) as item_name,
                    i.price,
                    COALESCE(jt.unit, i.unit_of_measure, 'EA') as unit,
                    COALESCE(jt.quantity_completed, 0) as quantity_completed,
                    COALESCE(jt.status, 'pending') as status,
                    CASE WHEN jt.quantity > 0 THEN ROUND((COALESCE(jt.quantity_completed, 0) / jt.quantity) * 100, 1) ELSE 0 END as percent_complete
             FROM job_takeoffs jt
             LEFT JOIN items i ON jt.item_id = i.id
             WHERE jt.job_id = $1
             ORDER BY COALESCE(i.name, jt.source)`,
            [req.params.id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching takeoffs:', error);
        res.status(500).json({ error: 'Failed to fetch takeoffs' });
    }
});

// Update takeoff progress
app.put('/api/jobs/:jobId/takeoffs/:takeoffId', async (req, res) => {
    try {
        const { quantity_completed, status } = req.body;
        const result = await pool.query(
            `UPDATE job_takeoffs
             SET quantity_completed = COALESCE($1, quantity_completed),
                 status = COALESCE($2, status),
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $3 AND job_id = $4
             RETURNING *`,
            [quantity_completed, status, req.params.takeoffId, req.params.jobId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Takeoff not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating takeoff:', error);
        res.status(500).json({ error: 'Failed to update takeoff' });
    }
});

// ========== PRODUCTION LOGS ==========

// Get production logs for a job
app.get('/api/jobs/:id/production-logs', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT pl.*, jt.quantity as takeoff_quantity, jt.unit, i.name as item_name
             FROM production_logs pl
             LEFT JOIN job_takeoffs jt ON pl.takeoff_id = jt.id
             LEFT JOIN items i ON jt.item_id = i.id
             WHERE pl.job_id = $1
             ORDER BY pl.log_date DESC, pl.created_at DESC`,
            [req.params.id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching production logs:', error);
        res.status(500).json({ error: 'Failed to fetch production logs' });
    }
});

// Log production against a takeoff item
app.post('/api/jobs/:id/production-logs', async (req, res) => {
    const client = await pool.connect();
    try {
        const { takeoff_id, quantity_done, log_date, notes } = req.body;
        const job_id = req.params.id;

        if (!takeoff_id || !quantity_done) {
            return res.status(400).json({ error: 'takeoff_id and quantity_done are required' });
        }

        await client.query('BEGIN');

        // Insert production log
        const logResult = await client.query(
            `INSERT INTO production_logs (job_id, takeoff_id, quantity_done, log_date, notes)
             VALUES ($1, $2, $3, COALESCE($4, CURRENT_DATE), $5)
             RETURNING *`,
            [job_id, takeoff_id, quantity_done, log_date, notes]
        );

        // Update takeoff's quantity_completed
        await client.query(
            `UPDATE job_takeoffs
             SET quantity_completed = COALESCE(quantity_completed, 0) + $1,
                 status = CASE
                     WHEN COALESCE(quantity_completed, 0) + $1 >= quantity THEN 'complete'
                     WHEN COALESCE(quantity_completed, 0) + $1 > 0 THEN 'in_progress'
                     ELSE 'pending'
                 END,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $2`,
            [quantity_done, takeoff_id]
        );

        await client.query('COMMIT');

        res.json(logResult.rows[0]);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error logging production:', error);
        res.status(500).json({ error: 'Failed to log production' });
    } finally {
        client.release();
    }
});

// Get comparison (estimated vs actual) for a job
app.get('/api/jobs/:id/comparison', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT jt.id,
                    COALESCE(i.name, jt.source) as item_name,
                    jt.quantity,
                    COALESCE(jt.quantity_completed, 0) as quantity_completed,
                    jt.unit,
                    jt.status
             FROM job_takeoffs jt
             LEFT JOIN items i ON jt.item_id = i.id
             WHERE jt.job_id = $1
             ORDER BY COALESCE(i.name, jt.source)`,
            [req.params.id]
        );

        // Calculate summary
        let totalEstimated = 0;
        let totalCompleted = 0;
        result.rows.forEach(row => {
            totalEstimated += parseFloat(row.quantity) || 0;
            totalCompleted += parseFloat(row.quantity_completed) || 0;
        });

        const summary = {
            total_items: result.rows.length,
            total_estimated: totalEstimated,
            total_completed: totalCompleted,
            complete: result.rows.filter(r => r.status === 'complete').length,
            in_progress: result.rows.filter(r => r.status === 'in_progress').length,
            pending: result.rows.filter(r => r.status === 'pending').length
        };

        res.json({ items: result.rows, summary });
    } catch (error) {
        console.error('Error fetching comparison:', error);
        res.status(500).json({ error: 'Failed to fetch comparison' });
    }
});

// ========== JOB PLANS (PDF) ==========

// Configure PDF upload storage
const planStorage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = './uploads/plans';
        try {
            await fs.mkdir(uploadDir, { recursive: true });
            cb(null, uploadDir);
        } catch (error) {
            cb(error, null);
        }
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const planUpload = multer({
    storage: planStorage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit for PDFs
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') {
            return cb(null, true);
        }
        cb(new Error('Only PDF files are allowed'));
    }
});

// Get plans for a job
// Get production summary for a job (from daily records)
app.get('/api/jobs/:id/production-summary', async (req, res) => {
    try {
        // Get production from daily_record_production
        const productionResult = await pool.query(
            `SELECT item_name, unit, SUM(quantity) as total_completed
             FROM daily_record_production
             WHERE job_id = $1
             GROUP BY item_name, unit
             ORDER BY item_name`,
            [req.params.id]
        );

        // Get total yards poured from daily records
        const yardsResult = await pool.query(
            `SELECT COALESCE(SUM(yards_poured), 0) as total_yards
             FROM daily_records
             WHERE job_id = $1`,
            [req.params.id]
        );

        // Get takeoffs with progress for comparison
        const takeoffsResult = await pool.query(
            `SELECT jt.id, COALESCE(i.name, jt.source) as item_name,
                    jt.quantity as estimated, jt.unit,
                    COALESCE(jt.quantity_completed, 0) as completed,
                    jt.status
             FROM job_takeoffs jt
             LEFT JOIN items i ON jt.item_id = i.id
             WHERE jt.job_id = $1
             ORDER BY COALESCE(i.name, jt.source)`,
            [req.params.id]
        );

        res.json({
            production: productionResult.rows,
            total_yards: parseFloat(yardsResult.rows[0].total_yards) || 0,
            takeoffs: takeoffsResult.rows
        });
    } catch (error) {
        console.error('Error fetching production summary:', error);
        res.status(500).json({ error: 'Failed to fetch production summary' });
    }
});

app.get('/api/jobs/:id/plans', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM job_plans WHERE job_id = $1 ORDER BY created_at DESC`,
            [req.params.id]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching plans:', error);
        res.status(500).json({ error: 'Failed to fetch plans' });
    }
});

// Upload a plan
app.post('/api/jobs/:id/plans', planUpload.single('plan'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const result = await pool.query(
            `INSERT INTO job_plans (job_id, file_path, file_name)
             VALUES ($1, $2, $3)
             RETURNING *`,
            [req.params.id, '/uploads/plans/' + req.file.filename, req.file.originalname]
        );

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error uploading plan:', error);
        res.status(500).json({ error: 'Failed to upload plan' });
    }
});

// Delete a plan
app.delete('/api/jobs/:id/plans/:planId', async (req, res) => {
    try {
        // Get file path first
        const planResult = await pool.query(
            'SELECT file_path FROM job_plans WHERE id = $1 AND job_id = $2',
            [req.params.planId, req.params.id]
        );

        if (planResult.rows.length === 0) {
            return res.status(404).json({ error: 'Plan not found' });
        }

        // Delete from database
        await pool.query('DELETE FROM job_plans WHERE id = $1', [req.params.planId]);

        // Try to delete file
        try {
            const filePath = '.' + planResult.rows[0].file_path;
            await fs.unlink(filePath);
        } catch (e) {
            console.log('Could not delete file:', e.message);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting plan:', error);
        res.status(500).json({ error: 'Failed to delete plan' });
    }
});

// ========== PLAN ANNOTATIONS ==========

// Get annotations for a plan
app.get('/api/plans/:planId/annotations', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM plan_annotations WHERE plan_id = $1 ORDER BY page_number, created_at`,
            [req.params.planId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching annotations:', error);
        res.status(500).json({ error: 'Failed to fetch annotations' });
    }
});

// Save annotation
app.post('/api/plans/:planId/annotations', async (req, res) => {
    try {
        const { page_number, annotation_data } = req.body;

        const result = await pool.query(
            `INSERT INTO plan_annotations (plan_id, page_number, annotation_data)
             VALUES ($1, $2, $3)
             RETURNING *`,
            [req.params.planId, page_number || 1, JSON.stringify(annotation_data)]
        );

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error saving annotation:', error);
        res.status(500).json({ error: 'Failed to save annotation' });
    }
});

// Delete annotation
app.delete('/api/plans/:planId/annotations/:annotationId', async (req, res) => {
    try {
        await pool.query('DELETE FROM plan_annotations WHERE id = $1 AND plan_id = $2',
            [req.params.annotationId, req.params.planId]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting annotation:', error);
        res.status(500).json({ error: 'Failed to delete annotation' });
    }
});

// ========== ENHANCED JOB COSTING ROUTES ==========

// Get detailed job costing with all cost breakdowns
app.get('/api/job-costing-detail/:id', async (req, res) => {
    try {
        const jobId = req.params.id;
        const { from, to } = req.query;

        // Get job info
        const jobResult = await pool.query('SELECT * FROM jobs WHERE id = $1', [jobId]);
        if (jobResult.rows.length === 0) {
            return res.status(404).json({ error: 'Job not found' });
        }
        const job = jobResult.rows[0];

        // Build date filter conditions
        let concreteDateFilter = '';
        let laborDateFilter = '';
        let costsDateFilter = '';
        const concreteParams = [jobId];
        const laborParams = [jobId];
        const costsParams = [jobId];

        if (from) {
            concreteParams.push(from);
            concreteDateFilter += ` AND cd.delivery_date >= $${concreteParams.length}`;
            laborParams.push(from);
            laborDateFilter += ` AND dr.record_date >= $${laborParams.length}`;
            costsParams.push(from);
            costsDateFilter += ` AND cost_date >= $${costsParams.length}`;
        }
        if (to) {
            concreteParams.push(to);
            concreteDateFilter += ` AND cd.delivery_date <= $${concreteParams.length}`;
            laborParams.push(to);
            laborDateFilter += ` AND dr.record_date <= $${laborParams.length}`;
            costsParams.push(to);
            costsDateFilter += ` AND cost_date <= $${costsParams.length}`;
        }

        // Get concrete deliveries
        const concreteResult = await pool.query(
            `SELECT cd.*, cs.name as supplier_name
             FROM concrete_deliveries cd
             LEFT JOIN concrete_suppliers cs ON cd.supplier_id = cs.id
             WHERE cd.job_id = $1${concreteDateFilter}
             ORDER BY cd.delivery_date DESC`,
            concreteParams
        );

        // Get labor costs from worker_hours
        const laborResult = await pool.query(
            `SELECT wh.*, w.full_name as worker_name, dr.record_date
             FROM worker_hours wh
             JOIN daily_records dr ON wh.daily_record_id = dr.id
             JOIN workers w ON wh.worker_id = w.id
             WHERE dr.job_id = $1${laborDateFilter}
             ORDER BY dr.record_date DESC`,
            laborParams
        );

        // Get other costs
        const costsResult = await pool.query(
            `SELECT * FROM job_costs WHERE job_id = $1${costsDateFilter} ORDER BY cost_date DESC`,
            costsParams
        );

        // Get takeoffs (not date-filtered)
        const takeoffsResult = await pool.query(
            `SELECT jt.*, i.name as item_name
             FROM job_takeoffs jt
             JOIN items i ON jt.item_id = i.id
             WHERE jt.job_id = $1`,
            [jobId]
        );

        // Get invoices
        const invoicesResult = await pool.query(
            `SELECT * FROM job_invoices WHERE job_id = $1 ORDER BY invoice_date DESC`,
            [jobId]
        );

        // Get change orders (if table exists)
        let changeOrders = [];
        try {
            const coResult = await pool.query(
                `SELECT * FROM job_change_orders WHERE job_id = $1 ORDER BY co_date DESC`,
                [jobId]
            );
            changeOrders = coResult.rows;
        } catch (e) {
            // Table might not exist yet
        }

        // Get field data from daily records (yards poured in field)
        let dailyRecordsParams = [jobId];
        let dailyRecordsDateFilter = '';
        if (from) {
            dailyRecordsParams.push(from);
            dailyRecordsDateFilter += ` AND record_date >= $${dailyRecordsParams.length}`;
        }
        if (to) {
            dailyRecordsParams.push(to);
            dailyRecordsDateFilter += ` AND record_date <= $${dailyRecordsParams.length}`;
        }
        const dailyRecordsResult = await pool.query(
            `SELECT record_date, concrete_yards, notes
             FROM daily_records
             WHERE job_id = $1${dailyRecordsDateFilter}
             ORDER BY record_date DESC`,
            dailyRecordsParams
        );
        const fieldYardsPoured = dailyRecordsResult.rows.reduce((sum, dr) => sum + (parseFloat(dr.concrete_yards) || 0), 0);

        // Get QB sync log to identify QB-sourced data
        let qbSyncedInvoices = [];
        let qbSyncedBills = [];
        try {
            const tokens = await pool.query('SELECT realm_id FROM qb_tokens ORDER BY updated_at DESC LIMIT 1');
            if (tokens.rows.length > 0) {
                const realmId = tokens.rows[0].realm_id;
                const qbInvoicesResult = await pool.query(
                    `SELECT sl.qb_id, ji.amount, ji.invoice_number, ji.invoice_date
                     FROM qb_sync_log sl
                     JOIN job_invoices ji ON ji.qb_invoice_id = sl.qb_id
                     WHERE sl.local_id = $1 AND sl.entity_type = 'invoice' AND sl.realm_id = $2`,
                    [jobId, realmId]
                );
                qbSyncedInvoices = qbInvoicesResult.rows;

                const qbBillsResult = await pool.query(
                    `SELECT sl.qb_id, jc.amount, jc.vendor, jc.cost_date, jc.description
                     FROM qb_sync_log sl
                     JOIN job_costs jc ON jc.job_id = sl.local_id AND sl.entity_type IN ('bill', 'purchase')
                     WHERE sl.local_id = $1 AND sl.realm_id = $2`,
                    [jobId, realmId]
                );
                qbSyncedBills = qbBillsResult.rows;
            }
        } catch (e) {
            // QB not connected or tables don't exist
        }

        // Calculate totals
        const concreteCost = concreteResult.rows.reduce((sum, c) => sum + (parseFloat(c.total_cost) || 0), 0);
        const concreteYards = concreteResult.rows.reduce((sum, c) => sum + (parseFloat(c.cubic_yards) || 0), 0);
        const laborHours = laborResult.rows.reduce((sum, l) => sum + (parseFloat(l.hours_worked) || 0), 0);
        const laborCost = laborResult.rows.reduce((sum, l) => sum + ((parseFloat(l.hours_worked) || 0) * (parseFloat(l.labor_rate) || 25)), 0);
        const otherCosts = costsResult.rows.reduce((sum, c) => sum + (parseFloat(c.amount) || 0), 0);
        const totalCost = concreteCost + laborCost + otherCosts;
        const income = parseFloat(job.income) || 0;
        const invoicedAmount = invoicesResult.rows.reduce((sum, i) => sum + (parseFloat(i.amount) || 0), 0);
        const profit = income - totalCost;

        // Calculate QB totals
        const qbInvoicedTotal = qbSyncedInvoices.reduce((sum, i) => sum + (parseFloat(i.amount) || 0), 0);
        const qbBillsTotal = qbSyncedBills.reduce((sum, b) => sum + (parseFloat(b.amount) || 0), 0);

        // Build comparison object
        const comparison = {
            field: {
                yards_poured: fieldYardsPoured,
                labor_hours: laborHours,
                labor_cost: laborCost,
                daily_records_count: dailyRecordsResult.rows.length,
                concrete_deliveries_count: concreteResult.rows.length,
                concrete_cost: concreteCost
            },
            quickbooks: {
                invoiced_amount: qbInvoicedTotal,
                invoices_count: qbSyncedInvoices.length,
                bills_amount: qbBillsTotal,
                bills_count: qbSyncedBills.length,
                invoices: qbSyncedInvoices,
                bills: qbSyncedBills
            },
            discrepancies: {
                yards: {
                    field: fieldYardsPoured,
                    invoiced: concreteYards,
                    difference: fieldYardsPoured - concreteYards,
                    has_discrepancy: Math.abs(fieldYardsPoured - concreteYards) > 0.5
                },
                income: {
                    contract: income,
                    invoiced: qbInvoicedTotal,
                    difference: income - qbInvoicedTotal,
                    has_discrepancy: Math.abs(income - qbInvoicedTotal) > 1
                },
                costs: {
                    field_concrete: concreteCost,
                    qb_bills: qbBillsTotal,
                    difference: concreteCost - qbBillsTotal,
                    has_discrepancy: Math.abs(concreteCost - qbBillsTotal) > 1
                }
            },
            daily_records: dailyRecordsResult.rows
        };

        res.json({
            job: job,
            summary: {
                income: income,
                invoiced: invoicedAmount,
                concrete_yards: concreteYards,
                concrete_cost: concreteCost,
                labor_hours: laborHours,
                labor_cost: laborCost,
                other_costs: otherCosts,
                total_cost: totalCost,
                profit: profit,
                margin: income > 0 ? ((profit / income) * 100).toFixed(1) : 0
            },
            concrete: concreteResult.rows,
            labor: laborResult.rows,
            costs: costsResult.rows,
            takeoffs: takeoffsResult.rows,
            invoices: invoicesResult.rows,
            change_orders: changeOrders,
            comparison: comparison
        });
    } catch (error) {
        console.error('Error fetching job costing detail:', error);
        res.status(500).json({ error: 'Failed to fetch job costing detail' });
    }
});

// ========== QUICKBOOKS ONLINE INTEGRATION ==========

// Helper function to get QB API base URL
function getQBApiUrl(realmId) {
    const baseUrl = process.env.QB_ENVIRONMENT === 'production'
        ? 'https://quickbooks.api.intuit.com'
        : 'https://sandbox-quickbooks.api.intuit.com';
    return `${baseUrl}/v3/company/${realmId}`;
}

// Helper function to get valid tokens (refresh if needed)
async function getValidQBTokens() {
    const tokenResult = await pool.query('SELECT * FROM qb_tokens ORDER BY updated_at DESC LIMIT 1');
    if (tokenResult.rows.length === 0) {
        return null;
    }

    const tokenData = tokenResult.rows[0];
    const now = new Date();
    const expiresAt = new Date(tokenData.expires_at);

    // If token expires in less than 5 minutes, refresh it
    if (expiresAt.getTime() - now.getTime() < 5 * 60 * 1000) {
        try {
            qbOAuthClient.setToken({
                access_token: tokenData.access_token,
                refresh_token: tokenData.refresh_token,
                token_type: tokenData.token_type,
                expires_in: Math.floor((expiresAt.getTime() - now.getTime()) / 1000),
                x_refresh_token_expires_in: tokenData.refresh_token_expires_at
                    ? Math.floor((new Date(tokenData.refresh_token_expires_at).getTime() - now.getTime()) / 1000)
                    : 0,
                realmId: tokenData.realm_id
            });

            const refreshResponse = await qbOAuthClient.refresh();
            const newToken = refreshResponse.getJson();

            // Save refreshed tokens
            await pool.query(
                `UPDATE qb_tokens SET
                    access_token = $1,
                    refresh_token = $2,
                    expires_at = $3,
                    updated_at = CURRENT_TIMESTAMP
                WHERE realm_id = $4`,
                [
                    newToken.access_token,
                    newToken.refresh_token,
                    new Date(Date.now() + newToken.expires_in * 1000),
                    tokenData.realm_id
                ]
            );

            return {
                accessToken: newToken.access_token,
                realmId: tokenData.realm_id
            };
        } catch (error) {
            console.error('Token refresh failed:', error);
            // Delete invalid tokens
            await pool.query('DELETE FROM qb_tokens WHERE realm_id = $1', [tokenData.realm_id]);
            return null;
        }
    }

    return {
        accessToken: tokenData.access_token,
        realmId: tokenData.realm_id
    };
}

// Check QuickBooks connection status
app.get('/api/quickbooks/status', async (req, res) => {
    try {
        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.json({ connected: false });
        }

        // Try to get company info to verify connection
        const apiUrl = getQBApiUrl(tokens.realmId);
        const response = await axios.get(`${apiUrl}/companyinfo/${tokens.realmId}`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            }
        });

        const companyInfo = response.data.CompanyInfo;
        res.json({
            connected: true,
            companyName: companyInfo.CompanyName,
            realmId: tokens.realmId
        });
    } catch (error) {
        console.error('QB status check error:', error.response?.data || error.message);
        res.json({ connected: false, error: error.message });
    }
});

// Start OAuth flow - redirect to QuickBooks
app.get('/api/quickbooks/connect', (req, res) => {
    const authUri = qbOAuthClient.authorizeUri({
        scope: [OAuthClient.scopes.Accounting],
        state: 'foreman-qb-connect'
    });
    res.redirect(authUri);
});

// OAuth callback - receive tokens from QuickBooks
app.get('/api/quickbooks/callback', async (req, res) => {
    try {
        // Build full URL - intuit-oauth needs the complete callback URL
        const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
        console.log('QuickBooks callback received:', fullUrl);
        const authResponse = await qbOAuthClient.createToken(fullUrl);
        const token = authResponse.getJson();

        // Get realmId from query params (Intuit sends it there) or token
        const realmId = req.query.realmId || token.realmId;
        console.log('QuickBooks realmId:', realmId);

        if (!realmId) {
            throw new Error('No realmId received from QuickBooks');
        }
        const apiUrl = getQBApiUrl(realmId);
        let companyName = 'Unknown Company';

        try {
            const companyResponse = await axios.get(`${apiUrl}/companyinfo/${realmId}`, {
                headers: {
                    'Authorization': `Bearer ${token.access_token}`,
                    'Accept': 'application/json'
                }
            });
            companyName = companyResponse.data.CompanyInfo.CompanyName;
        } catch (e) {
            console.error('Failed to get company info:', e.message);
        }

        // Save tokens to database
        await pool.query(
            `INSERT INTO qb_tokens (realm_id, access_token, refresh_token, token_type, expires_at, refresh_token_expires_at, company_name)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (realm_id) DO UPDATE SET
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                token_type = EXCLUDED.token_type,
                expires_at = EXCLUDED.expires_at,
                refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
                company_name = EXCLUDED.company_name,
                updated_at = CURRENT_TIMESTAMP`,
            [
                realmId,
                token.access_token,
                token.refresh_token,
                token.token_type || 'Bearer',
                new Date(Date.now() + token.expires_in * 1000),
                new Date(Date.now() + token.x_refresh_token_expires_in * 1000),
                companyName
            ]
        );

        // Redirect to QB integration page with success
        res.redirect('/quickbooks.html?connected=true&company=' + encodeURIComponent(companyName));
    } catch (error) {
        console.error('OAuth callback error:', error.message);
        console.error('Full error details:', JSON.stringify(error.authResponse || error, null, 2));
        res.redirect('/quickbooks.html?error=' + encodeURIComponent(error.message));
    }
});

// Disconnect from QuickBooks
app.post('/api/quickbooks/disconnect', async (req, res) => {
    try {
        const tokens = await getValidQBTokens();
        if (tokens) {
            // Revoke tokens with QuickBooks
            try {
                await qbOAuthClient.revoke({ access_token: tokens.accessToken });
            } catch (e) {
                console.error('Token revocation failed:', e.message);
            }

            // Delete from database
            await pool.query('DELETE FROM qb_tokens WHERE realm_id = $1', [tokens.realmId]);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Disconnect error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get estimates/proposals from QuickBooks
app.get('/api/quickbooks/estimates', async (req, res) => {
    try {
        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.status(401).json({ error: 'Not connected to QuickBooks' });
        }

        const apiUrl = getQBApiUrl(tokens.realmId);

        // Query for estimates - simple query first
        const query = "SELECT * FROM Estimate MAXRESULTS 50";
        console.log('QuickBooks estimate query:', query);
        console.log('QuickBooks API URL:', `${apiUrl}/query`);

        const response = await axios.get(`${apiUrl}/query`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            },
            params: { query }
        });

        const estimates = response.data.QueryResponse?.Estimate || [];

        // Check which ones are already synced and get job info
        const syncedResult = await pool.query(
            `SELECT s.qb_id, s.local_id, j.job_number, j.job_name
             FROM qb_sync_log s
             LEFT JOIN jobs j ON s.local_id = j.id
             WHERE s.realm_id = $1 AND s.entity_type = $2`,
            [tokens.realmId, 'estimate']
        );
        const syncedMap = {};
        syncedResult.rows.forEach(r => {
            syncedMap[r.qb_id] = {
                job_id: r.local_id,
                job_number: r.job_number,
                job_name: r.job_name
            };
        });

        // Format estimates for frontend
        const formattedEstimates = estimates.map(est => {
            const lines = est.Line?.filter(l => l.DetailType === 'SalesItemLineDetail') || [];
            return {
                id: est.Id,
                doc_number: est.DocNumber,
                customer_name: est.CustomerRef?.name || 'Unknown',
                customer_id: est.CustomerRef?.value,
                txn_date: est.TxnDate,
                expiration_date: est.ExpirationDate,
                total: parseFloat(est.TotalAmt || 0),
                status: est.TxnStatus,
                line_count: lines.length,
                lines: lines.map(l => ({
                    description: l.Description,
                    item_name: l.SalesItemLineDetail?.ItemRef?.name,
                    qty: l.SalesItemLineDetail?.Qty || 0,
                    rate: l.SalesItemLineDetail?.UnitPrice || 0,
                    amount: l.Amount || 0
                })),
                is_synced: !!syncedMap[est.Id],
                synced_job_id: syncedMap[est.Id]?.job_id || null,
                synced_job_number: syncedMap[est.Id]?.job_number || null,
                synced_job_name: syncedMap[est.Id]?.job_name || null,
                last_updated: est.MetaData?.LastUpdatedTime
            };
        });

        res.json({
            estimates: formattedEstimates,
            total: formattedEstimates.length,
            realm_id: tokens.realmId
        });
    } catch (error) {
        console.error('Get estimates error:', error.response?.data || error.message);
        res.status(500).json({ error: error.response?.data?.Fault?.Error?.[0]?.Message || error.message });
    }
});

// Get invoices from QuickBooks
app.get('/api/quickbooks/invoices', async (req, res) => {
    try {
        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.status(401).json({ error: 'Not connected to QuickBooks' });
        }

        const apiUrl = getQBApiUrl(tokens.realmId);

        // Query for recent invoices
        const query = "SELECT * FROM Invoice ORDER BY MetaData.LastUpdatedTime DESC MAXRESULTS 50";

        const response = await axios.get(`${apiUrl}/query`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            },
            params: { query }
        });

        const invoices = response.data.QueryResponse?.Invoice || [];

        // Check which ones are already synced and get linked job info
        const syncedResult = await pool.query(
            `SELECT sl.qb_id, sl.local_id as job_id, j.job_number
             FROM qb_sync_log sl
             LEFT JOIN jobs j ON sl.local_id = j.id
             WHERE sl.realm_id = $1 AND sl.entity_type = $2`,
            [tokens.realmId, 'invoice']
        );
        const syncedMap = {};
        syncedResult.rows.forEach(r => {
            syncedMap[r.qb_id] = { job_id: r.job_id, job_number: r.job_number };
        });

        const formattedInvoices = invoices.map(inv => ({
            id: inv.Id,
            doc_number: inv.DocNumber,
            customer_name: inv.CustomerRef?.name || 'Unknown',
            txn_date: inv.TxnDate,
            due_date: inv.DueDate,
            total: parseFloat(inv.TotalAmt || 0),
            balance: parseFloat(inv.Balance || 0),
            is_synced: !!syncedMap[inv.Id],
            synced_job_id: syncedMap[inv.Id]?.job_id || null,
            synced_job_number: syncedMap[inv.Id]?.job_number || null,
            last_updated: inv.MetaData?.LastUpdatedTime
        }));

        res.json({
            invoices: formattedInvoices,
            total: formattedInvoices.length,
            realm_id: tokens.realmId
        });
    } catch (error) {
        console.error('Get invoices error:', error.response?.data || error.message);
        res.status(500).json({ error: error.response?.data?.Fault?.Error?.[0]?.Message || error.message });
    }
});

// Get bills/expenses from QuickBooks
app.get('/api/quickbooks/bills', async (req, res) => {
    try {
        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.status(401).json({ error: 'Not connected to QuickBooks' });
        }

        const apiUrl = getQBApiUrl(tokens.realmId);

        // Query for bills (vendor invoices)
        const billQuery = "SELECT * FROM Bill ORDER BY MetaData.LastUpdatedTime DESC MAXRESULTS 100";
        const billResponse = await axios.get(`${apiUrl}/query`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            },
            params: { query: billQuery }
        });

        const bills = billResponse.data.QueryResponse?.Bill || [];

        // Also get Purchase orders/expenses
        const purchaseQuery = "SELECT * FROM Purchase ORDER BY MetaData.LastUpdatedTime DESC MAXRESULTS 100";
        let purchases = [];
        try {
            const purchaseResponse = await axios.get(`${apiUrl}/query`, {
                headers: {
                    'Authorization': `Bearer ${tokens.accessToken}`,
                    'Accept': 'application/json'
                },
                params: { query: purchaseQuery }
            });
            purchases = purchaseResponse.data.QueryResponse?.Purchase || [];
        } catch (e) {
            console.log('No purchases found or error:', e.message);
        }

        // Check which ones are already synced and get linked job info
        const syncedResult = await pool.query(
            `SELECT sl.qb_id, sl.entity_type, sl.local_id as job_id, j.job_number
             FROM qb_sync_log sl
             LEFT JOIN jobs j ON sl.local_id = j.id
             WHERE sl.realm_id = $1 AND sl.entity_type IN ($2, $3)`,
            [tokens.realmId, 'bill', 'purchase']
        );
        const syncedMap = {};
        syncedResult.rows.forEach(r => {
            syncedMap[r.entity_type + '-' + r.qb_id] = { job_id: r.job_id, job_number: r.job_number };
        });

        // Check vendor names for concrete suppliers
        const concreteVendors = ['concrete', 'rock', 'parson', 'geneva', 'sunroc', 'staker'];

        const formattedBills = bills.map(bill => {
            const vendorName = bill.VendorRef?.name || 'Unknown Vendor';
            const isConcrete = concreteVendors.some(v => vendorName.toLowerCase().includes(v));
            const syncKey = 'bill-' + bill.Id;
            return {
                id: bill.Id,
                type: 'Bill',
                doc_number: bill.DocNumber,
                vendor_name: vendorName,
                vendor_id: bill.VendorRef?.value,
                txn_date: bill.TxnDate,
                due_date: bill.DueDate,
                total: parseFloat(bill.TotalAmt || 0),
                balance: parseFloat(bill.Balance || 0),
                memo: bill.PrivateNote,
                lines: (bill.Line || []).filter(l => l.DetailType === 'AccountBasedExpenseLineDetail' || l.DetailType === 'ItemBasedExpenseLineDetail').map(l => ({
                    description: l.Description,
                    amount: l.Amount,
                    account: l.AccountBasedExpenseLineDetail?.AccountRef?.name || l.ItemBasedExpenseLineDetail?.ItemRef?.name
                })),
                is_synced: !!syncedMap[syncKey],
                synced_job_id: syncedMap[syncKey]?.job_id || null,
                synced_job_number: syncedMap[syncKey]?.job_number || null,
                is_concrete: isConcrete,
                last_updated: bill.MetaData?.LastUpdatedTime
            };
        });

        const formattedPurchases = purchases.map(p => {
            const vendorName = p.EntityRef?.name || 'Unknown';
            const isConcrete = concreteVendors.some(v => vendorName.toLowerCase().includes(v));
            const syncKey = 'purchase-' + p.Id;
            return {
                id: p.Id,
                type: 'Purchase',
                doc_number: p.DocNumber,
                vendor_name: vendorName,
                vendor_id: p.EntityRef?.value,
                txn_date: p.TxnDate,
                total: parseFloat(p.TotalAmt || 0),
                payment_type: p.PaymentType,
                memo: p.PrivateNote,
                lines: (p.Line || []).filter(l => l.DetailType === 'AccountBasedExpenseLineDetail' || l.DetailType === 'ItemBasedExpenseLineDetail').map(l => ({
                    description: l.Description,
                    amount: l.Amount,
                    account: l.AccountBasedExpenseLineDetail?.AccountRef?.name || l.ItemBasedExpenseLineDetail?.ItemRef?.name
                })),
                is_synced: !!syncedMap[syncKey],
                synced_job_id: syncedMap[syncKey]?.job_id || null,
                synced_job_number: syncedMap[syncKey]?.job_number || null,
                is_concrete: isConcrete,
                last_updated: p.MetaData?.LastUpdatedTime
            };
        });

        res.json({
            bills: formattedBills,
            purchases: formattedPurchases,
            total: formattedBills.length + formattedPurchases.length,
            realm_id: tokens.realmId
        });
    } catch (error) {
        console.error('Get bills error:', error.response?.data || error.message);
        res.status(500).json({ error: error.response?.data?.Fault?.Error?.[0]?.Message || error.message });
    }
});

// Sync invoice to a job (link QB invoice to local job for income tracking)
app.post('/api/quickbooks/sync-invoice/:invoiceId', async (req, res) => {
    try {
        const { invoiceId } = req.params;
        const { job_id } = req.body;

        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.status(401).json({ error: 'Not connected to QuickBooks' });
        }

        const apiUrl = getQBApiUrl(tokens.realmId);

        // Fetch the invoice details from QB
        const response = await axios.get(`${apiUrl}/invoice/${invoiceId}`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            }
        });

        const invoice = response.data.Invoice;
        if (!invoice) {
            return res.status(404).json({ error: 'Invoice not found in QuickBooks' });
        }

        // Insert into job_invoices table
        await pool.query(
            `INSERT INTO job_invoices (job_id, invoice_number, invoice_date, description, amount, status, qb_invoice_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (job_id, qb_invoice_id) DO UPDATE SET
                amount = EXCLUDED.amount,
                status = EXCLUDED.status,
                invoice_date = EXCLUDED.invoice_date`,
            [
                job_id,
                invoice.DocNumber,
                invoice.TxnDate,
                invoice.CustomerRef?.name + ' - Invoice',
                invoice.TotalAmt,
                parseFloat(invoice.Balance) === 0 ? 'paid' : 'pending',
                invoiceId
            ]
        );

        // Log the sync
        await pool.query(
            `INSERT INTO qb_sync_log (realm_id, entity_type, qb_id, local_id, status)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (realm_id, entity_type, qb_id) DO UPDATE SET
                local_id = EXCLUDED.local_id,
                status = EXCLUDED.status,
                synced_at = CURRENT_TIMESTAMP`,
            [tokens.realmId, 'invoice', invoiceId, job_id, 'success']
        );

        res.json({ success: true, invoice_number: invoice.DocNumber, amount: invoice.TotalAmt });
    } catch (error) {
        console.error('Sync invoice error:', error.response?.data || error.message);
        res.status(500).json({ error: error.message });
    }
});

// Sync bill/expense to a job (for cost tracking)
app.post('/api/quickbooks/sync-bill/:billId', async (req, res) => {
    try {
        const { billId } = req.params;
        const { job_id, bill_type } = req.body; // bill_type: 'bill' or 'purchase'

        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.status(401).json({ error: 'Not connected to QuickBooks' });
        }

        const apiUrl = getQBApiUrl(tokens.realmId);
        const entityType = bill_type || 'bill';

        // Fetch the bill/purchase details from QB
        const response = await axios.get(`${apiUrl}/${entityType}/${billId}`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            }
        });

        const bill = response.data.Bill || response.data.Purchase;
        if (!bill) {
            return res.status(404).json({ error: 'Bill not found in QuickBooks' });
        }

        const vendorName = bill.VendorRef?.name || bill.EntityRef?.name || 'Unknown Vendor';

        // Determine if this is concrete (check vendor name or line items)
        const isConcrete = vendorName.toLowerCase().includes('concrete') ||
                          vendorName.toLowerCase().includes('rock') ||
                          vendorName.toLowerCase().includes('parson') ||
                          vendorName.toLowerCase().includes('geneva');

        if (isConcrete) {
            // Insert as concrete delivery
            await pool.query(
                `INSERT INTO concrete_deliveries (job_id, delivery_date, invoice_number, total_cost, notes, status)
                 VALUES ($1, $2, $3, $4, $5, 'matched')
                 ON CONFLICT DO NOTHING`,
                [job_id, bill.TxnDate, bill.DocNumber, bill.TotalAmt, 'QB Bill: ' + vendorName]
            );
        } else {
            // Insert as job cost
            await pool.query(
                `INSERT INTO job_costs (job_id, cost_date, vendor, category, description, amount)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [
                    job_id,
                    bill.TxnDate,
                    vendorName,
                    'materials',
                    bill.PrivateNote || 'QB ' + entityType.charAt(0).toUpperCase() + entityType.slice(1),
                    bill.TotalAmt
                ]
            );
        }

        // Log the sync
        await pool.query(
            `INSERT INTO qb_sync_log (realm_id, entity_type, qb_id, local_id, status)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (realm_id, entity_type, qb_id) DO UPDATE SET
                local_id = EXCLUDED.local_id,
                status = EXCLUDED.status,
                synced_at = CURRENT_TIMESTAMP`,
            [tokens.realmId, entityType, billId, job_id, 'success']
        );

        res.json({ success: true, vendor: vendorName, amount: bill.TotalAmt, is_concrete: isConcrete });
    } catch (error) {
        console.error('Sync bill error:', error.response?.data || error.message);
        res.status(500).json({ error: error.message });
    }
});

// Import estimate as job with takeoffs
app.post('/api/quickbooks/import-estimate/:id', async (req, res) => {
    const client = await pool.connect();
    try {
        const estimateId = req.params.id;
        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.status(401).json({ error: 'Not connected to QuickBooks' });
        }

        const apiUrl = getQBApiUrl(tokens.realmId);

        // Get the estimate details
        const response = await axios.get(`${apiUrl}/estimate/${estimateId}`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            }
        });

        const estimate = response.data.Estimate;
        if (!estimate) {
            return res.status(404).json({ error: 'Estimate not found' });
        }

        await client.query('BEGIN');
        console.log('BEGIN transaction');

        // Check if already synced
        console.log('Checking existing sync...');
        const existingSync = await client.query(
            'SELECT local_id FROM qb_sync_log WHERE realm_id = $1 AND entity_type = $2 AND qb_id = $3',
            [tokens.realmId, 'estimate', estimateId]
        );

        let jobId;
        let jobCreated = false;

        if (existingSync.rows.length > 0 && existingSync.rows[0].local_id) {
            // Job already exists - update it
            jobId = existingSync.rows[0].local_id;
            await client.query(
                `UPDATE jobs SET
                    income = $1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $2`,
                [estimate.TotalAmt || 0, jobId]
            );
        } else {
            // Check if job exists by customer name
            const customerName = estimate.CustomerRef?.name || 'QB Estimate ' + estimate.DocNumber;
            const existingJob = await client.query(
                'SELECT id FROM jobs WHERE job_name ILIKE $1 LIMIT 1',
                ['%' + customerName + '%']
            );

            if (existingJob.rows.length > 0) {
                jobId = existingJob.rows[0].id;
                await client.query(
                    `UPDATE jobs SET income = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
                    [estimate.TotalAmt || 0, jobId]
                );
            } else {
                // Create new job - use estimate ID to ensure uniqueness
                let jobNumber = 'QB-' + (estimate.DocNumber || estimateId);

                // Check if job_number already exists
                const existingJobNum = await client.query(
                    'SELECT id FROM jobs WHERE job_number = $1',
                    [jobNumber]
                );
                if (existingJobNum.rows.length > 0) {
                    // Append estimate ID to make it unique
                    jobNumber = 'QB-' + estimateId;
                }

                const jobResult = await client.query(
                    `INSERT INTO jobs (job_number, job_name, income, status, notes, qb_estimate_id)
                     VALUES ($1, $2, $3, 'active', $4, $5)
                     RETURNING id`,
                    [
                        jobNumber,
                        customerName,
                        estimate.TotalAmt || 0,
                        'Imported from QuickBooks Estimate #' + (estimate.DocNumber || estimateId),
                        estimateId
                    ]
                );
                jobId = jobResult.rows[0].id;
                jobCreated = true;
            }
        }

        // Import line items as takeoffs
        const lines = estimate.Line?.filter(l => l.DetailType === 'SalesItemLineDetail') || [];
        let imported = 0;
        const errors = [];

        for (const line of lines) {
            try {
                const itemName = line.SalesItemLineDetail?.ItemRef?.name || line.Description || 'Line Item';
                const qty = parseFloat(line.SalesItemLineDetail?.Qty) || 1;
                const rate = parseFloat(line.SalesItemLineDetail?.UnitPrice) || parseFloat(line.Amount) || 0;

                // Find or create item in items table
                let itemResult = await client.query(
                    'SELECT id FROM items WHERE LOWER(name) = LOWER($1) LIMIT 1',
                    [itemName]
                );

                let itemId;
                if (itemResult.rows.length > 0) {
                    itemId = itemResult.rows[0].id;
                } else {
                    console.log('Creating new item:', itemName);
                    const newItem = await client.query(
                        'INSERT INTO items (name, price) VALUES ($1, $2) RETURNING id',
                        [itemName, rate]
                    );
                    itemId = newItem.rows[0].id;
                    console.log('Created item with id:', itemId);
                }

                // Insert or update takeoff
                console.log('Inserting takeoff:', { jobId, itemId, qty });
                await client.query(
                    `INSERT INTO job_takeoffs (job_id, item_id, quantity, notes, source)
                     VALUES ($1, $2, $3, $4, 'quickbooks')
                     ON CONFLICT (job_id, item_id) DO UPDATE SET
                        quantity = job_takeoffs.quantity + EXCLUDED.quantity,
                        notes = COALESCE(job_takeoffs.notes, '') || ' | QB: ' || EXCLUDED.notes,
                        updated_at = CURRENT_TIMESTAMP`,
                    [jobId, itemId, qty, line.Description || '']
                );
                console.log('Takeoff inserted successfully');
                imported++;
            } catch (e) {
                errors.push({ line: line.Description, error: e.message });
            }
        }

        // Log the sync
        await client.query(
            `INSERT INTO qb_sync_log (realm_id, entity_type, qb_id, local_id, status)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (realm_id, entity_type, qb_id) DO UPDATE SET
                local_id = EXCLUDED.local_id,
                status = EXCLUDED.status,
                synced_at = CURRENT_TIMESTAMP`,
            [tokens.realmId, 'estimate', estimateId, jobId, 'success']
        );

        await client.query('COMMIT');

        // Get job details for response
        const jobResult = await client.query('SELECT job_number, job_name FROM jobs WHERE id = $1', [jobId]);
        const job = jobResult.rows[0];

        res.json({
            success: true,
            job_id: jobId,
            job_number: job.job_number,
            job_name: job.job_name,
            job_created: jobCreated,
            imported: imported,
            income_set: parseFloat(estimate.TotalAmt || 0),
            errors: errors
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Import estimate error:', error);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// Link an estimate to an existing job (update contract value)
app.post('/api/quickbooks/link-estimate', async (req, res) => {
    const client = await pool.connect();
    try {
        const { estimate_id, job_id } = req.body;

        if (!estimate_id || !job_id) {
            return res.status(400).json({ error: 'estimate_id and job_id are required' });
        }

        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.status(401).json({ error: 'Not connected to QuickBooks' });
        }

        const apiUrl = getQBApiUrl(tokens.realmId);

        // Get the estimate details from QuickBooks
        const response = await axios.get(`${apiUrl}/estimate/${estimate_id}`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            }
        });

        const estimate = response.data.Estimate;
        if (!estimate) {
            return res.status(404).json({ error: 'Estimate not found in QuickBooks' });
        }

        await client.query('BEGIN');

        // Update the job with the estimate's total as contract value
        await client.query(
            `UPDATE jobs SET
                income = $1,
                qb_estimate_id = $2,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $3`,
            [estimate.TotalAmt || 0, estimate_id, job_id]
        );

        // Log the sync
        await client.query(
            `INSERT INTO qb_sync_log (realm_id, entity_type, qb_id, local_id, status)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (realm_id, entity_type, qb_id) DO UPDATE SET
                local_id = EXCLUDED.local_id,
                status = EXCLUDED.status,
                synced_at = CURRENT_TIMESTAMP`,
            [tokens.realmId, 'estimate', estimate_id, job_id, 'linked']
        );

        // Import line items as takeoffs (optional)
        const lines = estimate.Line?.filter(l => l.DetailType === 'SalesItemLineDetail') || [];
        let imported = 0;

        for (const line of lines) {
            try {
                const itemName = line.SalesItemLineDetail?.ItemRef?.name || line.Description || 'Line Item';
                const qty = parseFloat(line.SalesItemLineDetail?.Qty) || 1;
                const rate = parseFloat(line.SalesItemLineDetail?.UnitPrice) || parseFloat(line.Amount) || 0;

                // Find or create item
                let itemResult = await client.query(
                    'SELECT id FROM items WHERE LOWER(name) = LOWER($1) LIMIT 1',
                    [itemName]
                );

                let itemId;
                if (itemResult.rows.length > 0) {
                    itemId = itemResult.rows[0].id;
                } else {
                    const newItem = await client.query(
                        'INSERT INTO items (name, price) VALUES ($1, $2) RETURNING id',
                        [itemName, rate]
                    );
                    itemId = newItem.rows[0].id;
                }

                // Insert takeoff
                await client.query(
                    `INSERT INTO job_takeoffs (job_id, item_id, quantity, notes, source)
                     VALUES ($1, $2, $3, $4, 'quickbooks')
                     ON CONFLICT (job_id, item_id) DO UPDATE SET
                        quantity = job_takeoffs.quantity + EXCLUDED.quantity,
                        notes = COALESCE(job_takeoffs.notes, '') || ' | QB: ' || EXCLUDED.notes,
                        updated_at = CURRENT_TIMESTAMP`,
                    [job_id, itemId, qty, line.Description || '']
                );
                imported++;
            } catch (e) {
                // Ignore line item errors
                console.error('Error importing line item:', e.message);
            }
        }

        await client.query('COMMIT');

        // Get job details
        const jobResult = await client.query('SELECT job_number, job_name FROM jobs WHERE id = $1', [job_id]);
        const job = jobResult.rows[0];

        res.json({
            success: true,
            job_id: job_id,
            job_number: job?.job_number,
            job_name: job?.job_name,
            income_set: parseFloat(estimate.TotalAmt || 0),
            line_items_imported: imported
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Link estimate error:', error);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// Sync all pending estimates
app.post('/api/quickbooks/sync-all-estimates', async (req, res) => {
    try {
        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.status(401).json({ error: 'Not connected to QuickBooks' });
        }

        const apiUrl = getQBApiUrl(tokens.realmId);

        // Get all pending estimates
        const query = "SELECT * FROM Estimate WHERE TxnStatus = 'Pending' ORDERBY MetaData.LastUpdatedTime DESC";
        const response = await axios.get(`${apiUrl}/query`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            },
            params: { query }
        });

        const estimates = response.data.QueryResponse?.Estimate || [];

        // Check which are already synced
        const syncedResult = await pool.query(
            'SELECT qb_id FROM qb_sync_log WHERE realm_id = $1 AND entity_type = $2',
            [tokens.realmId, 'estimate']
        );
        const syncedIds = new Set(syncedResult.rows.map(r => r.qb_id));

        // Import unsynced estimates
        const results = { imported: 0, skipped: 0, errors: [] };

        for (const estimate of estimates) {
            if (syncedIds.has(estimate.Id)) {
                results.skipped++;
                continue;
            }

            try {
                // Make internal API call to import
                const importRes = await axios.post(
                    `http://localhost:${PORT}/api/quickbooks/import-estimate/${estimate.Id}`
                );
                if (importRes.data.success) {
                    results.imported++;
                }
            } catch (e) {
                results.errors.push({
                    estimate_id: estimate.Id,
                    doc_number: estimate.DocNumber,
                    error: e.response?.data?.error || e.message
                });
            }
        }

        res.json(results);
    } catch (error) {
        console.error('Sync all estimates error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get customers from QuickBooks
app.get('/api/quickbooks/customers', async (req, res) => {
    try {
        const tokens = await getValidQBTokens();
        if (!tokens) {
            return res.status(401).json({ error: 'Not connected to QuickBooks' });
        }

        const apiUrl = getQBApiUrl(tokens.realmId);
        const query = "SELECT * FROM Customer WHERE Active = true ORDERBY DisplayName";

        const response = await axios.get(`${apiUrl}/query`, {
            headers: {
                'Authorization': `Bearer ${tokens.accessToken}`,
                'Accept': 'application/json'
            },
            params: { query }
        });

        const customers = response.data.QueryResponse?.Customer || [];

        res.json({
            customers: customers.map(c => ({
                id: c.Id,
                name: c.DisplayName,
                company: c.CompanyName,
                email: c.PrimaryEmailAddr?.Address,
                phone: c.PrimaryPhone?.FreeFormNumber,
                balance: c.Balance
            })),
            total: customers.length
        });
    } catch (error) {
        console.error('Get customers error:', error.response?.data || error.message);
        res.status(500).json({ error: error.message });
    }
});

// ========== BATCH IMPORT ROUTES (Ultimate Foreman Migration) ==========

// Batch import upload configuration
const batchUpload = multer({
    storage: multer.diskStorage({
        destination: async (req, file, cb) => {
            const uploadDir = './uploads/batch-imports';
            try {
                await fs.mkdir(uploadDir, { recursive: true });
                cb(null, uploadDir);
            } catch (error) {
                cb(error, null);
            }
        },
        filename: (req, file, cb) => {
            const uniqueName = Date.now() + '-' + file.originalname;
            cb(null, uniqueName);
        }
    }),
    fileFilter: (req, file, cb) => {
        const allowedTypes = /csv|xlsx|xls/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        if (extname) {
            return cb(null, true);
        }
        cb(new Error('Only CSV and Excel files are allowed'));
    }
});

// Preview batch import - parse file and detect structure
app.post('/api/batch-import/preview', (req, res, next) => {
    batchUpload.single('file')(req, res, (err) => {
        if (err) {
            return res.status(400).json({ error: err.message || 'File upload failed' });
        }
        next();
    });
}, async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const filePath = req.file.path;
        const dataType = req.body.type || 'auto';

        // Parse the file
        const workbook = XLSX.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });

        if (data.length < 2) {
            return res.json({ error: 'File is empty or has no data rows', rows: [] });
        }

        const headers = data[0].map(h => String(h || '').trim());
        const headersLower = headers.map(h => h.toLowerCase());
        const rows = data.slice(1).filter(row => row.some(cell => cell !== null && cell !== undefined && cell !== ''));

        // Auto-detect data type based on headers
        let detectedType = dataType;
        if (dataType === 'auto') {
            if (headersLower.some(h => h.includes('job') && (h.includes('number') || h.includes('#') || h.includes('name')))) {
                detectedType = 'jobs';
            } else if (headersLower.some(h => h.includes('worker') || h.includes('employee') || h.includes('crew'))) {
                detectedType = 'workers';
            } else if (headersLower.some(h => h.includes('daily') || h.includes('record') || (h.includes('date') && headersLower.some(h2 => h2.includes('note'))))) {
                detectedType = 'daily_records';
            } else if (headersLower.some(h => h.includes('concrete') || h.includes('yard') || h.includes('delivery') || h.includes('supplier'))) {
                detectedType = 'concrete';
            } else {
                detectedType = 'jobs'; // Default
            }
        }

        // Suggest column mappings based on header names
        const suggestedMappings = suggestColumnMappings(headers, detectedType);

        // Convert rows to objects
        const mappedData = rows.map((row, idx) => {
            const obj = { _row: idx + 2 };
            headers.forEach((header, i) => {
                obj[header] = row[i];
            });
            return obj;
        });

        // Get existing data for reference
        const existingJobs = await pool.query('SELECT id, job_number, job_name FROM jobs ORDER BY job_name');
        const existingWorkers = await pool.query('SELECT id, full_name FROM workers ORDER BY full_name');
        const existingCrewLeads = await pool.query('SELECT id, name FROM crew_leads ORDER BY name');

        res.json({
            file_name: req.file.originalname,
            file_path: filePath,
            detected_type: detectedType,
            headers: headers,
            suggested_mappings: suggestedMappings,
            row_count: rows.length,
            preview: mappedData.slice(0, 20),
            all_data: mappedData,
            existing_jobs: existingJobs.rows,
            existing_workers: existingWorkers.rows,
            existing_crew_leads: existingCrewLeads.rows
        });
    } catch (error) {
        console.error('Batch import preview error:', error);
        res.status(500).json({ error: 'Failed to parse file: ' + error.message });
    }
});

// Helper function to suggest column mappings
function suggestColumnMappings(headers, dataType) {
    const mappings = {};
    const headersLower = headers.map(h => h.toLowerCase());

    if (dataType === 'jobs') {
        // Job mappings
        mappings.job_number = findBestMatch(headersLower, headers, ['job number', 'job #', 'job_number', 'jobnumber', 'job no', 'project number', 'project #', 'number', '#']);
        mappings.job_name = findBestMatch(headersLower, headers, ['job name', 'job_name', 'jobname', 'project name', 'project', 'name', 'title', 'customer', 'client']);
        mappings.location = findBestMatch(headersLower, headers, ['location', 'address', 'site', 'job address', 'site address', 'street', 'city']);
        mappings.contractor = findBestMatch(headersLower, headers, ['contractor', 'contractor name', 'client', 'customer', 'gc', 'general contractor', 'builder']);
        mappings.status = findBestMatch(headersLower, headers, ['status', 'state', 'job status', 'project status', 'active']);
        mappings.start_date = findBestMatch(headersLower, headers, ['start date', 'start_date', 'startdate', 'start', 'begin', 'begin date']);
        mappings.end_date = findBestMatch(headersLower, headers, ['end date', 'end_date', 'enddate', 'end', 'finish', 'complete', 'completion date']);
        mappings.income = findBestMatch(headersLower, headers, ['income', 'contract', 'contract amount', 'price', 'value', 'bid', 'bid amount', 'revenue', 'total']);
        mappings.notes = findBestMatch(headersLower, headers, ['notes', 'note', 'comments', 'description', 'remarks', 'memo']);
    } else if (dataType === 'workers') {
        // Worker mappings
        mappings.full_name = findBestMatch(headersLower, headers, ['name', 'full name', 'full_name', 'fullname', 'worker name', 'employee name', 'employee', 'worker']);
        mappings.role = findBestMatch(headersLower, headers, ['role', 'position', 'title', 'job title', 'type', 'classification', 'class']);
        mappings.contact_info = findBestMatch(headersLower, headers, ['phone', 'contact', 'contact info', 'cell', 'mobile', 'email', 'telephone']);
        mappings.hire_date = findBestMatch(headersLower, headers, ['hire date', 'hire_date', 'hiredate', 'start date', 'employed', 'hired']);
        mappings.hourly_rate = findBestMatch(headersLower, headers, ['rate', 'hourly rate', 'hourly', 'pay rate', 'wage', 'pay']);
    } else if (dataType === 'daily_records') {
        // Daily record mappings
        mappings.job = findBestMatch(headersLower, headers, ['job', 'job name', 'job number', 'project', 'project name', 'site']);
        mappings.date = findBestMatch(headersLower, headers, ['date', 'record date', 'work date', 'day']);
        mappings.foreman = findBestMatch(headersLower, headers, ['foreman', 'supervisor', 'lead', 'crew lead', 'superintendent']);
        mappings.notes = findBestMatch(headersLower, headers, ['notes', 'note', 'comments', 'description', 'work description', 'activities', 'remarks']);
        mappings.weather = findBestMatch(headersLower, headers, ['weather', 'conditions', 'weather conditions']);
        mappings.workers = findBestMatch(headersLower, headers, ['workers', 'crew', 'crew size', 'headcount', 'men', 'employees']);
        mappings.hours = findBestMatch(headersLower, headers, ['hours', 'total hours', 'man hours', 'labor hours']);
    } else if (dataType === 'concrete') {
        // Concrete delivery mappings
        mappings.invoice = findBestMatch(headersLower, headers, ['invoice', 'invoice number', 'invoice #', 'ticket', 'ticket number', 'po', 'po number']);
        mappings.job = findBestMatch(headersLower, headers, ['job', 'job name', 'job number', 'project', 'site', 'location']);
        mappings.supplier = findBestMatch(headersLower, headers, ['supplier', 'vendor', 'plant', 'concrete supplier', 'provider', 'company']);
        mappings.date = findBestMatch(headersLower, headers, ['date', 'delivery date', 'pour date', 'delivered']);
        mappings.yards = findBestMatch(headersLower, headers, ['yards', 'cubic yards', 'cy', 'quantity', 'volume', 'amount', 'cubic']);
        mappings.cost = findBestMatch(headersLower, headers, ['cost', 'total', 'total cost', 'amount', 'price', 'charge', 'invoice amount']);
        mappings.mix = findBestMatch(headersLower, headers, ['mix', 'mix design', 'type', 'concrete type', 'psi', 'strength']);
    }

    return mappings;
}

function findBestMatch(headersLower, headers, searchTerms) {
    for (const term of searchTerms) {
        const exactIdx = headersLower.indexOf(term);
        if (exactIdx !== -1) return headers[exactIdx];
    }
    // Try partial matches
    for (const term of searchTerms) {
        const partialIdx = headersLower.findIndex(h => h.includes(term) || term.includes(h));
        if (partialIdx !== -1) return headers[partialIdx];
    }
    return null;
}

// Execute batch import - Jobs
app.post('/api/batch-import/jobs', async (req, res) => {
    const client = await pool.connect();
    try {
        const { mappings, data, options } = req.body;
        // options: { skip_duplicates, update_existing }

        await client.query('BEGIN');
        const results = { imported: 0, updated: 0, skipped: 0, errors: [] };

        for (const row of data) {
            try {
                const jobNumber = row[mappings.job_number] ? String(row[mappings.job_number]).trim() : '';
                const jobName = row[mappings.job_name] ? String(row[mappings.job_name]).trim() : '';
                const location = row[mappings.location] ? String(row[mappings.location]).trim() : null;
                const contractor = row[mappings.contractor] ? String(row[mappings.contractor]).trim() : null;
                const notes = row[mappings.notes] ? String(row[mappings.notes]).trim() : null;
                const income = mappings.income && row[mappings.income] ? parseFloat(String(row[mappings.income]).replace(/[$,]/g, '')) || 0 : 0;

                // Parse dates
                let startDate = null, endDate = null;
                if (mappings.start_date && row[mappings.start_date]) {
                    startDate = parseExcelDate(row[mappings.start_date]);
                }
                if (mappings.end_date && row[mappings.end_date]) {
                    endDate = parseExcelDate(row[mappings.end_date]);
                }

                // Parse status
                let status = 'active';
                if (mappings.status && row[mappings.status]) {
                    const statusVal = String(row[mappings.status]).toLowerCase();
                    if (statusVal.includes('complete') || statusVal.includes('done') || statusVal.includes('closed') || statusVal.includes('finished')) {
                        status = 'completed';
                    } else if (statusVal.includes('hold') || statusVal.includes('pause')) {
                        status = 'on_hold';
                    }
                }

                if (!jobNumber && !jobName) {
                    results.skipped++;
                    continue;
                }

                // Check if job exists
                const existing = await client.query(
                    'SELECT id FROM jobs WHERE job_number = $1 OR (job_name = $2 AND $2 IS NOT NULL AND $2 != \'\')',
                    [jobNumber || 'NOMATCH', jobName]
                );

                if (existing.rows.length > 0) {
                    if (options?.update_existing) {
                        await client.query(
                            `UPDATE jobs SET
                                job_name = COALESCE(NULLIF($1, ''), job_name),
                                location = COALESCE($2, location),
                                contractor_name = COALESCE($3, contractor_name),
                                status = $4,
                                start_date = COALESCE($5, start_date),
                                end_date = COALESCE($6, end_date),
                                income = CASE WHEN $7 > 0 THEN $7 ELSE income END,
                                notes = COALESCE($8, notes),
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = $9`,
                            [jobName, location, contractor, status, startDate, endDate, income, notes, existing.rows[0].id]
                        );
                        results.updated++;
                    } else {
                        results.skipped++;
                    }
                } else {
                    const finalJobNumber = jobNumber || 'IMP-' + Date.now() + '-' + results.imported;
                    await client.query(
                        `INSERT INTO jobs (job_number, job_name, location, contractor_name, status, start_date, end_date, income, notes)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                        [finalJobNumber, jobName || finalJobNumber, location, contractor, status, startDate, endDate, income, notes]
                    );
                    results.imported++;
                }
            } catch (e) {
                results.errors.push({ row: row._row, error: e.message });
            }
        }

        await client.query('COMMIT');
        res.json(results);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Batch import jobs error:', error);
        res.status(500).json({ error: 'Import failed: ' + error.message });
    } finally {
        client.release();
    }
});

// Execute batch import - Workers
app.post('/api/batch-import/workers', async (req, res) => {
    const client = await pool.connect();
    try {
        const { mappings, data, options } = req.body;

        await client.query('BEGIN');
        const results = { imported: 0, updated: 0, skipped: 0, errors: [] };

        for (const row of data) {
            try {
                const fullName = row[mappings.full_name] ? String(row[mappings.full_name]).trim() : '';
                const role = row[mappings.role] ? String(row[mappings.role]).trim() : 'Laborer';
                const contactInfo = row[mappings.contact_info] ? String(row[mappings.contact_info]).trim() : null;
                const hireDate = mappings.hire_date && row[mappings.hire_date] ? parseExcelDate(row[mappings.hire_date]) : null;

                if (!fullName) {
                    results.skipped++;
                    continue;
                }

                // Check if worker exists (fuzzy match on name)
                const existing = await client.query(
                    'SELECT id FROM workers WHERE LOWER(full_name) = LOWER($1)',
                    [fullName]
                );

                if (existing.rows.length > 0) {
                    if (options?.update_existing) {
                        await client.query(
                            `UPDATE workers SET
                                role = COALESCE(NULLIF($1, ''), role),
                                contact_info = COALESCE($2, contact_info),
                                hire_date = COALESCE($3, hire_date)
                            WHERE id = $4`,
                            [role, contactInfo, hireDate, existing.rows[0].id]
                        );
                        results.updated++;
                    } else {
                        results.skipped++;
                    }
                } else {
                    await client.query(
                        `INSERT INTO workers (full_name, role, contact_info, hire_date)
                         VALUES ($1, $2, $3, COALESCE($4, CURRENT_DATE))`,
                        [fullName, role, contactInfo, hireDate]
                    );
                    results.imported++;
                }
            } catch (e) {
                results.errors.push({ row: row._row, error: e.message });
            }
        }

        await client.query('COMMIT');
        res.json(results);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Batch import workers error:', error);
        res.status(500).json({ error: 'Import failed: ' + error.message });
    } finally {
        client.release();
    }
});

// Execute batch import - Daily Records
app.post('/api/batch-import/daily-records', async (req, res) => {
    const client = await pool.connect();
    try {
        const { mappings, data, options } = req.body;

        await client.query('BEGIN');
        const results = { imported: 0, skipped: 0, errors: [], jobs_created: 0, workers_created: 0 };

        for (const row of data) {
            try {
                const jobRef = row[mappings.job] ? String(row[mappings.job]).trim() : '';
                const dateVal = row[mappings.date] ? parseExcelDate(row[mappings.date]) : null;
                const foremanRef = row[mappings.foreman] ? String(row[mappings.foreman]).trim() : null;
                const notes = row[mappings.notes] ? String(row[mappings.notes]).trim() : null;
                const weather = row[mappings.weather] ? String(row[mappings.weather]).trim() : null;

                if (!jobRef || !dateVal) {
                    results.skipped++;
                    continue;
                }

                // Find or create job
                let jobResult = await client.query(
                    'SELECT id FROM jobs WHERE job_number ILIKE $1 OR job_name ILIKE $1 LIMIT 1',
                    ['%' + jobRef + '%']
                );

                let jobId;
                if (jobResult.rows.length > 0) {
                    jobId = jobResult.rows[0].id;
                } else if (options?.create_missing) {
                    const newJob = await client.query(
                        'INSERT INTO jobs (job_number, job_name, status) VALUES ($1, $1, $2) RETURNING id',
                        [jobRef, 'active']
                    );
                    jobId = newJob.rows[0].id;
                    results.jobs_created++;
                } else {
                    results.errors.push({ row: row._row, error: 'Job not found: ' + jobRef });
                    continue;
                }

                // Find foreman (optional)
                let foremanId = null;
                if (foremanRef) {
                    const workerResult = await client.query(
                        'SELECT id FROM workers WHERE full_name ILIKE $1 LIMIT 1',
                        ['%' + foremanRef + '%']
                    );
                    if (workerResult.rows.length > 0) {
                        foremanId = workerResult.rows[0].id;
                    } else if (options?.create_missing) {
                        const newWorker = await client.query(
                            'INSERT INTO workers (full_name, role, hire_date) VALUES ($1, $2, CURRENT_DATE) RETURNING id',
                            [foremanRef, 'Foreman']
                        );
                        foremanId = newWorker.rows[0].id;
                        results.workers_created++;
                    }
                }

                // Check if record exists for this job/date
                const existingRecord = await client.query(
                    'SELECT id FROM daily_records WHERE job_id = $1 AND record_date = $2',
                    [jobId, dateVal]
                );

                if (existingRecord.rows.length > 0) {
                    if (options?.update_existing) {
                        await client.query(
                            `UPDATE daily_records SET
                                foreman_id = COALESCE($1, foreman_id),
                                notes = CASE WHEN $2 IS NOT NULL THEN COALESCE(notes, '') || E'\n' || $2 ELSE notes END,
                                weather_data = COALESCE($3, weather_data)
                            WHERE id = $4`,
                            [foremanId, notes, weather ? JSON.stringify({ condition: weather }) : null, existingRecord.rows[0].id]
                        );
                    }
                    results.skipped++;
                } else {
                    await client.query(
                        `INSERT INTO daily_records (job_id, foreman_id, record_date, notes, weather_data)
                         VALUES ($1, $2, $3, $4, $5)`,
                        [jobId, foremanId, dateVal, notes, weather ? JSON.stringify({ condition: weather }) : null]
                    );
                    results.imported++;
                }
            } catch (e) {
                results.errors.push({ row: row._row, error: e.message });
            }
        }

        await client.query('COMMIT');
        res.json(results);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Batch import daily records error:', error);
        res.status(500).json({ error: 'Import failed: ' + error.message });
    } finally {
        client.release();
    }
});

// Execute batch import - Concrete Deliveries
app.post('/api/batch-import/concrete', async (req, res) => {
    const client = await pool.connect();
    try {
        const { mappings, data, options } = req.body;

        await client.query('BEGIN');
        const results = { imported: 0, skipped: 0, errors: [], jobs_created: 0, unmatched: 0 };

        for (const row of data) {
            try {
                const invoice = row[mappings.invoice] ? String(row[mappings.invoice]).trim() : '';
                const jobRef = row[mappings.job] ? String(row[mappings.job]).trim() : '';
                const supplier = row[mappings.supplier] ? String(row[mappings.supplier]).trim() : null;
                const dateVal = row[mappings.date] ? parseExcelDate(row[mappings.date]) : new Date().toISOString().split('T')[0];
                const yards = mappings.yards && row[mappings.yards] ? parseFloat(String(row[mappings.yards]).replace(/,/g, '')) || 0 : 0;
                const cost = mappings.cost && row[mappings.cost] ? parseFloat(String(row[mappings.cost]).replace(/[$,]/g, '')) || 0 : 0;
                const mix = row[mappings.mix] ? String(row[mappings.mix]).trim() : null;

                if (!yards && !cost && !invoice) {
                    results.skipped++;
                    continue;
                }

                // Find job
                let jobId = null;
                if (jobRef) {
                    const jobResult = await client.query(
                        'SELECT id FROM jobs WHERE job_number ILIKE $1 OR job_name ILIKE $1 OR location ILIKE $1 LIMIT 1',
                        ['%' + jobRef + '%']
                    );
                    if (jobResult.rows.length > 0) {
                        jobId = jobResult.rows[0].id;
                    } else if (options?.create_missing) {
                        const newJob = await client.query(
                            'INSERT INTO jobs (job_number, job_name, status) VALUES ($1, $1, $2) RETURNING id',
                            [jobRef, 'active']
                        );
                        jobId = newJob.rows[0].id;
                        results.jobs_created++;
                    }
                }

                if (!jobId) {
                    results.unmatched++;
                }

                // Check for duplicate invoice
                if (invoice) {
                    const existingInvoice = await client.query(
                        'SELECT id FROM concrete_deliveries WHERE invoice_number = $1',
                        [invoice]
                    );
                    if (existingInvoice.rows.length > 0) {
                        if (options?.skip_duplicates) {
                            results.skipped++;
                            continue;
                        }
                    }
                }

                // Calculate cost per yard
                const costPerYard = yards > 0 ? cost / yards : 0;

                // Create notes with supplier and mix info
                const notesParts = [];
                if (supplier) notesParts.push('Supplier: ' + supplier);
                if (mix) notesParts.push('Mix: ' + mix);
                const notes = notesParts.join(' | ') || null;

                await client.query(
                    `INSERT INTO concrete_deliveries (invoice_number, job_id, delivery_date, cubic_yards, cost_per_yard, total_cost, status, notes)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                    [invoice || 'IMP-' + Date.now() + '-' + results.imported, jobId, dateVal, yards, costPerYard, cost, jobId ? 'matched' : 'unmatched', notes]
                );
                results.imported++;
            } catch (e) {
                results.errors.push({ row: row._row, error: e.message });
            }
        }

        await client.query('COMMIT');
        res.json(results);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Batch import concrete error:', error);
        res.status(500).json({ error: 'Import failed: ' + error.message });
    } finally {
        client.release();
    }
});

// Helper function to parse Excel date serial numbers or date strings
function parseExcelDate(value) {
    if (!value) return null;

    // If it's already a Date object
    if (value instanceof Date) {
        return value.toISOString().split('T')[0];
    }

    // If it's a number (Excel serial date)
    if (typeof value === 'number') {
        // Excel dates are days since 1900-01-01 (with a bug for 1900 leap year)
        const excelEpoch = new Date(1899, 11, 30);
        const date = new Date(excelEpoch.getTime() + value * 24 * 60 * 60 * 1000);
        return date.toISOString().split('T')[0];
    }

    // If it's a string, try to parse it
    const str = String(value).trim();

    // Try ISO format first
    if (/^\d{4}-\d{2}-\d{2}/.test(str)) {
        return str.substring(0, 10);
    }

    // Try MM/DD/YYYY or M/D/YYYY
    const usMatch = str.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})$/);
    if (usMatch) {
        const month = usMatch[1].padStart(2, '0');
        const day = usMatch[2].padStart(2, '0');
        let year = usMatch[3];
        if (year.length === 2) {
            year = parseInt(year) > 50 ? '19' + year : '20' + year;
        }
        return `${year}-${month}-${day}`;
    }

    // Try DD/MM/YYYY (if day > 12, it's clearly day first)
    const euMatch = str.match(/^(\d{1,2})[-\/](\d{1,2})[-\/](\d{2,4})$/);
    if (euMatch && parseInt(euMatch[1]) > 12) {
        const day = euMatch[1].padStart(2, '0');
        const month = euMatch[2].padStart(2, '0');
        let year = euMatch[3];
        if (year.length === 2) {
            year = parseInt(year) > 50 ? '19' + year : '20' + year;
        }
        return `${year}-${month}-${day}`;
    }

    // Try natural language parsing
    const parsed = new Date(str);
    if (!isNaN(parsed.getTime())) {
        return parsed.toISOString().split('T')[0];
    }

    return null;
}

// Get batch import status/summary
app.get('/api/batch-import/summary', async (req, res) => {
    try {
        const jobCount = await pool.query('SELECT COUNT(*) as count FROM jobs');
        const workerCount = await pool.query('SELECT COUNT(*) as count FROM workers');
        const recordCount = await pool.query('SELECT COUNT(*) as count FROM daily_records');
        const concreteCount = await pool.query('SELECT COUNT(*) as count FROM concrete_deliveries');

        res.json({
            jobs: parseInt(jobCount.rows[0].count),
            workers: parseInt(workerCount.rows[0].count),
            daily_records: parseInt(recordCount.rows[0].count),
            concrete_deliveries: parseInt(concreteCount.rows[0].count)
        });
    } catch (error) {
        console.error('Batch import summary error:', error);
        res.status(500).json({ error: 'Failed to get summary' });
    }
});

// ========== SERVER START ==========

// Public jobs endpoint (no auth required)
app.get("/api/public/jobs", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM jobs ORDER BY job_number");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Public concrete endpoints
app.get("/api/public/concrete2", async (req, res) => {
  try {
    const result = await pool.query("SELECT id, invoice_number, supplier_id, job_id, delivery_date, cubic_yards as yards, total_cost as cost, status, notes FROM concrete_deliveries ORDER BY delivery_date DESC");
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/public/concrete2", async (req, res) => {
  try {
    const { invoice_number, supplier, delivery_date, yards, cost, job_id } = req.body;
    const result = await pool.query(
      "INSERT INTO concrete_deliveries (invoice_number, delivery_date, cubic_yards, total_cost, job_id, notes, status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
      [invoice_number, delivery_date, yards, cost, job_id, "Supplier: " + supplier, job_id ? "matched" : "unmatched"]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Public workers endpoints
app.get("/api/public/workers", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM workers ORDER BY full_name");
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/public/workers", async (req, res) => {
  try {
    const { full_name, role, contact_info } = req.body;
    const result = await pool.query(
      "INSERT INTO workers (full_name, role, contact_info, hire_date) VALUES ($1, $2, $3, CURRENT_DATE) RETURNING *",
      [full_name, role, contact_info]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Daily Records endpoints
app.get("/api/public/daily-records", async (req, res) => {
  try {
    const result = await pool.query("SELECT dr.*, j.job_number, j.job_name, w.full_name as foreman_name FROM daily_records dr LEFT JOIN jobs j ON dr.job_id = j.id LEFT JOIN workers w ON dr.foreman_id = w.id ORDER BY dr.record_date DESC LIMIT 50");
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Helper function to fetch weather data
async function fetchWeather(date, lat = 40.76, lon = -111.89) {
  // Default coords are Salt Lake City area - adjust as needed
  try {
    const response = await fetch(
      `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&daily=temperature_2m_max,temperature_2m_min,precipitation_sum,weathercode&timezone=America/Denver&start_date=${date}&end_date=${date}`
    );
    const data = await response.json();
    
    if (data.daily) {
      const weatherCodes = {
        0: 'Clear', 1: 'Mainly Clear', 2: 'Partly Cloudy', 3: 'Overcast',
        45: 'Foggy', 48: 'Depositing Rime Fog',
        51: 'Light Drizzle', 53: 'Moderate Drizzle', 55: 'Dense Drizzle',
        61: 'Slight Rain', 63: 'Moderate Rain', 65: 'Heavy Rain',
        71: 'Slight Snow', 73: 'Moderate Snow', 75: 'Heavy Snow',
        77: 'Snow Grains', 80: 'Slight Rain Showers', 81: 'Moderate Rain Showers',
        82: 'Violent Rain Showers', 85: 'Slight Snow Showers', 86: 'Heavy Snow Showers',
        95: 'Thunderstorm', 96: 'Thunderstorm with Slight Hail', 99: 'Thunderstorm with Heavy Hail'
      };
      
      return {
        high: Math.round(data.daily.temperature_2m_max[0] * 9/5 + 32), // Convert to Fahrenheit
        low: Math.round(data.daily.temperature_2m_min[0] * 9/5 + 32),
        precipitation: data.daily.precipitation_sum[0],
        condition: weatherCodes[data.daily.weathercode[0]] || 'Unknown',
        code: data.daily.weathercode[0]
      };
    }
    return null;
  } catch (e) {
    console.error('Weather fetch error:', e);
    return null;
  }
}

app.post("/api/public/daily-records", async (req, res) => {
  try {
    const { job_id, foreman_id, record_date, notes, work_items, production_items, yards_poured } = req.body;

    // Auto-fetch weather for the record date
    const weather = await fetchWeather(record_date);

    // Start transaction for record + work items + production
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const result = await client.query(
        "INSERT INTO daily_records (job_id, foreman_id, record_date, notes, yards_poured, weather_data) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
        [job_id, foreman_id, record_date, notes, yards_poured || 0, weather ? JSON.stringify(weather) : null]
      );

      const recordId = result.rows[0].id;

      // Insert work items if any
      if (work_items && work_items.length > 0) {
        for (const item of work_items) {
          await client.query(
            'INSERT INTO work_items (daily_record_id, item_id, quantity) VALUES ($1, $2, $3)',
            [recordId, item.item_id, item.quantity]
          );
        }
      }

      // Handle production items (work done with quantities)
      if (production_items && production_items.length > 0) {
        for (const item of production_items) {
          // Store production in daily_record_production table
          await client.query(
            `INSERT INTO daily_record_production (daily_record_id, job_id, item_name, quantity, unit)
             VALUES ($1, $2, $3, $4, $5)`,
            [recordId, job_id, item.name, item.quantity, item.unit]
          );

          // Try to find matching takeoff item and update progress
          const takeoffMatch = await client.query(
            `SELECT jt.id FROM job_takeoffs jt
             LEFT JOIN items i ON jt.item_id = i.id
             WHERE jt.job_id = $1 AND (
               LOWER(i.name) LIKE $2 OR
               LOWER(jt.source) LIKE $2
             )
             LIMIT 1`,
            [job_id, '%' + item.name.toLowerCase() + '%']
          );

          if (takeoffMatch.rows.length > 0) {
            // Update the takeoff's quantity_completed
            await client.query(
              `UPDATE job_takeoffs
               SET quantity_completed = COALESCE(quantity_completed, 0) + $1,
                   status = CASE
                     WHEN COALESCE(quantity_completed, 0) + $1 >= quantity THEN 'complete'
                     WHEN COALESCE(quantity_completed, 0) + $1 > 0 THEN 'in_progress'
                     ELSE 'pending'
                   END
               WHERE id = $2`,
              [item.quantity, takeoffMatch.rows[0].id]
            );
          }
        }
      }

      await client.query('COMMIT');
      res.json(result.rows[0]);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/job-costing
app.get("/api/job-costing", async (req, res) => {
  try {
    const result = await pool.query("SELECT j.id, j.job_number, j.job_name, j.contractor_name, j.status, COALESCE(SUM(cd.cubic_yards), 0) as total_yards, COALESCE(SUM(cd.total_cost), 0) as total_concrete_cost, COUNT(cd.invoice_number) as delivery_count FROM jobs j LEFT JOIN concrete_deliveries cd ON cd.job_id = j.id GROUP BY j.id, j.job_number, j.job_name, j.contractor_name, j.status ORDER BY j.status ASC, total_concrete_cost DESC");
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/job-detail/:id
app.get("/api/job-detail/:id", async (req, res) => {
  try {
    const jobResult = await pool.query("SELECT id, job_number, job_name, location, contractor_name, status, start_date, end_date, notes, income, planned_materials, planned_labor, planned_overhead FROM jobs WHERE id = $1", [req.params.id]);
    if (jobResult.rows.length === 0) return res.status(404).json({ error: "Job not found" });
    const concreteResult = await pool.query("SELECT invoice_number, supplier, delivery_date, yards, cost FROM concrete_deliveries WHERE job_id = $1 ORDER BY delivery_date DESC", [req.params.id]);
    const dailyResult = await pool.query("SELECT delivery_date as date, supplier as activity, yards, cost FROM concrete_deliveries WHERE job_id = $1 ORDER BY delivery_date DESC", [req.params.id]);
    res.json({ job: jobResult.rows[0], concrete: concreteResult.rows, daily: dailyResult.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/jobs/:id/estimate
app.put("/api/jobs/:id/estimate", async (req, res) => {
  const { income, planned_materials, planned_labor, planned_overhead } = req.body;
  try {
    const result = await pool.query("UPDATE jobs SET income = $1, planned_materials = $2, planned_labor = $3, planned_overhead = $4 WHERE id = $5 RETURNING id", [income, planned_materials, planned_labor, planned_overhead, req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Job not found" });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/job-costs - Add overhead/misc cost to a job
app.post("/api/job-costs", async (req, res) => {
  try {
    const { job_id, cost_date, vendor, category, description, amount } = req.body;
    const result = await pool.query(
      "INSERT INTO job_costs (job_id, cost_date, vendor, category, description, amount) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
      [job_id, cost_date || new Date(), vendor, category, description, amount]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/change-orders - Add change order to a job
app.post("/api/change-orders", async (req, res) => {
  try {
    const { job_id, description, amount, approved_date } = req.body;

    // First check if change_orders table exists, create if not
    await pool.query(`
      CREATE TABLE IF NOT EXISTS job_change_orders (
        id SERIAL PRIMARY KEY,
        job_id INTEGER REFERENCES jobs(id),
        co_number VARCHAR(50),
        description TEXT,
        amount DECIMAL(12,2),
        co_date DATE,
        approved_by VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Get the next change order number for this job
    const coCountResult = await pool.query(
      "SELECT COUNT(*) as count FROM job_change_orders WHERE job_id = $1",
      [job_id]
    );
    const coNumber = `CO-${parseInt(coCountResult.rows[0].count) + 1}`;

    const result = await pool.query(
      "INSERT INTO job_change_orders (job_id, co_number, description, amount, co_date) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [job_id, coNumber, description, amount, approved_date || new Date()]
    );

    // Update job income to include change order amount
    await pool.query(
      "UPDATE jobs SET income = COALESCE(income, 0) + $1 WHERE id = $2",
      [amount, job_id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error adding change order:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/job-costing-full
app.get("/api/job-costing-full", async (req, res) => {
  try {
    const { from, to } = req.query;

    // Build date filter conditions for each subquery
    let concreteWhere = '';
    let laborWhere = '';
    let costsWhere = '';
    const params = [];

    if (from) {
      params.push(from);
      concreteWhere = ` WHERE delivery_date >= $${params.length}`;
      laborWhere = ` WHERE dr.record_date >= $${params.length}`;
      costsWhere = ` WHERE cost_date >= $${params.length}`;
    }
    if (to) {
      params.push(to);
      const connector = from ? ' AND' : ' WHERE';
      concreteWhere += `${connector} delivery_date <= $${params.length}`;
      laborWhere += `${connector} dr.record_date <= $${params.length}`;
      costsWhere += `${connector} cost_date <= $${params.length}`;
    }

    const result = await pool.query(`
      SELECT
        j.id, j.job_number, j.job_name, j.contractor_name, j.status,
        j.income,
        COALESCE(concrete.yards, 0) as concrete_yards,
        COALESCE(concrete.cost, 0) as concrete_cost,
        COALESCE(labor.hours, 0) as labor_hours,
        COALESCE(labor.cost, 0) as labor_cost,
        COALESCE(costs.total, 0) as other_costs
      FROM jobs j
      LEFT JOIN (
        SELECT job_id, SUM(cubic_yards) as yards, SUM(total_cost) as cost
        FROM concrete_deliveries${concreteWhere}
        GROUP BY job_id
      ) concrete ON concrete.job_id = j.id
      LEFT JOIN (
        SELECT dr.job_id, SUM(wh.hours_worked) as hours, SUM(wh.hours_worked * COALESCE(wh.labor_rate, 25)) as cost
        FROM worker_hours wh
        JOIN daily_records dr ON wh.daily_record_id = dr.id${laborWhere}
        GROUP BY dr.job_id
      ) labor ON labor.job_id = j.id
      LEFT JOIN (
        SELECT job_id, SUM(amount) as total
        FROM job_costs${costsWhere}
        GROUP BY job_id
      ) costs ON costs.job_id = j.id
      ORDER BY j.status ASC, j.job_number DESC
    `, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get job running totals (for daily record form)
app.get("/api/public/jobs/:jobId/totals", async (req, res) => {
  try {
    const { jobId } = req.params;

    // Get total yards poured (from work_items where item is concrete/yards)
    const yardsResult = await pool.query(`
      SELECT COALESCE(SUM(wi.quantity), 0) as total_yards
      FROM work_items wi
      JOIN daily_records dr ON wi.daily_record_id = dr.id
      JOIN items i ON wi.item_id = i.id
      WHERE dr.job_id = $1
        AND (LOWER(i.unit_of_measure) LIKE '%yard%' OR LOWER(i.name) LIKE '%concrete%' OR LOWER(i.name) LIKE '%pour%')
    `, [jobId]);

    // Get total hours logged
    const hoursResult = await pool.query(`
      SELECT COALESCE(SUM(wh.hours_worked), 0) as total_hours,
             COUNT(DISTINCT wh.worker_id) as unique_workers
      FROM worker_hours wh
      JOIN daily_records dr ON wh.daily_record_id = dr.id
      WHERE dr.job_id = $1
    `, [jobId]);

    // Get daily records count
    const recordsResult = await pool.query(
      'SELECT COUNT(*) as record_count FROM daily_records WHERE job_id = $1',
      [jobId]
    );

    res.json({
      total_yards: parseFloat(yardsResult.rows[0].total_yards) || 0,
      total_hours: parseFloat(hoursResult.rows[0].total_hours) || 0,
      unique_workers: parseInt(hoursResult.rows[0].unique_workers) || 0,
      record_count: parseInt(recordsResult.rows[0].record_count) || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get today's scheduled jobs with crew info
app.get("/api/public/schedule/today", async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const result = await pool.query(`
      SELECT js.*, j.job_number, j.job_name, j.location, j.contractor_name,
             cl.name as crew_lead_name, cl.color,
             (SELECT COUNT(*) FROM daily_records dr WHERE dr.job_id = j.id AND dr.record_date = $1) as has_record
      FROM job_schedule js
      LEFT JOIN jobs j ON js.job_id = j.id
      LEFT JOIN crew_leads cl ON js.crew_lead_id = cl.id
      WHERE js.scheduled_date = $1
      ORDER BY j.job_number
    `, [today]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get crew scheduled for a job on a specific date
app.get("/api/public/jobs/:jobId/crew/:date", async (req, res) => {
  try {
    const { jobId, date } = req.params;

    // Get the crew lead from schedule
    const scheduleResult = await pool.query(`
      SELECT cl.id as crew_lead_id, cl.name as crew_lead_name, cl.color
      FROM job_schedule js
      JOIN crew_leads cl ON js.crew_lead_id = cl.id
      WHERE js.job_id = $1 AND js.scheduled_date = $2
    `, [jobId, date]);

    // Get workers who have logged time on this job before (likely crew members)
    const workersResult = await pool.query(`
      SELECT DISTINCT w.id, w.full_name, w.role,
             COUNT(wh.id) as times_worked
      FROM workers w
      JOIN worker_hours wh ON w.id = wh.worker_id
      JOIN daily_records dr ON wh.daily_record_id = dr.id
      WHERE dr.job_id = $1
      GROUP BY w.id, w.full_name, w.role
      ORDER BY times_worked DESC
      LIMIT 10
    `, [jobId]);

    res.json({
      crew_lead: scheduleResult.rows[0] || null,
      suggested_workers: workersResult.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get current weather
app.get("/api/public/weather", async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const weather = await fetchWeather(today);
    res.json(weather);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Schedule endpoints
app.get("/api/public/schedule", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT js.*, j.job_number, j.job_name, j.location, cl.name as crew_lead_name, cl.color
      FROM job_schedule js
      LEFT JOIN jobs j ON js.job_id = j.id
      LEFT JOIN crew_leads cl ON js.crew_lead_id = cl.id
      ORDER BY js.scheduled_date DESC
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/public/schedule", async (req, res) => {
  try {
    const { job_id, crew_lead_id, scheduled_date, notes } = req.body;
    const result = await pool.query(
      "INSERT INTO job_schedule (job_id, crew_lead_id, scheduled_date, notes) VALUES ($1, $2, $3, $4) RETURNING *",
      [job_id, crew_lead_id, scheduled_date, notes]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update schedule entry
app.put("/api/public/schedule/:id", async (req, res) => {
  try {
    const { crew_lead_id, scheduled_date, notes, job_id } = req.body;

    // Build dynamic update query based on provided fields
    const updates = [];
    const values = [];
    let paramIndex = 1;

    if (scheduled_date !== undefined) {
      updates.push(`scheduled_date = $${paramIndex++}`);
      values.push(scheduled_date);
    }
    if (crew_lead_id !== undefined) {
      updates.push(`crew_lead_id = $${paramIndex++}`);
      values.push(crew_lead_id || null);
    }
    if (notes !== undefined) {
      updates.push(`notes = $${paramIndex++}`);
      values.push(notes);
    }
    if (job_id !== undefined) {
      updates.push(`job_id = $${paramIndex++}`);
      values.push(job_id);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.params.id);
    const result = await pool.query(
      `UPDATE job_schedule SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Schedule entry not found' });
    }
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete schedule entry
app.delete("/api/public/schedule/:id", async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM job_schedule WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Schedule entry not found' });
    }
    res.json({ success: true, deleted: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Run migrations on startup
(async () => {
    try {
        // Add qb_estimate_id column to jobs if it doesn't exist
        await pool.query(`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS qb_estimate_id TEXT;`);

        // Add progress tracking to job_takeoffs
        await pool.query(`ALTER TABLE job_takeoffs ADD COLUMN IF NOT EXISTS quantity_completed DECIMAL(12,2) DEFAULT 0;`);
        await pool.query(`ALTER TABLE job_takeoffs ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending';`);
        await pool.query(`ALTER TABLE job_takeoffs ADD COLUMN IF NOT EXISTS unit VARCHAR(20) DEFAULT 'EA';`);
        await pool.query(`ALTER TABLE job_takeoffs ADD COLUMN IF NOT EXISTS unit_cost DECIMAL(10,2) DEFAULT 0;`);
        await pool.query(`ALTER TABLE job_takeoffs ADD COLUMN IF NOT EXISTS item_name VARCHAR(255);`);

        // Add foreman_id to workers for crew assignments
        await pool.query(`ALTER TABLE workers ADD COLUMN IF NOT EXISTS foreman_id INTEGER REFERENCES crew_leads(id);`);

        // Create job_plans table for PDF storage
        await pool.query(`
            CREATE TABLE IF NOT EXISTS job_plans (
                id SERIAL PRIMARY KEY,
                job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
                file_path TEXT NOT NULL,
                file_name VARCHAR(255),
                page_count INTEGER DEFAULT 1,
                uploaded_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Create plan_annotations table for PDF markup
        await pool.query(`
            CREATE TABLE IF NOT EXISTS plan_annotations (
                id SERIAL PRIMARY KEY,
                plan_id INTEGER REFERENCES job_plans(id) ON DELETE CASCADE,
                page_number INTEGER DEFAULT 1,
                annotation_data JSONB NOT NULL,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Create production_logs table for tracking daily production
        await pool.query(`
            CREATE TABLE IF NOT EXISTS production_logs (
                id SERIAL PRIMARY KEY,
                job_id INTEGER NOT NULL,
                takeoff_id INTEGER,
                quantity_done DECIMAL(12,2) NOT NULL,
                log_date DATE NOT NULL DEFAULT CURRENT_DATE,
                notes TEXT,
                logged_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Create daily_record_production table for production items from daily records
        await pool.query(`
            CREATE TABLE IF NOT EXISTS daily_record_production (
                id SERIAL PRIMARY KEY,
                daily_record_id INTEGER REFERENCES daily_records(id) ON DELETE CASCADE,
                job_id INTEGER NOT NULL,
                item_name VARCHAR(255) NOT NULL,
                quantity DECIMAL(12,2) NOT NULL,
                unit VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Add yards_poured column to daily_records if it doesn't exist
        await pool.query(`
            ALTER TABLE daily_records ADD COLUMN IF NOT EXISTS yards_poured DECIMAL(12,2) DEFAULT 0;
        `);

        console.log('Database migrations complete');
    } catch (e) {
        console.log('Migration note:', e.message);
    }
})();

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
