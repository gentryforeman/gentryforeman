-- FOREMAN SYSTEM DATABASE SCHEMA

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL, -- 'admin', 'foreman', 'office'
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'inactive'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Crew Leads table
CREATE TABLE crew_leads (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    color VARCHAR(7) NOT NULL, -- hex color code like '#FF5733'
    user_id INTEGER REFERENCES users(id),
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Jobs table
CREATE TABLE jobs (
    id SERIAL PRIMARY KEY,
    job_number VARCHAR(100) UNIQUE NOT NULL,
    job_name VARCHAR(255) NOT NULL,
    location TEXT,
    contractor_name VARCHAR(255),
    crew_lead_id INTEGER REFERENCES crew_leads(id),
    status VARCHAR(50) DEFAULT 'active', -- 'active', 'completed', 'on_hold'
    start_date DATE,
    end_date DATE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Workers table
CREATE TABLE workers (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    role VARCHAR(100), -- 'foreman', 'laborer', etc
    contact_info TEXT,
    hire_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Items master list table
CREATE TABLE items (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    unit_of_measure VARCHAR(50), -- 'CYD', 'SF', 'MLF', 'Each', etc
    category VARCHAR(100), -- 'material', 'labor', 'equipment'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Daily records table
CREATE TABLE daily_records (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
    foreman_id INTEGER REFERENCES workers(id),
    record_date DATE NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Work items (materials/tasks used on jobs)
CREATE TABLE work_items (
    id SERIAL PRIMARY KEY,
    daily_record_id INTEGER REFERENCES daily_records(id) ON DELETE CASCADE,
    item_id INTEGER REFERENCES items(id),
    quantity DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Worker hours table
CREATE TABLE worker_hours (
    id SERIAL PRIMARY KEY,
    daily_record_id INTEGER REFERENCES daily_records(id) ON DELETE CASCADE,
    worker_id INTEGER REFERENCES workers(id),
    hours_worked DECIMAL(5,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Concrete suppliers table
CREATE TABLE concrete_suppliers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    contact_info TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Concrete deliveries table (THE NEW FEATURE!)
CREATE TABLE concrete_deliveries (
    id SERIAL PRIMARY KEY,
    invoice_number VARCHAR(100) UNIQUE NOT NULL,
    supplier_id INTEGER REFERENCES concrete_suppliers(id),
    job_id INTEGER REFERENCES jobs(id),
    delivery_date DATE NOT NULL,
    cubic_yards DECIMAL(10,2) NOT NULL,
    cost_per_yard DECIMAL(10,2),
    total_cost DECIMAL(10,2),
    invoice_pdf_path TEXT,
    status VARCHAR(50) DEFAULT 'unmatched', -- 'unmatched', 'matched', 'verified'
    matched_by_user_id INTEGER REFERENCES users(id),
    matched_at TIMESTAMP,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Files/photos table
CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
    daily_record_id INTEGER REFERENCES daily_records(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    file_type VARCHAR(50),
    uploaded_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_crew_lead ON jobs(crew_lead_id);
CREATE INDEX idx_daily_records_job ON daily_records(job_id);
CREATE INDEX idx_daily_records_date ON daily_records(record_date);
CREATE INDEX idx_concrete_deliveries_job ON concrete_deliveries(job_id);
CREATE INDEX idx_concrete_deliveries_status ON concrete_deliveries(status);
