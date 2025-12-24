-- Migration: Add Job Costing, QB Import, and STACK Integration tables
-- Run this against your PostgreSQL database

-- Job Costs table (for tracking expenses from QB imports and manual entry)
CREATE TABLE IF NOT EXISTS job_costs (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES jobs(id),
    invoice_number VARCHAR(100),
    vendor VARCHAR(255),
    cost_date DATE,
    amount DECIMAL(12, 2) NOT NULL DEFAULT 0,
    description TEXT,
    category VARCHAR(100) DEFAULT 'materials', -- materials, labor, overhead, equipment, subcontractor, other
    source VARCHAR(50) DEFAULT 'manual', -- manual, qb_import
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Job Takeoffs table (for STACK integration and manual takeoff entry)
CREATE TABLE IF NOT EXISTS job_takeoffs (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES jobs(id) NOT NULL,
    item_id INTEGER REFERENCES items(id) NOT NULL,
    quantity DECIMAL(12, 2) DEFAULT 0,
    unit VARCHAR(20) DEFAULT 'EA',
    area_sqft DECIMAL(12, 2) DEFAULT 0,
    linear_ft DECIMAL(12, 2) DEFAULT 0,
    notes TEXT,
    source VARCHAR(50) DEFAULT 'manual', -- manual, stack
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(job_id, item_id)
);

-- Add labor_rate column to worker_hours if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='worker_hours' AND column_name='labor_rate') THEN
        ALTER TABLE worker_hours ADD COLUMN labor_rate DECIMAL(10, 2) DEFAULT 25.00;
    END IF;
END $$;

-- Add other_costs column to jobs for quick summary if needed
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='jobs' AND column_name='other_costs') THEN
        ALTER TABLE jobs ADD COLUMN other_costs DECIMAL(12, 2) DEFAULT 0;
    END IF;
END $$;

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_job_costs_job_id ON job_costs(job_id);
CREATE INDEX IF NOT EXISTS idx_job_costs_category ON job_costs(category);
CREATE INDEX IF NOT EXISTS idx_job_costs_cost_date ON job_costs(cost_date);
CREATE INDEX IF NOT EXISTS idx_job_takeoffs_job_id ON job_takeoffs(job_id);
CREATE INDEX IF NOT EXISTS idx_job_takeoffs_item_id ON job_takeoffs(item_id);

-- Update jobs table to add other_costs calculation trigger
CREATE OR REPLACE FUNCTION update_job_other_costs()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE jobs
    SET other_costs = (
        SELECT COALESCE(SUM(amount), 0)
        FROM job_costs
        WHERE job_id = COALESCE(NEW.job_id, OLD.job_id)
    )
    WHERE id = COALESCE(NEW.job_id, OLD.job_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_job_other_costs ON job_costs;
CREATE TRIGGER trigger_update_job_other_costs
AFTER INSERT OR UPDATE OR DELETE ON job_costs
FOR EACH ROW
EXECUTE FUNCTION update_job_other_costs();

-- Grant permissions (adjust as needed for your setup)
-- GRANT ALL PRIVILEGES ON TABLE job_costs TO your_user;
-- GRANT ALL PRIVILEGES ON TABLE job_takeoffs TO your_user;
-- GRANT USAGE, SELECT ON SEQUENCE job_costs_id_seq TO your_user;
-- GRANT USAGE, SELECT ON SEQUENCE job_takeoffs_id_seq TO your_user;

-- Sample data for testing (uncomment to use)
-- INSERT INTO job_costs (job_id, invoice_number, vendor, cost_date, amount, description, category, source)
-- VALUES
--     (1, 'INV-001', 'Home Depot', '2024-01-15', 250.00, 'Rebar and wire mesh', 'materials', 'manual'),
--     (1, 'INV-002', 'Equipment Rental Co', '2024-01-16', 500.00, 'Concrete pump rental', 'equipment', 'manual');

COMMENT ON TABLE job_costs IS 'Tracks all job-related costs from QB imports and manual entry';
COMMENT ON TABLE job_takeoffs IS 'Stores takeoff measurements from STACK and manual entry';
