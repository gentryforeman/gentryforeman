const fs = require('fs');
const { Pool } = require('pg');

const pool = new Pool({
  user: 'gentryboswell',
  host: 'localhost',
  database: 'foreman_system',
  port: 5432,
});

async function importData() {
  try {
    console.log('Reading data files...');
    
    const workersData = JSON.parse(fs.readFileSync('./workers.txt', 'utf8'));
    const jobsData = JSON.parse(fs.readFileSync('./jobs.txt', 'utf8'));
    
    const workers = workersData.Data.Response.List;
    const jobs = jobsData.Data.Response.List;
    
    console.log('Found ' + workers.length + ' workers, ' + jobs.length + ' jobs');
    
    console.log('Importing workers...');
    let wCount = 0;
    for (const w of workers) {
      try {
        await pool.query(
          "INSERT INTO workers (full_name, role, contact_info) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
          [w.fullName, w.craftName || 'Laborer', w.phone || '']
        );
        wCount++;
      } catch (err) {}
    }
    console.log('  Imported ' + wCount + ' workers');
    
    console.log('Importing jobs...');
    let jCount = 0;
    for (const j of jobs) {
      try {
        const status = j.status === 'Active' ? 'active' : 'closed';
        await pool.query(
          "INSERT INTO jobs (job_number, job_name, location, contractor_name, status, start_date, end_date, income) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
          [j.purchaseOrderNumber || '', j.jobName, j.address || '', j.clientName || '', status, 
           j.startDate ? j.startDate.split('T')[0] : null, j.endDate ? j.endDate.split('T')[0] : null, j.contractAmount || null]
        );
        jCount++;
      } catch (err) {}
    }
    console.log('  Imported ' + jCount + ' jobs');
    
    console.log('\n=== Import Complete ===');
    const r1 = await pool.query('SELECT COUNT(*) FROM jobs');
    const r2 = await pool.query('SELECT COUNT(*) FROM workers');
    console.log('Total jobs: ' + r1.rows[0].count);
    console.log('Total workers: ' + r2.rows[0].count);
    
  } catch (err) {
    console.error('Error:', err);
  } finally {
    await pool.end();
  }
}

importData();
