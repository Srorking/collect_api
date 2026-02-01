import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

async function testConnection() {
  console.log("Testing database connection...");
  
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL
  });

  try {
    // Test connection
    const client = await pool.connect();
    console.log("✅ Database connected successfully!");
    
    // Create tables
    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id UUID PRIMARY KEY,
        name VARCHAR(255),
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);
    console.log("✅ Projects table created/verified");

    await client.query(`
      CREATE TABLE IF NOT EXISTS events_raw (
        id BIGSERIAL PRIMARY KEY,
        project_id UUID NOT NULL,
        event_name VARCHAR(255) NOT NULL,
        event_ts TIMESTAMP WITH TIME ZONE NOT NULL,
        received_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        anonymous_id VARCHAR(255),
        session_id VARCHAR(255),
        user_id VARCHAR(255),
        page_url TEXT,
        page_path TEXT,
        page_title VARCHAR(500),
        referrer TEXT,
        previous_url TEXT,
        context JSONB DEFAULT '{}',
        properties JSONB DEFAULT '{}',
        web_vitals JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);
    console.log("✅ Events_raw table created/verified");

    // Create indexes
    await client.query(`CREATE INDEX IF NOT EXISTS idx_events_raw_project_id ON events_raw(project_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_events_raw_event_ts ON events_raw(event_ts)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_events_raw_anonymous_id ON events_raw(anonymous_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_events_raw_session_id ON events_raw(session_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_events_raw_user_id ON events_raw(user_id)`);
    console.log("✅ Indexes created/verified");

    // Insert sample project for testing
    await client.query(`
      INSERT INTO projects (id, name, is_active)
      VALUES ('', 'Test Project', true)
      ON CONFLICT (id) DO NOTHING
    `);
    console.log("✅ Sample project inserted (or already exists)");

    client.release();
    await pool.end();
    
    console.log("\n🎉 Database setup completed successfully!");
  } catch (error) {
    console.error("❌ Database connection failed:", error.message);
    process.exit(1);
  }
}

testConnection();

