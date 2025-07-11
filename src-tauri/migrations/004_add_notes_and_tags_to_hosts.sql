-- Add notes column to the 'hosts' table
ALTER TABLE hosts ADD COLUMN notes TEXT;

-- Add tags column to the 'hosts' table
ALTER TABLE hosts ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';