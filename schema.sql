-

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY,
    name VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Events raw table
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
);

-- Indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_events_raw_project_id ON events_raw(project_id);
CREATE INDEX IF NOT EXISTS idx_events_raw_event_ts ON events_raw(event_ts);
CREATE INDEX IF NOT EXISTS idx_events_raw_anonymous_id ON events_raw(anonymous_id);
CREATE INDEX IF NOT EXISTS idx_events_raw_session_id ON events_raw(session_id);
CREATE INDEX IF NOT EXISTS idx_events_raw_user_id ON events_raw(user_id);

-- Insert a sample project for testing (replace with your actual project UUID)
-- INSERT INTO projects (id, name, is_active) VALUES ('11111111-1111-1111-1111-111111111111', 'Test Project', true);



-- آخر أحداث وصلت للسيرفر خلال آخر 15 دقيقة (وهون ما بهمنا event_ts)

-- آخر 20 حدث
select event_name, event_ts, received_at, project_id, page_path, user_id
from events_raw
order by received_at desc
limit 20;

-- كم حدث بالدقيقة آخر 10 دقائق
select date_trunc('minute', received_at) as m, count(*)
from events_raw
where received_at > now() - interval '10 minutes'
group by 1
order by 1 desc;

select event_name, count(*) from events_raw group by 1 order by 2 desc;

-- End of schema.sql

-- شو المفاتيح الموجودة داخل properties لحدث معيّن؟
select
  k as property_key,
  count(*) as cnt
from events_raw
cross join lateral jsonb_object_keys(coalesce(properties,'{}'::jsonb)) as k
where project_id = 'd2f3a4b5-c6d7-4e8f-9a0b-6c5d4e3f2a66'
  and event_name = 'card_click'
group by 1
order by 2 desc
limit 50;


select received_at, event_name, page_path, properties
from events_raw
where project_id = 'd2f3a4b5-c6d7-4e8f-9a0b-6c5d4e3f2a66'
  and event_name in ('card_impression','card_click','ad_impression','ad_viewable','search','search_result_click','checkout','error')
order by received_at desc
limit 20;

select received_at, event_name, page_url, page_path
from events_raw
where project_id = 'd2f3a4b5-c6d7-4e8f-9a0b-6c5d4e3f2a66'
  and received_at >= now() - interval '10 minutes'
order by received_at desc
limit 100;
