BEGIN;

DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO public;
COMMENT ON SCHEMA public IS 'standard public schema';

-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- chatgpt
CREATE SEQUENCE snowflake_sequence
    START 0
    INCREMENT 1
    MINVALUE 0
    MAXVALUE 4095;  -- 12 bits, so max value is 4095

CREATE OR REPLACE FUNCTION generate_snowflake_id() RETURNS BIGINT AS $$
DECLARE
    epoch BIGINT := 1609459200000;  -- Custom epoch (e.g., 2021-01-01 00:00:00 UTC)
    timestamp_ms BIGINT;
    seq BIGINT;
    machine_id INT := 1;  -- Replace with a unique identifier for your machine or server
    snowflake_id BIGINT;
BEGIN
    -- Get the current timestamp in milliseconds
    timestamp_ms := EXTRACT(EPOCH FROM NOW()) * 1000 - epoch;

    -- Get the next value from the sequence (this is the sequence part of the ID)
    seq := nextval('snowflake_sequence');

    -- Combine all parts to generate the final Snowflake-like ID
    -- The 64-bit ID is structured as:
    -- 1 bit for sign (not used), 41 bits for timestamp, 10 bits for machine_id + 12 bits for sequence
    snowflake_id := (timestamp_ms << 22) | (machine_id << 12) | seq;

    RETURN snowflake_id;
END;
$$ LANGUAGE plpgsql;


-- TODO VARCHAR(250) -> VARCHAR(???)
CREATE TYPE gender AS ENUM ('male', 'female', 'other');

CREATE TABLE users(
  -- id UUID PRIMARY KEY DEFAULT uuid_generate_v1mc(), -- kinda too excessive
  id BIGINT PRIMARY KEY DEFAULT generate_snowflake_id(),
  name VARCHAR(250) NOT NULL,
  gender GENDER,
  date_of_birth DATE,
  profile_picture VARCHAR(250),
  email VARCHAR(254) UNIQUE, -- https://stackoverflow.com/questions/386294/what-is-the-maximum-length-of-a-valid-email-address
  email_verified BOOLEAN,
  pwhash BYTEA, -- bcrypt max length, Ignored when using oauth?
  phone_number VARCHAR(250) UNIQUE,
  phone_verified BOOLEAN,
  CHECK (email IS NOT NULL OR phone_number IS NOT NULL) -- can use either to login
);
-- postgres already creates indexes on unique columns
-- CREATE INDEX ON users(email);
-- CREATE INDEX ON users(phone_number);

CREATE TABLE instructors(
  id BIGINT PRIMARY KEY REFERENCES users(id),
  profession VARCHAR(250),
  bio TEXT,
  short_bio VARCHAR(250),
  resume VARCHAR(250), -- file path
  affiliates VARCHAR(250)[] -- facebook whatever
);

CREATE TABLE students(
  id BIGINT PRIMARY KEY REFERENCES users(id)
);

CREATE TABLE tags(
  id BIGINT PRIMARY KEY DEFAULT generate_snowflake_id(),
  name VARCHAR(250)
);
CREATE INDEX ON tags(name); -- HMMMMMM

CREATE TABLE courses(
  id BIGINT PRIMARY KEY DEFAULT generate_snowflake_id(),
  instructor_id BIGINT REFERENCES instructors(id) NOT NULL,
  title VARCHAR(250),
  -- category BIGINT REFERENCES tags(id) NOT NULL, -- main "tag"?
  -- duration BIGINT, -- in seconds
  price BIGINT,
  description TEXT
);
CREATE INDEX ON courses(instructor_id);

CREATE TABLE course_tags(
  tag_id BIGINT REFERENCES tags(id),
  course_id BIGINT REFERENCES courses(id),
  PRIMARY KEY(tag_id, course_id)
);
CREATE INDEX ON course_tags(tag_id);
CREATE INDEX ON course_tags(course_id);

-- TODO idk
CREATE TABLE course_completions(
  course_id BIGINT REFERENCES courses(id),
  student_id BIGINT REFERENCES students(id),
  certificate VARCHAR(250),
  PRIMARY KEY(course_id, student_id)
);
CREATE INDEX ON course_completions(course_id);
CREATE INDEX ON course_completions(student_id);

CREATE TABLE sessions(
  id BIGINT PRIMARY KEY DEFAULT generate_snowflake_id(),
  course_id BIGINT REFERENCES courses(id) NOT NULL,
  title VARCHAR(250),
  subtitle VARCHAR(250)
);
CREATE INDEX ON course_completions(course_id);

-- TODO idk
CREATE TABLE session_completions(
  session_id BIGINT REFERENCES sessions(id),
  student_id BIGINT REFERENCES students(id),
  PRIMARY KEY(session_id, student_id)
);
CREATE INDEX ON session_completions(student_id);

CREATE TABLE reviews(
  student_id BIGINT REFERENCES students(id) NOT NULL,
  instructor_id BIGINT REFERENCES instructors(id),
  course_id BIGINT REFERENCES courses(id),
  rating SMALLINT NOT NULL CHECK (rating BETWEEN 0 AND 5),
  review TEXT,
  PRIMARY KEY(student_id, instructor_id, course_id)
);
CREATE INDEX ON reviews(instructor_id);
CREATE INDEX ON reviews(course_id);
CREATE INDEX ON reviews(student_id);

CREATE TABLE follows(
  follower BIGINT REFERENCES users(id),
  followee BIGINT REFERENCES users(id),
  PRIMARY KEY(follower, followee)
);
CREATE INDEX ON follows(follower);
CREATE INDEX ON follows(followee);

CREATE TABLE favorites(
  user_id BIGINT REFERENCES users(id),
  course_id BIGINT REFERENCES courses(id),
  PRIMARY KEY(user_id, course_id)
);
CREATE INDEX ON favorites(user_id);

CREATE TABLE mfa_tokens(
  id BIGINT PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  purpose VARCHAR(250),
  updated_at DATE,
  expires_at DATE,
  fulfilled BOOLEAN
);

COMMIT;
