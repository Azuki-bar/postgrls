CREATE TABLE accounts (id int, manager text);
CREATE TABLE users (id int, name text);
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY account_managers ON accounts USING (manager = current_user);
