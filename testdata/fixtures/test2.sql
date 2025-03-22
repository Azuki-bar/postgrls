CREATE TABLE products (id int, name text, price int);
CREATE TABLE orders (id int, product_id int, quantity int);
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
CREATE POLICY product_policy ON products USING (true);
