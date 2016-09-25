CREATE TABLE users (
  user_id serial PRIMARY KEY,
  username text UNIQUE,
  password varchar(60),
  email text
);

CREATE TABLE items (
  username text,
  item_id serial,
  item_name text,
  item_desc text,
  item_price decimal(9,2),
  item_image text,
  item_store text,
  CONSTRAINT item_pk PRIMARY KEY(username, item_id),
  CONSTRAINT user_fk FOREIGN KEY (username) REFERENCES users(username)
);
