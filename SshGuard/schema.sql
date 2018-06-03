DROP TABLE IF EXISTS guard;
DROP TABLE IF EXISTS log_ssh;

CREATE TABLE guard (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  sshuser  TEXT NOT NULL,
  activated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  allowed INTEGER NOT NULL
);

CREATE TABLE log_ssh (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  logtime TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  marker TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES user (id)
);
