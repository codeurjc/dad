-- Esperamos a que el master esté listo (esto lo gestiona el driver/script)
CHANGE MASTER TO 
  MASTER_HOST='mysql-master',
  MASTER_USER='repl_user',
  MASTER_PASSWORD='repl_pass',
  MASTER_LOG_FILE='mysql-bin.000001',
  MASTER_LOG_POS=4;
START SLAVE;