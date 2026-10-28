-- 1. Crear base de datos si no existe y usarla
CREATE DATABASE IF NOT EXISTS post;
USE post;

-- 2. Limpiar tablas previas para evitar errores de duplicados en la demo
DROP TABLE IF EXISTS comment;
DROP TABLE IF EXISTS post;

-- 3. Crear tabla POST (Entidad principal)
CREATE TABLE post (
    id BIGINT NOT NULL AUTO_INCREMENT,
    username VARCHAR(255),
    title VARCHAR(255) NOT NULL,
    text TEXT,
    PRIMARY KEY (id)
) ENGINE=InnoDB;

-- 4. Crear tabla COMMENT (Entidad relacionada)
CREATE TABLE comment (
    id BIGINT NOT NULL AUTO_INCREMENT,
    username VARCHAR(255),
    comment TEXT,
    post_id BIGINT,
    PRIMARY KEY (id),
    CONSTRAINT fk_post_comment FOREIGN KEY (post_id) REFERENCES post (id)
) ENGINE=InnoDB;

-- 5. Procedimiento de carga masiva optimizado
DELIMITER $$

DROP PROCEDURE IF EXISTS FastDataLoad;
CREATE PROCEDURE FastDataLoad()
BEGIN
    DECLARE i INT DEFAULT 1;
    
    -- Optimizaciones críticas de MySQL para inserción masiva
    SET FOREIGN_KEY_CHECKS = 0;
    SET UNIQUE_CHECKS = 0;
    SET AUTOCOMMIT = 0;

    WHILE i <= 100000 DO
        -- Insertar Post
        INSERT INTO post (username, title, text) 
        VALUES (
            CONCAT('User_Alpha_', i), 
            CONCAT('Producto Pro v', i), 
            CONCAT('Descripción técnica del post ', i, '. Este registro se usa para pruebas de estrés de JPA y latencia de red en topologías distribuidas.')
        );
        
        -- Para el comentario, necesitamos el ID que se acaba de generar
        SET @last_id = LAST_INSERT_ID();

        -- Insertar Comentario relacionado
        INSERT INTO comment (username, comment, post_id) 
        VALUES (
            CONCAT('User_Alpha_', i), 
            'Reseña automática generada para carga de base de datos.', 
            @last_id
        );

        -- Commit parcial cada 10.000 filas para evitar saturar el buffer
        IF (MOD(i, 10000) = 0) THEN
            COMMIT;
        END IF;
        
        SET i = i + 1;
    END WHILE;

    COMMIT;
    
    -- Restaurar configuración normal
    SET FOREIGN_KEY_CHECKS = 1;
    SET UNIQUE_CHECKS = 1;
    SET AUTOCOMMIT = 1;
END$$

DELIMITER ;

-- 6. Ejecutar la carga
CALL FastDataLoad();

-- Limpieza (Opcional)
DROP PROCEDURE IF EXISTS LoadMassiveData;