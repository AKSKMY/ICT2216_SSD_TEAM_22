-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema critical
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `critical` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci ;
USE `critical` ;

-- -----------------------------------------------------
-- Table `critical`.`kek`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`kek` ;

CREATE TABLE IF NOT EXISTS `critical`.`kek` (
  `kek_id` INT NOT NULL AUTO_INCREMENT,
  `label` VARCHAR(50) NOT NULL,
  `kek_value` VARCHAR(1024) NOT NULL,
  PRIMARY KEY (`kek_id`)
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table `critical`.`patient_encryption_key`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`patient_encryption_key` ;

CREATE TABLE IF NOT EXISTS `critical`.`patient_encryption_key` (
  `patient_id` INT NOT NULL,
  `patient_AES_key` VARCHAR(255) NOT NULL,
  `kek_id` INT NOT NULL,
  PRIMARY KEY (`patient_id`),
  INDEX `fk_kek_patient_idx` (`kek_id` ASC),
  CONSTRAINT `fk_kek_patient`
    FOREIGN KEY (`kek_id`)
    REFERENCES `critical`.`kek` (`kek_id`)
    ON DELETE RESTRICT
    ON UPDATE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table `critical`.`doctor_priv_key`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`doctor_priv_key` ;

CREATE TABLE IF NOT EXISTS `critical`.`doctor_priv_key` (
  `doctor_id` INT NOT NULL,
  `private_enc_key` TEXT NOT NULL,
  `kek_id` INT NOT NULL,
  PRIMARY KEY (`doctor_id`),
  INDEX `fk_kek_doctor_idx` (`kek_id` ASC),
  CONSTRAINT `fk_kek_doctor`
    FOREIGN KEY (`kek_id`)
    REFERENCES `critical`.`kek` (`kek_id`)
    ON DELETE RESTRICT
    ON UPDATE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table `critical`.`doctor_pub_key`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`doctor_pub_key` ;

CREATE TABLE IF NOT EXISTS `critical`.`doctor_pub_key` (
  `doctor_id` INT NOT NULL,
  `public_key` TEXT NOT NULL,
  PRIMARY KEY (`doctor_id`),
  CONSTRAINT `fk_doctor_pubkey_id`
    FOREIGN KEY (`doctor_id`)
    REFERENCES `rbac`.`doctor` (`user_Id`)  -- Adjust if your doctor ID is from elsewhere
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table `critical`.`admin_encryption_key`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`admin_encryption_key` ;

CREATE TABLE IF NOT EXISTS `critical`.`admin_encryption_key` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `admin_AES_key` VARCHAR(255) NOT NULL,
  `kek_id` INT NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `fk_kek_admin_idx` (`kek_id` ASC),
  CONSTRAINT `fk_kek_admin`
    FOREIGN KEY (`kek_id`)
    REFERENCES `critical`.`kek` (`kek_id`)
    ON DELETE RESTRICT
    ON UPDATE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `critical`.`admin_encryption_key`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`admin_encryption_key` ;

CREATE TABLE IF NOT EXISTS `critical`.`admin_encryption_key` (
  `admin_id` INT NOT NULL,
  `admin_AES_key` VARCHAR(255) NOT NULL,
  `kek_id` INT NOT NULL,
  PRIMARY KEY (`admin_id`),
  INDEX `fk_kek_admin_idx` (`kek_id` ASC),
  CONSTRAINT `fk_kek_admin`
    FOREIGN KEY (`kek_id`)
    REFERENCES `critical`.`kek` (`kek_id`)
    ON DELETE RESTRICT
    ON UPDATE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `critical`.`user_sessions`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`user_sessions` ;

CREATE TABLE IF NOT EXISTS `critical`.`user_sessions` (
  `session_token` VARCHAR(255) NOT NULL,
  `user_id` INT NOT NULL,
  `ip_address` VARCHAR(45),
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `last_active` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `expires_at` DATETIME,
  PRIMARY KEY (`session_token`),
  INDEX `user_id_idx` (`user_id` ASC) VISIBLE,
  CONSTRAINT `fk_user_sessions_user`
    FOREIGN KEY (`user_id`)
    REFERENCES `rbac`.`user` (`user_Id`)
    ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;
-- Reset original settings
SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
