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
-- Table `critical`.`patient_encryption_key`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`patient_encryption_key` ;

CREATE TABLE IF NOT EXISTS `critical`.`patient_encryption_key` (
  `patient_id` INT NOT NULL,
  `patient_AES_key` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`patient_id`)
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table `critical`.`doctor_priv_key`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`doctor_priv_key` ;

CREATE TABLE IF NOT EXISTS `critical`.`doctor_priv_key` (
  `doctor_id` INT NOT NULL,
  `private_enc_key` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`doctor_id`)
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table `critical`.`audit_key`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`audit_key` ;

CREATE TABLE IF NOT EXISTS `critical`.`audit_key` (
  `log_id` INT NOT NULL,
  `admin_AES_key` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`log_id`)
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table `critical`.`medical_records_key`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `critical`.`medical_records_key` ;

CREATE TABLE IF NOT EXISTS `critical`.`medical_records_key` (
  `record_id` INT NOT NULL,
  `patient_id` INT NOT NULL,
  PRIMARY KEY (`record_id`),
  INDEX `patient_FK_idx` (`patient_id` ASC) VISIBLE,
  CONSTRAINT `patient_FK`
    FOREIGN KEY (`patient_id`)
    REFERENCES `critical`.`patient_encryption_key` (`patient_id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION
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
