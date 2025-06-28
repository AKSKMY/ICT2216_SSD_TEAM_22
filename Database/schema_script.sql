-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------
-- -----------------------------------------------------
-- Schema rbac
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema rbac
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `rbac` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci ;
USE `rbac` ;

-- -----------------------------------------------------
-- Table `rbac`.`user`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`user` ;

CREATE TABLE IF NOT EXISTS `rbac`.`user` (
  `user_Id` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(255) NOT NULL,
  `email` VARCHAR(45) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `salt` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`user_Id`))
ENGINE = InnoDB
AUTO_INCREMENT = 9
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `rbac`.`audit_log`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`audit_log` ;

CREATE TABLE IF NOT EXISTS `rbac`.`audit_log` (
  `log_id` INT NOT NULL AUTO_INCREMENT,
  `user_Id` INT NULL DEFAULT NULL,
  `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `description` TEXT NOT NULL,
  PRIMARY KEY (`log_id`),
  CONSTRAINT `fk_auditlog_user_Id`
    FOREIGN KEY (`user_Id`)
    REFERENCES `rbac`.`user` (`user_Id`)
    ON DELETE CASCADE)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;

CREATE INDEX `fk_auditlog_user_Id` ON `rbac`.`audit_log` (`user_Id` ASC) VISIBLE;


-- -----------------------------------------------------
-- Table `rbac`.`doctor`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`doctor` ;

CREATE TABLE IF NOT EXISTS `rbac`.`doctor` (
  `user_Id` INT NOT NULL AUTO_INCREMENT,
  `first_name` VARCHAR(45) NULL DEFAULT NULL,
  `last_name` VARCHAR(45) NULL DEFAULT NULL,
  `age` INT NULL DEFAULT NULL,
  `gender` VARCHAR(45) NULL DEFAULT NULL,
  PRIMARY KEY (`user_Id`),
  CONSTRAINT `fk_user_doctor_Id`
    FOREIGN KEY (`user_Id`)
    REFERENCES `rbac`.`user` (`user_Id`))
ENGINE = InnoDB
AUTO_INCREMENT = 3
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `rbac`.`patient`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`patient` ;

CREATE TABLE IF NOT EXISTS `rbac`.`patient` (
  `user_Id` INT NOT NULL AUTO_INCREMENT,
  `first_name` VARCHAR(45) NULL DEFAULT NULL,
  `last_name` VARCHAR(45) NULL DEFAULT NULL,
  `age` INT NULL DEFAULT NULL,
  `gender` VARCHAR(45) NULL DEFAULT NULL,
  `data_of_birth` DATE NULL DEFAULT NULL,
  PRIMARY KEY (`user_Id`),
  CONSTRAINT `fk_user_patient_Id`
    FOREIGN KEY (`user_Id`)
    REFERENCES `rbac`.`user` (`user_Id`))
ENGINE = InnoDB
AUTO_INCREMENT = 2
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `rbac`.`medical_record`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`medical_record` ;

CREATE TABLE IF NOT EXISTS `rbac`.`medical_record` (
  `record_id` INT NOT NULL AUTO_INCREMENT,
  `patient_id` INT NULL DEFAULT NULL,
  `diagnosis` VARCHAR(255) NULL DEFAULT NULL,
  `doctor_id` INT NULL DEFAULT NULL,
  `date` DATE NULL DEFAULT NULL,
  `digital_signature` TEXT NULL DEFAULT NULL,
  PRIMARY KEY (`record_id`),
  CONSTRAINT `fk_doctor_Id`
    FOREIGN KEY (`doctor_id`)
    REFERENCES `rbac`.`doctor` (`user_Id`),
  CONSTRAINT `fk_patient_Id`
    FOREIGN KEY (`patient_id`)
    REFERENCES `rbac`.`patient` (`user_Id`))
ENGINE = InnoDB
AUTO_INCREMENT = 2
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;

CREATE INDEX `fk_doctor_Id_idx` ON `rbac`.`medical_record` (`doctor_id` ASC) VISIBLE;

CREATE INDEX `fk_patient_Id_idx` ON `rbac`.`medical_record` (`patient_id` ASC) VISIBLE;


-- -----------------------------------------------------
-- Table `rbac`.`nurse`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`nurse` ;

CREATE TABLE IF NOT EXISTS `rbac`.`nurse` (
  `user_Id` INT NOT NULL AUTO_INCREMENT,
  `first_name` VARCHAR(45) NULL DEFAULT NULL,
  `last_name` VARCHAR(45) NULL DEFAULT NULL,
  `age` INT NULL DEFAULT NULL,
  `gender` VARCHAR(45) NULL DEFAULT NULL,
  PRIMARY KEY (`user_Id`),
  CONSTRAINT `fk_user_nurse_Id`
    FOREIGN KEY (`user_Id`)
    REFERENCES `rbac`.`user` (`user_Id`))
ENGINE = InnoDB
AUTO_INCREMENT = 4
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `rbac`.`permission`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`permission` ;

CREATE TABLE IF NOT EXISTS `rbac`.`permission` (
  `permission_Id` INT NOT NULL AUTO_INCREMENT,
  `permission_name` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`permission_Id`))
ENGINE = InnoDB
AUTO_INCREMENT = 5
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `rbac`.`role`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`role` ;

CREATE TABLE IF NOT EXISTS `rbac`.`role` (
  `role_Id` INT NOT NULL AUTO_INCREMENT,
  `role_name` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`role_Id`))
ENGINE = InnoDB
AUTO_INCREMENT = 5
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `rbac`.`rolepermission`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`rolepermission` ;

CREATE TABLE IF NOT EXISTS `rbac`.`rolepermission` (
  `role_Id` INT NOT NULL,
  `permission_Id` INT NOT NULL,
  PRIMARY KEY (`role_Id`, `permission_Id`),
  CONSTRAINT `rolepermission_ibfk_1`
    FOREIGN KEY (`role_Id`)
    REFERENCES `rbac`.`role` (`role_Id`),
  CONSTRAINT `rolepermission_ibfk_2`
    FOREIGN KEY (`permission_Id`)
    REFERENCES `rbac`.`permission` (`permission_Id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;

CREATE INDEX `permission_Id` ON `rbac`.`rolepermission` (`permission_Id` ASC) VISIBLE;


-- -----------------------------------------------------
-- Table `rbac`.`userrole`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rbac`.`userrole` ;

CREATE TABLE IF NOT EXISTS `rbac`.`userrole` (
  `user_Id` INT NOT NULL,
  `role_Id` INT NOT NULL,
  PRIMARY KEY (`user_Id`, `role_Id`),
  CONSTRAINT `userrole_ibfk_1`
    FOREIGN KEY (`user_Id`)
    REFERENCES `rbac`.`user` (`user_Id`),
  CONSTRAINT `userrole_ibfk_2`
    FOREIGN KEY (`role_Id`)
    REFERENCES `rbac`.`role` (`role_Id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;

CREATE INDEX `role_Id` ON `rbac`.`userrole` (`role_Id` ASC) VISIBLE;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
