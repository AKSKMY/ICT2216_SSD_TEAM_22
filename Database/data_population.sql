-- Disable FK checks to avoid constraint issues during reset
SET FOREIGN_KEY_CHECKS = 0;

-- TRUNCATE tables and reset auto_increment
TRUNCATE TABLE `rbac`.`user`;
TRUNCATE TABLE `rbac`.`role`;
TRUNCATE TABLE `rbac`.`permission`;
TRUNCATE TABLE `rbac`.`userrole`;
TRUNCATE TABLE `rbac`.`rolepermission`;
TRUNCATE TABLE `rbac`.`patient`;
TRUNCATE TABLE `rbac`.`doctor`;
TRUNCATE TABLE `rbac`.`nurse`;
TRUNCATE TABLE `rbac`.`medical_record`;
TRUNCATE TABLE `critical`.`kek`;
TRUNCATE TABLE `critical`.`admin_encryption_key`;
TRUNCATE TABLE `critical`.`doctor_priv_key`;
TRUNCATE TABLE `critical`.`patient_encryption_key`;
-- Users (IDs start from 1) (Password is all 'admin')
INSERT INTO `rbac`.`user` (`username`, `email`, `password`, `salt`)
VALUES 
    ('alice', 'alice@example.com', '$2b$12$N5Kdp9OPLeDn1qPpf6gJzeUy.EudyvTSitjwrtDuWCzKWFCTwbfXG', '$2b$12$N5Kdp9OPLeDn1qPpf6gJze'), -- ID = 1 (patient)
    ('bob', 'bob@example.com', '$2b$12$0WxzutQqA.kDgEC/YGodkuzNi0MDJ4QEffJKbA9gQ1m97b2KNfrri', '$2b$12$0WxzutQqA.kDgEC/YGodku'),     -- ID = 2 (doctor)
    ('carol', 'carol@example.com', '$2b$12$gFb0jF/j1yTz07wX5xO6COiQvGGJk5HL7ALlxvjk/iWzFQbSU5PDi', '$2b$12$gFb0jF/j1yTz07wX5xO6CO'), -- ID = 3 (nurse)
    ('david', 'david@example.com', '$2b$12$.WWWVSzseRtqNbLuuuyRpeu1uP6QRDqjZcwPJLnnM.8EngHPMEX6C', '$2b$12$.WWWVSzseRtqNbLuuuyRpe'); -- ID = 4 (admin)


-- Patients (tie patient_id = user_id = 1)
INSERT INTO `rbac`.`patient` (`user_Id`, `first_name`, `last_name`, `age`, `gender`, `data_of_birth`)
VALUES (1, 'Alice', 'Johnson', 30, 'Female', '1994-01-01');

-- Doctors (user_id = 2)
INSERT INTO `rbac`.`doctor` (`user_Id`, `first_name`, `last_name`, `age`, `gender`)
VALUES (2, 'Bob', 'Smith', 45, 'Male');

-- Nurses (user_id = 3)
INSERT INTO `rbac`.`nurse` (`user_Id`, `first_name`, `last_name`, `age`, `gender`)
VALUES (3, 'Carol', 'White', 28, 'Female');

-- Roles (IDs start from 1)
INSERT INTO `rbac`.`role` (`role_name`)
VALUES 
    ('Patient'), 
    ('Doctor'), 
    ('Nurse'), 
    ('Admin');

-- Permissions (IDs start from 1)
INSERT INTO `rbac`.`permission` (`permission_name`)
VALUES 
    ('View Medical Records'),       -- ID = 1
    ('Edit Medical Records'),       -- ID = 2
    ('Prescribe Medication'),       -- ID = 3
    ('Manage Users');               -- ID = 4

-- Role-Permission Mapping
-- Patient (Role 1): View only
INSERT INTO `rbac`.`rolepermission` (`role_Id`, `permission_Id`) 
VALUES (1, 1);

-- Doctor (Role 2): View, Edit, Prescribe
INSERT INTO `rbac`.`rolepermission` (`role_Id`, `permission_Id`)
VALUES (2, 1), (2, 2), (2, 3);

-- Nurse (Role 3): View only
INSERT INTO `rbac`.`rolepermission` (`role_Id`, `permission_Id`) 
VALUES (3, 1);

-- Admin (Role 4): Manage Users only
INSERT INTO `rbac`.`rolepermission` (`role_Id`, `permission_Id`) 
VALUES (4, 4);

-- User-Role Mapping
INSERT INTO `rbac`.`userrole` (`user_Id`, `role_Id`)
VALUES 
    (1, 1),  -- Alice → Patient
    (2, 2),  -- Bob → Doctor
    (3, 3),  -- Carol → Nurse
    (4, 4);  -- David → Admin

-- Example: Medical Record (for Alice, by Bob)
INSERT INTO `rbac`.`medical_record` (`patient_id`, `diagnosis`, `doctor_id`, `date`)
VALUES (1, 'Flu', 2, '2024-12-01');

-- Encrypted KEK values
ALTER TABLE `critical`.`kek` AUTO_INCREMENT = 1;
INSERT INTO `critical`.`kek` (`label`, `kek_value`)
VALUES
  ('patient', 'P4lTSvE+LJJHwD3wzZeaZrMlpUMgC5DOITooC7yOcNJDBLpabRlHJ7V92RnjvU4futbr0mOqICaGreTZ'),
  ('doctor',  'G+Gt+DsxyYC160938qNKAOxpKsRtIfVrAZ/oo3pnqo0fruMp3IL3FrAYJPylTF8XSsXBP70hw1axZVpX'),
  ('admin',   'qoLLmn6YUgqiRyGILp117bXm1TkZmm4cyYc/t6j81q2U80iswxiZ+umhVCcpVp6MLWn3KM/GW/jb9FAi');
INSERT INTO `critical`.patient_encryption_key
VALUES
	(1, 'H86iZFvFvr64SQH06reDhVvJmYyZph8sOTXtAOMW5AxHuWlmPU7JWtFJljhaVmU0UpqMGOb5el9dsbq4', 1);
INSERT INTO `critical`.doctor_priv_key
VALUES
	(2, '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',2);
INSERT INTO `critical`.admin_encryption_key
VALUES
	(4, 'veT5z4a/luOhvkyfH8P0UJ8I0mO1wxE8u/ZOSnct4lZ/IWZ1vl1Ssm1fk1d+foVYR0UerseSrXEQLPgu', 3);
SELECT * FROM `critical`.`kek`;
-- Re-enable FK checks
SET FOREIGN_KEY_CHECKS = 1;
