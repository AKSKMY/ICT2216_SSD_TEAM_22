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

-- Users (IDs start from 1) (Password is all 'admin')
INSERT INTO `rbac`.`user` (`username`, `email`, `password`)
VALUES 
    ('alice', 'alice@example.com', 'scrypt:32768:8:1$3v6Hg0W8aXSeMfNt$59018d7c2e74c5803e0e3227386785d29b6d9b5bdedd4a8064c2c8a4fc59f1f66e7201ffdd5c1d3fd21d0c2706024e4416887c08245873c550d1b5709eb3c799'),  -- ID = 1
    ('bob', 'bob@example.com', 'scrypt:32768:8:1$3v6Hg0W8aXSeMfNt$59018d7c2e74c5803e0e3227386785d29b6d9b5bdedd4a8064c2c8a4fc59f1f66e7201ffdd5c1d3fd21d0c2706024e4416887c08245873c550d1b5709eb3c799'),      -- ID = 2
    ('carol', 'carol@example.com', 'scrypt:32768:8:1$3v6Hg0W8aXSeMfNt$59018d7c2e74c5803e0e3227386785d29b6d9b5bdedd4a8064c2c8a4fc59f1f66e7201ffdd5c1d3fd21d0c2706024e4416887c08245873c550d1b5709eb3c799'),  -- ID = 3
    ('david', 'david@example.com', 'scrypt:32768:8:1$3v6Hg0W8aXSeMfNt$59018d7c2e74c5803e0e3227386785d29b6d9b5bdedd4a8064c2c8a4fc59f1f66e7201ffdd5c1d3fd21d0c2706024e4416887c08245873c550d1b5709eb3c799');  -- ID = 4

-- Patients (tie patient_id = user_id = 1)
INSERT INTO `rbac`.`patient` (`patient_id`, `first_name`, `last_name`, `age`, `gender`, `data_of_birth`)
VALUES (1, 'Alice', 'Johnson', 30, 'Female', '1994-01-01');

-- Doctors (user_id = 2)
INSERT INTO `rbac`.`doctor` (`doctor_id`, `first_name`, `last_name`, `age`, `gender`)
VALUES (2, 'Bob', 'Smith', 45, 'Male');

-- Nurses (user_id = 3)
INSERT INTO `rbac`.`nurse` (`nurse_id`, `first_name`, `last_name`, `age`, `gender`)
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

-- Re-enable FK checks
SET FOREIGN_KEY_CHECKS = 1;
