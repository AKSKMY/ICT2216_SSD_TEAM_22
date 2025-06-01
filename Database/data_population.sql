-- Disable FK checks for safe insert order
SET FOREIGN_KEY_CHECKS = 0;

-- Users (let IDs auto-increment)
INSERT INTO `rbac`.`user` (`username`, `email`, `password`)
VALUES 
    ('alice', 'alice@example.com', 'hashedpass1'), -- will get ID = 1
    ('bob', 'bob@example.com', 'hashedpass2'),     -- ID = 2
    ('carol', 'carol@example.com', 'hashedpass3'); -- ID = 3

-- Doctors (Bob, user_id = 2)
INSERT INTO `rbac`.`doctor` (`doctor_id`, `first_name`, `last_name`, `age`, `gender`)
VALUES (2, 'Bob', 'Smith', 45, 'Male');

-- Patients (Alice, user_id = 1)
INSERT INTO `rbac`.`patient` (`patient_id`, `first_name`, `last_name`, `age`, `gender`, `data_of_birth`)
VALUES (1, 'Alice', 'Johnson', 30, 'Female', '1994-01-01');

-- Nurses (Carol, user_id = 3)
INSERT INTO `rbac`.`nurse` (`nurse_id`, `first_name`, `last_name`, `age`, `gender`)
VALUES (3, 'Carol', 'White', 28, 'Female');

-- Roles (static)
INSERT INTO `rbac`.`role` (`role_name`)
VALUES 
    ('Patient'),   -- ID = 1
    ('Doctor'),    -- ID = 2
    ('Nurse'),     -- ID = 3
    ('Admin');     -- ID = 4

-- Permissions (static)
INSERT INTO `rbac`.`permission` (`permission_name`)
VALUES 
    ('View Medical Records'),       -- ID = 1
    ('Edit Medical Records'),       -- ID = 2
    ('Prescribe Medication'),       -- ID = 3
    ('Manage Users');               -- ID = 4

-- Role-Permission Mapping
INSERT INTO `rbac`.`rolepermission` (`role_Id`, `permission_Id`)
VALUES 
    (1, 1),                    -- Patient
    (2, 1), (2, 2), (2, 3),    -- Doctor
    (3, 1),                    -- Nurse
    (4, 1), (4, 2), (4, 3), (4, 4); -- Admin

-- User-Role Mapping
INSERT INTO `rbac`.`userrole` (`user_Id`, `role_Id`)
VALUES 
    (1, 1),  -- Alice = Patient
    (2, 2),  -- Bob = Doctor
    (3, 3);  -- Carol = Nurse

-- Medical Records (auto record_id)
INSERT INTO `rbac`.`medical_record` (`patient_id`, `diagnosis`, `doctor_id`, `date`)
VALUES (1, 'Flu', 2, '2024-12-01');

SET FOREIGN_KEY_CHECKS = 1;
