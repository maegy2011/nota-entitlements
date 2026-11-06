-- 015-admin-seed.sql — default superadmin (change password immediately).
-- username: admin  password: admin123
INSERT INTO admin_users (username, password_hash, role)
VALUES ('admin', '2d58edbf97afa55c2e04f08c9312c7a9:87f4caa1cc9ea73bf9537b504f4e0c31b96749ec3d0c3ec7ea53d350bf357a625633485d21b764c9681190512e41509847f32012b067a30cbfe1957aebc4377a', 'superadmin')
ON CONFLICT (username) DO NOTHING;
