-- Demo data so you can actually see the thing work, not just read SQL.
--  sqlite3 filetrail.db < db/schema.sql
--  sqlite3 filetrail.db < db/seed.sql

INSERT INTO offices (id, code, name, kind) VALUES
  (1, 'REG',  'Registry',                  'registry'),
  (2, 'CSC',  'Dept. of Computer Science', 'department'),
  (3, 'EXAM', 'Exams & Records',           'exams'),
  (4, 'DEAN', 'Faculty of Science',        'faculty'),
  (5, 'BURS', 'Bursary',                   'bursary');

INSERT INTO staff (id, full_name, office_id, role) VALUES
  (1, 'Adaeze Okonkwo', 1, 'Registry clerk'),
  (2, 'Mr. Bala Yakubu',2, 'Departmental officer'),
  (3, 'Dr. Chinelo Obi',2, 'HOD'),
  (4, 'Musa Ibrahim',   3, 'Exams officer'),
  (5, 'Prof. T. Adeyemi',4,'Dean'),
  (6, 'Grace Etim',     5, 'Bursary officer');

-- One file, doing exactly what you described: it walks, it waits, it comes back.
INSERT INTO files (id, file_number, subject, file_type, subject_ref, subject_name, opened_on)
VALUES
  (1, 'CSC/2025/0413', 'Clearance — final year', 'clearance', 'CSC/19/1042', 'Fatima Suleiman', '2025-09-02'),
  (2, 'CSC/2025/0414', 'First semester result — CSC 401', 'result', 'CSC/19/1108', 'Ikechukwu Nwosu', '2025-09-05'),
  (3, 'CSC/2025/0415', 'Transcript request — postgraduate admission', 'transcript', 'CSC/15/0987', 'Yetunde Bakare', '2025-09-08');

-- File 1: clear, painful real-life trail with a stall in it
INSERT INTO movements (file_id, from_office_id, to_office_id, status, note, moved_at, recorded_by, signature) VALUES
  (1, NULL, 1, 'received',         'Registered at registry counter',            datetime('now','-27 days'), 1, 'Adaeze Okonkwo'),
  (1, 1,    2, 'received',         'Sent to department for verification',       datetime('now','-26 days'), 1, 'Adaeze Okonkwo'),
  (1, 2,    2, 'pending_approval', 'Awaiting HOD signature',                    datetime('now','-24 days'), 2, 'Mr. Bala Yakubu'),
  (1, 2,    4, 'approved',         'HOD signed, sent to Dean for approval',     datetime('now','-3 days'),  2, 'Mr. Bala Yakubu'),
  (1, 4,    1, 'received',         'Dean approved, back at registry for stamping', datetime('now','-2 days'), 1, 'Adaeze Okonkwo');

-- File 2: went out to exams and has been sitting there
INSERT INTO movements (file_id, from_office_id, to_office_id, status, note, moved_at, recorded_by, signature) VALUES
  (2, NULL, 2, 'received', 'Collected from lecturer',              datetime('now','-14 days'), 2, 'Mr. Bala Yakubu'),
  (2, 2,    3, 'received', 'Forwarded to exams & records',        datetime('now','-13 days'), 2, 'Mr. Bala Yakubu');

-- File 3: a clean, fast one (proof the system can also show good news)
INSERT INTO movements (file_id, from_office_id, to_office_id, status, note, moved_at, recorded_by, signature) VALUES
  (3, NULL, 1, 'received', 'Transcript request lodged',      datetime('now','-5 days'), 1, 'Adaeze Okonkwo'),
  (3, 1,    2, 'received', 'To department for result check', datetime('now','-4 days'), 1, 'Adaeze Okonkwo'),
  (3, 2,    3, 'received', 'Verified, to exams & records',   datetime('now','-3 days'), 2, 'Mr. Bala Yakubu'),
  (3, 3,    1, 'received', 'Transcript prepared',           datetime('now','-1 days'), 4, 'Musa Ibrahim');
